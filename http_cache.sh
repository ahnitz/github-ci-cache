#!/usr/bin/env bash
#
# Start or stop the caching HTTP proxy.  See http_cache_proxy.py for what the
# cache does and why, and action.yml for the GitHub Actions wrapper.
#
#   eval "$(http_cache.sh start)"    # exports the client settings
#   http_cache.sh stop               # stops it, reports the counts
#
# Inside GitHub Actions the settings are also appended to $GITHUB_ENV, so
# later steps in the job pick them up without the eval.
#
# Environment:
#   HTTP_CACHE_MODE       record (default) | strict | off
#   HTTP_CACHE_STATE      where the cache and the proxy's files live
#   HTTP_CACHE_HOSTS      optional: cache ONLY these hosts (default: all)
#   HTTP_CACHE_NO_PROXY   comma-separated hosts to keep off the proxy
#   HTTP_CACHE_PORT       listen port, default 3128
#   HTTP_CACHE_MITMDUMP   mitmdump to use, default the one on PATH
#   HTTP_CACHE_SYSTEM_CA  CA bundle to extend, default certifi's or the system's
#
# Diagnostics go to stderr and the settings to stdout, so the eval above only
# ever consumes the settings.

set -eu

MODE="${HTTP_CACHE_MODE:-record}"
STATE="${HTTP_CACHE_STATE:-${XDG_CACHE_HOME:-$HOME/.cache}/http-cache}"
PORT="${HTTP_CACHE_PORT:-3128}"

CACHE_DIR="$STATE/cache"
CONF_DIR="$STATE/conf"
CA_BUNDLE="$STATE/ca-bundle.pem"
WGETRC="$STATE/wgetrc"
PYSITE="$STATE/pysite"
LOG="$STATE/mitmdump.log"
PIDFILE="$STATE/mitmdump.pid"
STATS="$STATE/stats.json"
EVENTS="$STATE/events.jsonl"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ADDON="$HERE/http_cache_proxy.py"

# The deny list.  Nothing here is specific to any project, which is the whole
# point: it decides what is NOT cached, so a caller lists nothing.  Three
# groups, for three reasons:
# the package ecosystems carry their own caches and would dominate the cache
# budget; the GitHub API is where a job's token goes, and nothing carrying a
# credential should pass through a process that terminates TLS; and the Actions
# cache service is how this cache itself is saved and restored, so routing its
# multi-GB range-request traffic through the proxy would put the proxy in the
# path of its own persistence.
NO_PROXY_HOSTS="${HTTP_CACHE_NO_PROXY:-localhost,127.0.0.1,::1,\
pypi.org,files.pythonhosted.org,pythonhosted.org,\
prefix.dev,repo.prefix.dev,conda.anaconda.org,anaconda.org,\
archive.ubuntu.com,security.ubuntu.com,ppa.launchpad.net,\
api.github.com,codeload.github.com,\
blob.core.windows.net,actions.githubusercontent.com,\
actions.results.githubusercontent.com}"

log() { printf '%s\n' "$*" >&2; }

# The proxy's own upstream fetches must be direct and must use the real trust
# store, so every variable this script is about to export is cleared for it.
# Called as `run_unproxied ... &`: it execs, so that $! is the proxy's own pid
# rather than a wrapper subshell's.  Killing a wrapper leaves the proxy running,
# holding the port and never reaching its shutdown hook.
run_unproxied() {
    exec env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
        -u ALL_PROXY -u all_proxy -u no_proxy -u NO_PROXY \
        -u SSL_CERT_FILE -u SSL_CERT_DIR -u REQUESTS_CA_BUNDLE \
        -u CURL_CA_BUNDLE -u WGETRC -u GIT_SSL_CAINFO \
        PYTHONUNBUFFERED=1 \
        "$@"
}

system_ca_bundle() {
    if [ -n "${HTTP_CACHE_SYSTEM_CA:-}" ]; then
        printf '%s\n' "$HTTP_CACHE_SYSTEM_CA"
        return
    fi
    if python3 -c 'import certifi' 2>/dev/null; then
        python3 -c 'import certifi; print(certifi.where())'
        return
    fi
    for candidate in /etc/ssl/certs/ca-certificates.crt \
                     /etc/pki/tls/certs/ca-bundle.crt \
                     /etc/ssl/cert.pem; do
        if [ -r "$candidate" ]; then
            printf '%s\n' "$candidate"
            return
        fi
    done
    log "http-cache: found no system CA bundle to extend"
    return 1
}

emit() {
    # stdout for `eval`, $GITHUB_ENV for the rest of the job.
    printf 'export %s=%s\n' "$1" "$2"
    if [ -n "${GITHUB_ENV:-}" ]; then
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_ENV"
    fi
}

wait_for_port() {
    local waited=0
    while [ "$waited" -lt 60 ]; do
        if python3 - "$PORT" <<'PY' 2>/dev/null
import socket, sys
s = socket.socket()
s.settimeout(1)
sys.exit(0 if s.connect_ex(('127.0.0.1', int(sys.argv[1]))) == 0 else 1)
PY
        then
            return 0
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

start() {
    if [ "$MODE" = "off" ]; then
        log "http-cache: mode is off, starting no proxy"
        return 0
    fi

    mkdir -p "$CACHE_DIR" "$CONF_DIR"
    rm -f "$EVENTS"

    # Only intercept what we mean to cache.  Everything else is tunnelled
    # blindly, so it never sees a substituted certificate and never needs to
    # be taught to trust one.  This is the structural version of the no_proxy
    # list: enumerating what to bypass is guesswork and gets it wrong (Node
    # actions verifying TLS against their own roots is how that surfaced),
    # whereas the set we *do* want to intercept is known exactly.
    #
    # ignore_hosts matches on host:port, before any request line is read, so
    # it can only key on the host -- a host that appears in the allow list with
    # a path prefix is still intercepted, and the path is applied afterwards.
    # Tunnel exactly the deny list, and intercept everything else so that it
    # can be cached.  This is the inverse of the first version, which tunnelled
    # everything *except* an allow list: that made caching depend on each
    # project listing its own hosts, which is the metadata this exists to
    # remove.  What has to be excluded is generic -- package registries, the
    # GitHub API, the Actions services -- so it ships here and a project
    # configures nothing.
    local ignore
    ignore=$(python3 - "$NO_PROXY_HOSTS" <<'PY'
import re, sys
hosts = sorted({e.strip().lower() for e in sys.argv[1].split(',')
                if e.strip() and not e.strip().startswith(('127.', '::', 'localhost'))})
alt = '|'.join(re.escape(h) for h in hosts)
print(f'^(?:[^.]+\\.)*(?:{alt})(?::\\d+)?$')
PY
)

    local mitmdump="${HTTP_CACHE_MITMDUMP:-mitmdump}"
    if ! command -v "$mitmdump" >/dev/null 2>&1; then
        log "http-cache: $mitmdump is not on PATH (pip install mitmproxy)"
        return 1
    fi

    # upstream_cert=false is what makes a cache hit need no network at all: by
    # default mitmproxy fetches the real certificate to mint a lookalike, which
    # would contact the origin server even when the answer is already on disk.
    HTTP_CACHE_DIR="$CACHE_DIR" \
    HTTP_CACHE_MODE="$MODE" \
    HTTP_CACHE_STATS="$STATS" \
    HTTP_CACHE_DENY="$NO_PROXY_HOSTS" \
    HTTP_CACHE_EVENTS="$EVENTS" \
    run_unproxied "$mitmdump" \
        --listen-host 127.0.0.1 \
        --listen-port "$PORT" \
        --set confdir="$CONF_DIR" \
        --set upstream_cert=false \
        --ignore-hosts "$ignore" \
        --set connection_strategy=lazy \
        --set termlog_verbosity=info \
        --set flow_detail=0 \
        -s "$ADDON" \
        >"$LOG" 2>&1 &
    echo $! > "$PIDFILE"

    if ! wait_for_port; then
        log "http-cache: proxy did not come up on port $PORT; log follows"
        tail -30 "$LOG" >&2 || true
        return 1
    fi
    local ca="$CONF_DIR/mitmproxy-ca-cert.pem"
    if [ ! -r "$ca" ]; then
        log "http-cache: proxy started but wrote no CA certificate"
        return 1
    fi

    # Our CA is *appended to* the system bundle rather than replacing it, so
    # that anything deliberately bypassing the proxy keeps its trust roots.
    cat "$(system_ca_bundle)" "$ca" > "$CA_BUNDLE"
    # wget has no CA environment variable of its own, only a config file -- and
    # there are two wgets.  GNU wget 1.x reads $WGETRC, wget2 (what Fedora and
    # some other distributions install as "wget") reads $WGET2RC and ignores
    # $WGETRC entirely.  Both accept the same ca_certificate key, so one file
    # serves both.  Getting this wrong does not fail cleanly: wget2 with an
    # untrusted certificate hangs until it is killed rather than reporting the
    # verification failure, which in CI reads as a stuck job.
    printf 'ca_certificate=%s\n' "$CA_BUNDLE" > "$WGETRC"

    # Some clients ignore every CA environment variable there is.  astropy's
    # download_file -- which is how a great deal of scientific Python fetches
    # data -- does `ssl.create_default_context(cafile=certifi.where())`, and
    # create_default_context with an explicit cafile does not consult
    # SSL_CERT_FILE at all.  Overriding certifi.where() at interpreter startup
    # covers every certifi-based client at once without modifying anything in
    # site-packages.  Caveat: this shadows a sitecustomize of the project's own
    # if it has one on PYTHONPATH; set HTTP_CACHE_NO_SITECUSTOMIZE=1 to skip.
    if [ -z "${HTTP_CACHE_NO_SITECUSTOMIZE:-}" ]; then
        mkdir -p "$PYSITE"
        cat > "$PYSITE/sitecustomize.py" <<'PY'
"""Point certifi-based clients at the caching proxy's CA bundle."""
import os

_bundle = os.environ.get('HTTP_CACHE_CA_BUNDLE')
if _bundle and os.path.exists(_bundle):
    try:
        import certifi
    except ImportError:
        pass
    else:
        certifi.where = lambda _b=_bundle: _b
PY
        emit HTTP_CACHE_CA_BUNDLE "$CA_BUNDLE"
        if [ -n "${PYTHONPATH:-}" ]; then
            emit PYTHONPATH "$PYSITE:$PYTHONPATH"
        else
            emit PYTHONPATH "$PYSITE"
        fi
    fi

    log "http-cache: listening on 127.0.0.1:$PORT in $MODE mode, cache $CACHE_DIR"

    emit http_proxy          "http://127.0.0.1:$PORT"
    emit https_proxy         "http://127.0.0.1:$PORT"
    emit HTTP_PROXY          "http://127.0.0.1:$PORT"
    emit HTTPS_PROXY         "http://127.0.0.1:$PORT"
    emit no_proxy            "$NO_PROXY_HOSTS"
    emit NO_PROXY            "$NO_PROXY_HOSTS"
    emit SSL_CERT_FILE       "$CA_BUNDLE"
    emit REQUESTS_CA_BUNDLE  "$CA_BUNDLE"
    emit CURL_CA_BUNDLE      "$CA_BUNDLE"
    emit WGETRC              "$WGETRC"
    emit WGET2RC             "$WGETRC"
    emit GIT_SSL_CAINFO      "$CA_BUNDLE"
    # Node reads neither SSL_CERT_FILE nor any of the above, only this.  It
    # matters more than it looks: GitHub's own actions are Node programs that
    # honour http_proxy, so without this they are sent through the proxy and
    # then cannot verify it -- actions/upload-artifact failed exactly that way,
    # after the job's real work had already succeeded.  Every host they use
    # ought to be in no_proxy, but an action meant to reduce fragility should
    # not depend on that list being exhaustive.
    emit NODE_EXTRA_CA_CERTS "$CA_BUNDLE"
    emit HTTP_CACHE_STATE    "$STATE"
}

stop() {
    if [ ! -r "$PIDFILE" ]; then
        log "http-cache: no pidfile at $PIDFILE, nothing to stop"
        return 0
    fi
    local pid
    pid="$(cat "$PIDFILE")"
    # SIGTERM so the proxy shuts down cleanly; the counts are written as it
    # goes, so they survive even if it has to be killed outright.
    kill "$pid" 2>/dev/null || true
    local waited=0
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 15 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        log "http-cache: pid $pid ignored SIGTERM, killing it"
        kill -9 "$pid" 2>/dev/null || true
    fi
    rm -f "$PIDFILE"
    if [ -r "$STATS" ]; then
        log "http-cache: $(tr -d '\n ' < "$STATS")"
        if [ -r "$EVENTS" ]; then
            log "http-cache: $(wc -l < "$EVENTS") requests logged in $EVENTS"
        fi
    else
        log "http-cache: stopped, but no stats were written"
    fi
}

case "${1:-}" in
    start) start ;;
    stop)  stop ;;
    *) log "usage: ${0##*/} start|stop"; exit 2 ;;
esac
