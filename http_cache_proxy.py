"""A caching HTTP proxy addon, for making CI data downloads reproducible.

A job that fetches data files over the network fails whenever any one of those
requests fails.  The usual answer is retry logic, mirror lists and a
hand-maintained prefetch manifest -- download metadata in several places that
has to be kept in step with the tests by hand.

Run under ``mitmdump``, this addon removes the need for that.  Downloads are
routed through the proxy by environment variable, so a request whose answer is
already on disk never reaches the network, and the code doing the downloading
does not have to know a cache exists.

Three modes, from ``HTTP_CACHE_MODE``:

record
    The default, and what every job uses.  A hit is served from disk; a miss
    goes to the origin exactly as it would without a proxy, and is then
    stored.  So the cache can only make a job faster or more reliable, never
    less: with nothing cached at all this is the behaviour the job had before.
    Shrinking the surface where CI can break matters more than hermeticity --
    the point is not to add a new place for it to break.

    Pull requests write too, deliberately.  Someone iterating on a branch and
    re-running CI is exactly who benefits most, and a pull request's cache can
    only be read by that same pull request, so it cannot affect anyone else.
    Cruft accumulated this way is cleared by rebuilding the cache, which is
    simpler than arranging for one writer.
strict
    A miss fails with a 504 naming the URL.  Not for ordinary use: it proves a
    workload needs nothing but the cache, which is worth doing deliberately --
    with the network removed, say -- and not worth imposing on a pull request,
    where it would mean that adding a test that downloads something turns CI
    red until somebody populates the cache.  That is the tax this action
    exists to remove.
off
    Handled by the launcher, which starts no proxy at all.

The proxy does not fetch upstream itself.  It did once, so that a redirect
chain could be collapsed and stored under the URL the client asked for -- and
that meant no byte reached the client until the whole object had been
downloaded, plus however long the proxy spent retrying.  astropy's
download_file allows 10 seconds, and pycbc.dq passes timeout=10, so any file
that took longer than that upstream failed with a client-side read timeout.
Letting mitmproxy stream from the origin, and storing the body in the response
hook, is both correct and less code.

What gets cached is decided by exclusion, not by a list.  Anything a job
downloads is cached unless it is on the deny list, which is generic: the
package ecosystems (PyPI, conda channels, apt) because they carry their own
caches and would dominate the budget, the GitHub API and the Actions services
because that is where a job's credentials go, and the git smart-HTTP endpoints
because they are a protocol rather than a file.

Nothing on that list is specific to any project, so a project configures
nothing.  The alternative -- each caller listing the hosts worth caching --
was tried first and is the same failure it set out to fix: metadata to keep in
step with the tests by hand, in every workflow file, silently doing nothing
when a host is forgotten.
"""

import asyncio
import hashlib
import json
import logging
import os
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter

from mitmproxy import http

logger = logging.getLogger('http_cache_proxy')

# Request headers NOT to pass upstream: hop-by-hop, or ones that describe the
# connection to the proxy rather than the request being made.  Everything else
# is forwarded, so the origin sees the request the client actually made.
# Substituting our own User-Agent and Accept is a way to get different
# behaviour out of a picky server for no reason -- a caching proxy should
# replay the request, not paraphrase it.
SKIPPED_REQUEST_HEADERS = frozenset({
    'host', 'connection', 'proxy-connection', 'keep-alive', 'te', 'trailer',
    'transfer-encoding', 'upgrade', 'accept-encoding',
})

# Response headers worth replaying.  Deliberately not the hop-by-hop ones, and
# deliberately not Content-Encoding: the stored body is already decoded.
REPLAYED_HEADERS = ('content-type', 'last-modified', 'etag')

# Statuses worth keeping.  The redirects matter as much as the 200s: a client
# that follows a chain asks for each hop, so replaying the same 3xx sends it to
# the same target, which is the hop we also stored.
CACHEABLE_STATUS = (200, 301, 302, 303, 307, 308)

# Headers not to store or replay: hop-by-hop, or ones describing a connection
# that no longer exists by the time the entry is replayed.
SKIPPED_RESPONSE_HEADERS = frozenset({
    'connection', 'proxy-connection', 'keep-alive', 'te', 'trailer',
    'transfer-encoding', 'upgrade', 'content-length',
})


# Paths belonging to a protocol rather than a file.  git's smart-HTTP
# endpoints are the ones that matter: they are per-clone, never worth storing,
# and caching them would break `pip install git+https://...`.
DENIED_PATH_PARTS = ('/info/refs', '/git-upload-pack', '/git-receive-pack')


def _parse_patterns(spec):
    """Parse the allow list into ``(host, path_prefix)`` pairs.

    An entry is a host, optionally followed by a path prefix:
    ``raw.githubusercontent.com`` or
    ``github.com/gwastro/pycbc_data/releases/download/``.  The prefix matters
    for more than tidiness: a host listed bare has *everything* on it treated
    as cacheable, and in strict mode that means refused.  ``github.com`` serves
    release assets but also the git smart-HTTP endpoints, so listing it bare
    breaks ``pip install git+https://github.com/...``.
    """
    patterns = []
    for entry in spec.split(','):
        entry = entry.strip().lower().lstrip('/')
        if not entry:
            continue
        host, _, path = entry.partition('/')
        patterns.append((host, '/' + path if path else ''))
    return tuple(patterns)


def _matches(host, path, patterns):
    """Whether this host and path match any of ``patterns``."""
    host = host.lower()
    for pattern_host, pattern_path in patterns:
        if not (host == pattern_host or host.endswith('.' + pattern_host)):
            continue
        if not pattern_path or path.startswith(pattern_path):
            return True
    return False


class HTTPCache:
    """Serve GETs for allow-listed hosts from disk, storing them on a miss."""

    def __init__(self):
        self.root = os.environ.get('HTTP_CACHE_DIR')
        if not self.root:
            raise SystemExit('HTTP_CACHE_DIR is not set')
        self.mode = os.environ.get('HTTP_CACHE_MODE', 'record')
        if self.mode not in ('record', 'strict'):
            raise SystemExit(
                f'HTTP_CACHE_MODE must be record or strict, got {self.mode!r}'
            )
        # An explicit allow list is an override, not the normal case.  Empty
        # (the default) means "cache anything that is not denied".
        self.allowed = _parse_patterns(os.environ.get('HTTP_CACHE_HOSTS', ''))
        self.denied = _parse_patterns(os.environ.get('HTTP_CACHE_DENY', ''))
        self.stats = Counter()
        self.stats_path = os.path.abspath(os.environ.get(
            'HTTP_CACHE_STATS', os.path.join(self.root, os.pardir, 'stats.json')
        ))
        # One line per request, appended as it happens.  The counters say how
        # many; this says which, which is what someone debugging a cache miss
        # in a CI log actually needs.
        self.events_path = os.path.abspath(os.environ.get(
            'HTTP_CACHE_EVENTS',
            os.path.join(self.root, os.pardir, 'events.jsonl')
        ))
        os.makedirs(self.root, exist_ok=True)
        logger.info(
            'http cache in %s mode, %s, %d hosts denied, cache dir %s',
            self.mode,
            (f'{len(self.allowed)} allow patterns'
             if self.allowed else 'caching anything not denied'),
            len(self.denied), self.root
        )

    # -- cache layout ----------------------------------------------------
    #
    # One directory per entry, named for the sha256 of "<METHOD> <URL>", with
    # the body and its metadata beside each other.  Directory-per-entry rather
    # than one index file so that a cache action sees an incremental change,
    # and so that a human can see what is cached without a tool.

    def _entry(self, method, url):
        digest = hashlib.sha256(f'{method} {url}'.encode()).hexdigest()
        return os.path.join(self.root, digest)

    def _read(self, method, url):
        """Return ``(body, meta)`` if this request is cached and intact."""
        entry = self._entry(method, url)
        body_path = os.path.join(entry, 'body')
        meta_path = os.path.join(entry, 'meta.json')
        if not (os.path.exists(body_path) and os.path.exists(meta_path)):
            return None
        try:
            with open(meta_path) as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            logger.warning('unreadable metadata for %s, ignoring entry', url)
            return None
        # Length is checked on every read because it is free from the stat and
        # it is the failure this cache exists to stop: a truncated body stored
        # under a 200.  The sha256 is recorded at store time for anyone who
        # wants to audit the cache offline, but rehashing a few hundred MB per
        # read would cost more than the download it replaces.
        actual = os.path.getsize(body_path)
        if actual != meta.get('length'):
            logger.warning(
                'cached body for %s is %d bytes, metadata says %d; '
                'discarding the entry', url, actual, meta.get('length')
            )
            shutil.rmtree(entry, ignore_errors=True)
            return None
        with open(body_path, 'rb') as fh:
            return fh.read(), meta

    def _write(self, method, url, status, headers, body, final_url):
        """Store a response, atomically enough for a concurrent reader."""
        entry = self._entry(method, url)
        tmp = entry + '.tmp'
        shutil.rmtree(tmp, ignore_errors=True)
        os.makedirs(tmp, exist_ok=True)
        with open(os.path.join(tmp, 'body'), 'wb') as fh:
            fh.write(body)
        meta = {
            'url': url,
            'method': method,
            'status': status,
            'headers': headers,
            'length': len(body),
            'sha256': hashlib.sha256(body).hexdigest(),
            # Kept for auditing: which mirror or signed redirect target the
            # bytes actually came from, which the requested URL does not say.
            'final_url': final_url,
            'stored': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }
        with open(os.path.join(tmp, 'meta.json'), 'w') as fh:
            json.dump(meta, fh, indent=1, sort_keys=True)
        shutil.rmtree(entry, ignore_errors=True)
        os.replace(tmp, entry)
        return meta

    # -- mitmproxy hooks -------------------------------------------------

    async def request(self, flow: http.HTTPFlow):
        try:
            await self._handle(flow)
        except Exception as exc:
            # As above: never fail a request because the cache misbehaved.
            # Leaving flow.response unset lets mitmproxy fetch it normally.
            self.stats['error'] += 1
            logger.warning('cache bypassed for %s: %s: %s',
                           flow.request.pretty_url, type(exc).__name__, exc)
        finally:
            self._save_stats()

    def responseheaders(self, flow: http.HTTPFlow):
        """Stream the body to the client while copying it into the cache.

        Streaming is the point.  mitmproxy would otherwise read the whole
        response before passing it on, so a client waiting on the status line
        gets nothing until the download finishes -- and astropy allows ten
        seconds.  A tee gives the client its first byte immediately and still
        leaves us the complete body to store.
        """
        if flow.response is None or getattr(flow, 'from_cache', False):
            return
        if flow.response.status_code not in CACHEABLE_STATUS:
            return
        if not self._cacheable(flow, flow.request.pretty_url, count=False):
            return

        url = flow.request.pretty_url
        declared = flow.response.headers.get('content-length')
        chunks = []
        started = time.monotonic()

        def tee(chunk):
            # mitmproxy calls this for each chunk and finally with b'' to
            # signal the end of the body.  The chunk is returned unchanged
            # whatever happens here: this function sits in the path of a
            # response the client is already reading, so a fault in the cache
            # must not become a fault in the download.  A cache that cannot
            # store something is a slow CI job; a cache that breaks the
            # response is a broken CI job, which is what it exists to prevent.
            try:
                if chunk:
                    chunks.append(chunk)
                else:
                    self._finish(url, flow, b''.join(chunks), declared,
                                 (time.monotonic() - started) * 1000)
            except Exception as exc:
                self.stats['store_failed'] += 1
                logger.warning('not caching %s: %s: %s',
                               url, type(exc).__name__, exc)
            return chunk

        flow.response.stream = tee

    def _finish(self, url, flow, body, declared, elapsed_ms):
        """Store a completed response, unless it arrived short."""
        # A truncated body served with a 200 is a real failure mode -- Git LFS
        # does it when a bandwidth quota is spent -- so a length that does not
        # match what was promised is never stored.  The client still gets what
        # it got; we simply refuse to remember it.
        if declared is not None and len(body) != int(declared):
            self.stats['short'] += 1
            self._log_event(
                'SHORT', url, len(body), elapsed_ms,
                note=f'declared {declared}, not cached'
            )
            return
        headers = {k.lower(): v for k, v in flow.response.headers.items()
                   if k.lower() not in SKIPPED_RESPONSE_HEADERS}
        self._write(flow.request.method, url, flow.response.status_code,
                    headers, body, url)
        self.stats['stored'] += 1
        self.stats['stored_bytes'] += len(body)
        note = ''
        if flow.response.status_code != 200:
            note = f"HTTP {flow.response.status_code} -> {headers.get('location','')}"
        self._log_event('STORE', url, len(body), elapsed_ms, note)
        self._save_stats()

    async def _handle(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        method = flow.request.method

        if not self._cacheable(flow, url):
            return
        if method != 'GET' or 'range' in flow.request.headers:
            # A partial or non-GET request is forwarded rather than stored: it
            # would need a separate key per byte range to be correct, and
            # nothing being cached here asks for one.
            self.stats['forwarded'] += 1
            self._log_event(
                'FORWARD', url,
                note='range request' if method == 'GET' else f'{method}, not GET'
            )
            return

        hit = self._read(method, url)
        if hit is not None:
            body, meta = hit
            self.stats['hit'] += 1
            self.stats['hit_bytes'] += len(body)
            self._log_event('HIT', url, len(body),
                            note=f"stored {meta.get('stored', 'unknown')}")
            flow.response = http.Response.make(
                meta['status'], body, meta.get('headers', {})
            )
            # So the response hook does not store what it just served.
            flow.from_cache = True
            return

        if self.mode == 'strict':
            self.stats['blocked'] += 1
            self._log_event('BLOCK', url, note='not cached, strict mode')
            flow.response = http.Response.make(
                504,
                (
                    f'http cache: {url} is not in the cache and the cache is '
                    f'in strict mode, so nothing was fetched.\n\n'
                    f'To add it: run the cache-refresh workflow on the '
                    f'default branch, or label this pull request '
                    f'"ci-http-cache-record" to let this run populate the '
                    f'cache itself.\n'
                ).encode(),
                {'content-type': 'text/plain'},
            )
            flow.from_cache = True
            return

        # A miss in record mode is left to mitmproxy: it fetches and streams
        # from the origin, and responseheaders() copies the body as it passes.
        #
        # Logged as an event, because the summary was actively misleading
        # without it: a job that spent seventy seconds timing out against an
        # origin reported only "3 passed through, not cached" and said nothing
        # at all about the five requests that had missed and failed.  A miss is
        # the most interesting thing in the log when something goes wrong.
        self.stats['miss'] += 1
        self._log_event('MISS', url, note='not cached, fetching from origin')

    def _cacheable(self, flow, url, count=True):
        """Whether this request is one we should be storing.

        Decided by exclusion: everything is cacheable unless it is denied, or
        is not a plain whole-object GET.  An explicit allow list, if the caller
        supplied one, narrows it further.
        """
        host, path = flow.request.pretty_host, flow.request.path
        why = None
        if _matches(host, path, self.denied):
            why = 'denied host'
        elif any(part in path for part in DENIED_PATH_PARTS):
            why = 'git protocol endpoint, not a file'
        elif self.allowed and not _matches(host, path, self.allowed):
            why = 'not in the allow list'
        elif flow.request.method != 'GET':
            why = f'{flow.request.method}, not GET'
        elif 'range' in flow.request.headers:
            # Correct caching of a partial response needs a key per byte
            # range; forwarding is the honest answer.
            why = 'range request'
        if why is None:
            return True
        if count:
            self.stats['forwarded'] += 1
            self._log_event('FORWARD', url, note=why)
        return False

    def _log_event(self, disposition, url, bytes_=0, elapsed_ms=0, note=''):
        """Append one request to the event log, and say so at INFO.

        The disposition is a fixed-width word so that a CI log can be read
        down the left-hand column: HIT, STORE, BLOCK, FORWARD or ERROR.
        """
        logger.info(
            '%-7s %9s %6s  %s%s',
            disposition,
            f'{bytes_} B' if bytes_ else '-',
            f'{elapsed_ms:.0f}ms' if elapsed_ms else '-',
            url,
            f'  ({note})' if note else '',
        )
        record = {
            'disposition': disposition,
            'url': url,
            'bytes': bytes_,
            'elapsed_ms': round(elapsed_ms, 1),
        }
        if note:
            record['note'] = note
        try:
            with open(self.events_path, 'a') as fh:
                fh.write(json.dumps(record, sort_keys=True) + '\n')
        except OSError as exc:
            logger.warning('could not append to the event log: %s', exc)

    def _save_stats(self):
        """Record the request counts, so a run can assert it used us.

        A cache that is never consulted looks exactly like a cache that works,
        so the numbers have to be checkable rather than inferred from the
        absence of a failure.
        """
        stats = dict(self.stats)
        stats['mode'] = self.mode
        try:
            tmp = self.stats_path + '.tmp'
            with open(tmp, 'w') as fh:
                json.dump(stats, fh, indent=1, sort_keys=True)
            os.replace(tmp, self.stats_path)
        except OSError as exc:
            logger.warning('could not write cache stats: %s', exc)

    def done(self):
        self._save_stats()
        logger.info('http cache stats: %s', dict(self.stats))


addons = [HTTPCache()]
