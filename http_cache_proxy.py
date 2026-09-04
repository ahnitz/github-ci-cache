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
    A miss is fetched from upstream and stored.  What the default branch and
    a scheduled cache-refresh job use.
strict
    A miss fails with a 504 naming the URL.  Pull requests use this, so an
    upstream outage cannot break them, and a developer can prove a test needs
    nothing beyond the cache.
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

Only allow-listed hosts are cached; anything else is forwarded untouched.  The
package ecosystems (PyPI, conda channels, apt) are kept off the proxy
altogether by ``no_proxy`` in the launcher -- they carry their own caches, they
would dominate the cache budget, and keeping them away from a process that
terminates TLS keeps credentials out of it.
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


def _url_allowed(host, path, patterns):
    """Whether this host and path are ones we are meant to be caching."""
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
        self.allowed = _parse_patterns(os.environ.get('HTTP_CACHE_HOSTS', ''))
        if not self.allowed:
            raise SystemExit('HTTP_CACHE_HOSTS is empty, nothing would cache')
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
            'http cache in %s mode, %d patterns cached, cache dir %s',
            self.mode, len(self.allowed), self.root
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
        if not _url_allowed(flow.request.pretty_host, flow.request.path,
                            self.allowed):
            return
        if flow.request.method != 'GET' or 'range' in flow.request.headers:
            return
        if flow.response.status_code not in CACHEABLE_STATUS:
            return

        url = flow.request.pretty_url
        declared = flow.response.headers.get('content-length')
        chunks = []
        started = time.monotonic()

        def tee(chunk):
            # mitmproxy calls this for each chunk and finally with b'' to
            # signal the end of the body.
            if chunk:
                chunks.append(chunk)
                return chunk
            body = b''.join(chunks)
            self._finish(url, flow, body, declared,
                         (time.monotonic() - started) * 1000)
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

        if not _url_allowed(flow.request.pretty_host, flow.request.path,
                            self.allowed):
            self.stats['forwarded'] += 1
            self._log_event('FORWARD', url, note='not in the allow list')
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
        self.stats['miss'] += 1

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
