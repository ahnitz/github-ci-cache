"""A caching HTTP proxy addon, for making CI data downloads reproducible.

Run under ``mitmdump``.  Downloads are routed through the proxy by environment
variable, so a request whose answer is on disk never reaches the network, and
the code doing the downloading does not have to know a cache exists.

Modes, from ``HTTP_CACHE_MODE``:

record
    The default.  A hit is served from disk; a miss goes to the origin as it
    would without a proxy, and is then stored.  The cache can only make a job
    faster or more reliable, never less.
strict
    A miss fails with a 504 naming the URL, so a workload can be shown to need
    nothing but the cache.
off
    Handled by the launcher, which starts no proxy.

What is cached is decided by exclusion: anything a job downloads, unless it is
denied.  mitmproxy fetches from the origin and the body is copied out of the
response stream, so the client gets its first byte immediately.
"""

import hashlib
import json
import logging
import os
import shutil
import time
from collections import Counter

from mitmproxy import http

logger = logging.getLogger('http_cache_proxy')

# Redirects are kept as well as 200s: a client following a chain asks for each
# hop, so replaying the 3xx sends it to the target that was stored too.
CACHEABLE_STATUS = (200, 301, 302, 303, 307, 308)

# Hop-by-hop headers, and ones describing a connection that no longer exists
# when the entry is replayed.
SKIPPED_RESPONSE_HEADERS = frozenset({
    'connection', 'proxy-connection', 'keep-alive', 'te', 'trailer',
    'transfer-encoding', 'upgrade', 'content-length',
})


# Paths belonging to a protocol rather than a file: per-clone, never worth
# storing, and caching them breaks `pip install git+https://...`.
DENIED_PATH_PARTS = ('/info/refs', '/git-upload-pack', '/git-receive-pack')


def _parse_patterns(spec):
    """Parse the deny list's ``host`` or ``host/path/prefix`` entries."""
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
        self.denied = _parse_patterns(os.environ.get('HTTP_CACHE_DENY', ''))
        self.stats = Counter()
        self.stats_path = os.path.abspath(os.environ.get(
            'HTTP_CACHE_STATS', os.path.join(self.root, os.pardir, 'stats.json')
        ))
        # One line per request as it happens: the counters say how many, this
        # says which.
        self.events_path = os.path.abspath(os.environ.get(
            'HTTP_CACHE_EVENTS',
            os.path.join(self.root, os.pardir, 'events.jsonl')
        ))
        os.makedirs(self.root, exist_ok=True)
        logger.info('http cache in %s mode, %d hosts denied, cache dir %s',
                    self.mode, len(self.denied), self.root)

    # -- cache layout ----------------------------------------------------
    #
    # One directory per entry, named for the sha256 of "<METHOD> <URL>".  A
    # directory each rather than one index file, so a cache action sees an
    # incremental change and the contents can be read without a tool.

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
        # Free from the stat, and catches the failure worth catching: a
        # truncated body stored under a 200.  The sha256 is recorded at store
        # time rather than rechecked here, which would cost more than the
        # download it saves.
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
            # Which redirect target the bytes came from, for auditing.
            'final_url': final_url,
            'stored': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        }
        with open(os.path.join(tmp, 'meta.json'), 'w') as fh:
            json.dump(meta, fh, indent=1, sort_keys=True)
        shutil.rmtree(entry, ignore_errors=True)
        os.replace(tmp, entry)
        return meta

    # -- mitmproxy hooks -------------------------------------------------

    def request(self, flow: http.HTTPFlow):
        try:
            self._handle(flow)
        except Exception as exc:
            # Never fail a request because the cache misbehaved: leaving
            # flow.response unset lets mitmproxy fetch it normally.
            self.stats['error'] += 1
            logger.warning('cache bypassed for %s: %s: %s',
                           flow.request.pretty_url, type(exc).__name__, exc)
        finally:
            self._save_stats()

    def responseheaders(self, flow: http.HTTPFlow):
        """Stream the body to the client while copying it into the cache.

        Without the tee, mitmproxy reads the whole response before passing it
        on, and a client with a read timeout of a few seconds gives up on any
        large download.
        """
        if not self._storable(flow) or flow.response.status_code != 200:
            # A redirect carries no body, so the stream callback never fires;
            # response() stores those instead.
            return

        url = flow.request.pretty_url
        declared = flow.response.headers.get('content-length')
        chunks = []
        started = time.monotonic()

        def tee(chunk):
            # Called per chunk, then with b'' at the end.  The chunk is
            # returned unchanged whatever happens here: this sits in the path
            # of a response the client is already reading, so a fault in the
            # cache must not become a fault in the download.
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

    def response(self, flow: http.HTTPFlow):
        """Store the responses that carry no body, chiefly redirects.

        Not storing a redirect means re-resolving it every run, and where the
        target is a signed URL that is a fresh cache entry each time: the
        payload is downloaded again and a second copy kept.
        """
        if not self._storable(flow) or flow.response.status_code == 200:
            return
        self._finish(flow.request.pretty_url, flow,
                     flow.response.content or b'', None, 0)

    def _storable(self, flow: http.HTTPFlow):
        """Whether this response is one to keep."""
        return (flow.response is not None
                and not getattr(flow, 'from_cache', False)
                and flow.response.status_code in CACHEABLE_STATUS
                and self._cacheable(flow, flow.request.pretty_url, count=False))

    def _finish(self, url, flow, body, declared, elapsed_ms):
        """Store a completed response, unless it arrived short."""
        # A body short of its promised length is never stored: Git LFS serves
        # truncated files under a 200 when a quota is spent.  The client still
        # gets what it got.
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

    def _handle(self, flow: http.HTTPFlow):
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

        # Left to mitmproxy, which fetches and streams from the origin while
        # responseheaders() copies the body.  Logged, because a miss is the
        # most interesting line in the report when something goes wrong.
        self.stats['miss'] += 1
        self._log_event('MISS', url, note='not cached, fetching from origin')

    def _cacheable(self, flow, url, count=True):
        """Whether to store this request: anything not denied, and a plain
        whole-object GET."""
        host, path = flow.request.pretty_host, flow.request.path
        why = None
        if _matches(host, path, self.denied):
            why = 'denied host'
        elif any(part in path for part in DENIED_PATH_PARTS):
            why = 'git protocol endpoint, not a file'
        elif flow.request.method != 'GET':
            why = f'{flow.request.method}, not GET'
        elif 'range' in flow.request.headers:
            # Caching a partial response needs a key per byte range.
            why = 'range request'
        if why is None:
            return True
        if count:
            self.stats['forwarded'] += 1
            self._log_event('FORWARD', url, note=why)
        return False

    def _log_event(self, disposition, url, bytes_=0, elapsed_ms=0, note=''):
        """Append one request to the event log, and log it at INFO.

        The disposition is fixed-width so a CI log reads down that column.
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
        """Record the request counts, so a run can assert it used the cache."""
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
