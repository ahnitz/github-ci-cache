# github-ci-cache

Caches the files a CI job downloads, so a flaky origin server stops failing
your build. Nothing in the project being tested has to change.

```yaml
    - uses: ahnitz/github-ci-cache@v1

    - name: run the tests
      run: pytest

    - uses: ahnitz/github-ci-cache/report@v1
      if: always()
```

That is the whole integration. No inputs.

## What it does

The first step starts a caching proxy on localhost and points every client at
it — `curl`, `wget`, `git`, `urllib`, `requests`, `astropy`. A file that was
downloaded by an earlier run is served from disk; anything else goes to the
origin as normal and is then stored. The cache can only make a job faster or
more reliable, never less: with nothing cached at all, the job behaves exactly
as it did before.

The second step stops the proxy, prints what happened, and saves the cache.

Everything a job downloads is cached, except:

- the package registries (PyPI, conda, apt), which have their own caches
- the GitHub API and the Actions services, which carry your credentials
- git's smart-HTTP endpoints, which are a protocol rather than a file
- non-`GET` and range requests

There is no list of hosts to maintain.

## What you get in the log

One line per request, outcome first:

```
STORE      2492 B   96ms  https://raw.githubusercontent.com/…/README.md
HIT        2492 B      -  https://raw.githubusercontent.com/…/README.md
MISS            -      -  https://gwosc.org/eventapi/json/
FORWARD         -      -  https://github.com/org/repo/info/refs?service=git-upload-pack
```

plus a job summary listing every URL under its outcome, and how many bytes
were served without touching the network.

## The cache itself

One Actions cache entry called `http-cache`, replaced each time something new
is stored. Deleting it from the repository's cache page is safe; the next run
fills it again.

A pull request from a fork gets a read-only token, so it can restore the cache
but not replace it.

## Options

All optional.

| Input | Default | |
|---|---|---|
| `mode` | `record` | `strict` refuses a miss with a 504 naming the URL, for showing that a job needs nothing but the cache. `off` starts no proxy. |
| `cache-key` | `http-cache` | Name of the cache entry. |
| `port` | `3128` | Proxy port on `127.0.0.1`. |
| `no-proxy` | *(see above)* | Overrides the built-in deny list. |
| `mitmproxy-version` | pinned | |

`report` takes `assert-used`, to fail if nothing was routed through the proxy,
and `fail-on-blocked` (default true) for strict mode.

## Running it locally

```bash
eval "$(./http_cache.sh start)"
# ... run whatever downloads ...
./http_cache.sh stop
```

`HTTP_CACHE_MODE=strict` with the network removed — `unshare -n`, or
`docker run --network none` — shows whether a job needs anything it has not
already cached.

## How it works

[mitmproxy](https://mitmproxy.org) does the proxying; `http_cache_proxy.py` is
the cache. HTTPS is intercepted with a CA generated per run, exported through
the several variables its clients each read, and appended to the system bundle
rather than replacing it. Hosts on the deny list are tunnelled without
interception, so they never see a substituted certificate.

Entries are one directory each, named for the sha256 of the request, holding
the body and its metadata.
