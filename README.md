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

One Actions cache entry called `http-cache`, replaced whenever a job stored
something new. A job that hit the cache for everything it asked for uploads
nothing. Deleting the entry from the repository's cache page is safe; the next
run fills it again.

Every job in a run shares that one key, so each upload has to carry the other
jobs' work as well as its own. Before uploading, a job restores the key again
and unpacks it over what it already has, making the upload a superset of the
entry it replaces. Without that step the uploads are last-writer-wins and the
cache only ever gains the downloads of whichever job finished last. The race
is narrowed, not closed: a job that uploads in the seconds between another
job's restore and its upload loses its downloads until the next run, and the
cache API offers no compare-and-swap to do better.

One entry for every platform, not one per platform: these are HTTP responses,
so a file fetched on macOS is the same file on Linux. The cache lives at a
fixed path for that reason -- a path built from `$HOME` differs between the
two and would silently give each its own copy.

A pull request never writes the cache unless its branch lives in the
repository itself. It still reads one: a run restores entries scoped to its
own ref and to its base branch, and reading was never restricted. So the
default branch is the writer -- on its own pushes, and on the schedule in the
refresh workflow -- and every pull request reads what it leaves.

A pull request from another repository could create an entry, but the entry
would be scoped to `refs/pull/N/merge`, readable by that one pull request and
nothing else, holding whatever the job that made it happened to download, with
no way to improve it afterwards. Such a run skips the upload, and the delete,
and folding the cache in, and says so in its one notice.

One consequence worth knowing: an entry in a pull request's own scope shadows
the default branch's, and restoring it every run keeps resetting its seven-day
eviction timer. A pull request that cached something before this rule existed
will keep reading that copy until the entry is deleted by hand.

Who can write it follows from the two credentials involved. Deleting an entry
goes through the REST API on `GITHUB_TOKEN`, which needs `actions: write` and
is read-only on a pull request from a fork; uploading goes through the cache
service on `ACTIONS_RUNTIME_TOKEN`, which every job has. So:

- Nothing in the way: upload, no delete. This is how the cache first appears,
  and it works even on a fork's pull request.
- An entry in the way and deletable: delete, then upload over it.
- An entry in the way and not deletable: keep it and skip the upload, which
  could only conflict. A run would otherwise report one conflict warning per
  job. A pull request on a branch of the repository itself lands here only if
  the repository withholds `actions: write` from workflows.

"In the way" comes from the restore, not from asking the API: a restore hits
only for an entry whose key and version both match what an upload would use,
and the version is a hash of the path that a caller cannot compute for itself.

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
