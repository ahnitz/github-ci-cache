# github-ci-cache

A caching HTTP proxy for CI jobs, as a GitHub Action.

Route a job's downloads through a userspace caching proxy, so that data files
tests need come from a cache instead of the network. Nothing in the project
being tested has to know the cache exists — no retry wrappers, no mirror
lists, no prefetch manifest to keep in step with the tests by hand.

```yaml
    - uses: ahnitz/github-ci-cache@v1
      with:
        hosts: >-
          gwosc.org,dcc.ligo.org,zenodo.org,raw.githubusercontent.com,
          github.com/myorg/mydata/releases/download/

    - name: run the test suite
      run: pytest

    - uses: ahnitz/github-ci-cache/report@v1
      if: always()
      with:
        assert-used: true
```

That is the whole integration. The code doing the downloading is not
changed, and does not know a cache exists.

## What it does

`http_cache.sh start` launches `mitmdump` on `127.0.0.1` with the addon in
`http_cache_proxy.py`, then exports the settings that make every client use
it: `http_proxy`/`https_proxy`, plus the CA bundle under each of the six names
its clients read — `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`,
`WGETRC`, `WGET2RC`, `GIT_SSL_CAINFO` and `NODE_EXTRA_CA_CERTS`. Even that is not enough for every
client; see the `certifi` note below. In Actions the settings go to
`$GITHUB_ENV`, so the rest of the job picks them up.

A request to an allow-listed host is answered from disk if it is there. On a
miss the proxy either fetches and stores it (`record`) or refuses with a 504
naming the URL (`strict`). Anything not allow-listed is forwarded untouched.

### Modes

`mode: auto` — the default — is **strict on pull requests and record
everywhere else**. Pull requests are then hermetic: an upstream outage cannot
break one. The default branch and scheduled runs populate the cache.

A pull request that adds a *new* download would deadlock on that, so labelling
it `ci-http-cache-record` switches it to record mode. A cache written by a
pull request run can only be restored by re-runs of that same pull request, so
the label cannot affect anyone else's cache.

### Details that matter

- **`upstream_cert=false`** is what makes a cache hit need no network at all.
  By default mitmproxy fetches the real certificate to mint a lookalike, which
  contacts the origin server even when the answer is already on disk.
- **The CA bundle is the system bundle with our CA appended**, never our CA
  alone, so anything deliberately bypassing the proxy keeps its trust roots.
- **The proxy follows redirect chains itself** and stores the result under the
  URL that was asked for. GitHub release assets and zenodo files redirect to
  signed URLs that expire, so a cached redirect is a replay that breaks for no
  reason once its token goes stale.
- **Retrying lives here, not in each client.** The proxy is the only thing
  that talks to the origin server now, so one policy (4 attempts, capped
  back-off, no retry on a definitive 4xx) covers every caller — including a
  plain `curl` or `wget` with no flags of its own.
- **A body whose length disagrees with `Content-Length` is never cached.** A
  truncated body under a 200 is a real failure mode — Git LFS does it when a
  bandwidth quota is spent — and refusing to store it turns a wrong answer
  into a retryable error.
- **The cache is saved only when something new was stored**, so an unchanged
  cache is not re-uploaded every run. That matters against a 10 GB
  per-repository budget with least-recently-used eviction.
- **The allow list takes path prefixes, and should use them.** A bare host
  makes everything on it cacheable, which in strict mode means refused. A bare
  `github.com` covers the release assets we want *and* the git smart-HTTP
  endpoints we do not, so strict mode would refuse
  `pip install git+https://github.com/...`. Measured: with the prefix form, a
  `git clone` over https is `forwarded`, neither cached nor blocked.
- **Some clients ignore every CA variable there is.** astropy's
  `download_file` does `ssl.create_default_context(cafile=certifi.where())`,
  and `create_default_context` with an explicit `cafile` never consults
  `SSL_CERT_FILE`. A `sitecustomize.py` on `PYTHONPATH` overrides
  `certifi.where()`, which covers every certifi-based client without touching
  site-packages. It does shadow a project's own `sitecustomize`;
  `HTTP_CACHE_NO_SITECUSTOMIZE=1` skips it.
- **There are two wgets.** GNU wget 1.x reads `$WGETRC`; wget2 — what Fedora
  and others install as `wget` — reads `$WGET2RC` and ignores `$WGETRC`. Both
  are exported. Getting it wrong does not fail cleanly: wget2 with an
  untrusted certificate **hangs** until killed instead of reporting the
  verification failure, which in CI reads as a stuck job.
- **The proxy picks its own interpreter.** mitmproxy 12 requires Python 3.12,
  and the job's `python3` belongs to the project's test matrix — on a 3.11 leg
  the install would fail for a reason that has nothing to do with the project.
  The action looks for a suitable interpreter itself and runs the proxy in a
  virtual environment of its own, so the project's environment is untouched.
- **A proxy that cannot start is fatal only where it has to be.** In strict
  mode the guarantee is that nothing reaches the network, so there is nothing
  safe to fall back to and the job fails. In record mode the fall-back is
  exactly what the job did before this action existed — downloads go straight
  out — so it warns and carries on rather than inventing a new way for CI to
  fail.
- **Node needs its own CA variable, and GitHub's actions are Node programs.**
  They honour `http_proxy`, so they get sent through the proxy, but they verify
  TLS against Node's bundled roots and read none of the other CA variables.
  Without `NODE_EXTRA_CA_CERTS`, `actions/upload-artifact` fails — after the
  job's real work has already succeeded, which makes it a confusing failure to
  read. Their hosts should all be in `no_proxy` too, but an action meant to
  reduce fragility should not rely on that list being exhaustive.
- **`no_proxy` excludes three groups**: the package ecosystems (own caches,
  would dominate the budget), the GitHub API (a job's token should not pass
  through a process that terminates TLS), and the Actions cache service
  itself (or the proxy sits in the path of its own persistence).

## Verified

Recorded cold, then replayed in strict mode with **both the proxy and the
clients inside a network namespace with no route off loopback**, where a direct
fetch was confirmed impossible. `curl`, `wget`, `urllib`, `requests`,
`astropy.download_file` and `git clone` all worked; the bodies came back
byte-identical to the recorded ones; a URL that was not in the cache got a 504.

A server that declares 1000 bytes and sends 100 -- the Git LFS quota failure --
is retried and then reported as a 502, and **nothing is cached**, verified
against a deliberately lying local server.

## Why not something off the shelf

| Candidate | Why it does not fit |
|---|---|
| [`cirruslabs/http-cache-action`](https://github.com/cirruslabs/http-cache-action) | Despite the name, a key/value cache **API** for Gradle/Bazel/Buck, not a forward proxy. Does not cache ordinary downloads. |
| [`airtasker/proxay`](https://github.com/airtasker/proxay) | Closest in intent, but a **reverse** proxy the client must point at per backend, not `http_proxy`. Tapes are YAML with inline bodies — unusable for 100–300 MB binaries. |
| [`chayleaf/mitm-cache`](https://github.com/chayleaf/mitm-cache) | Mechanically closest: Rust MITM forward proxy, own CA, record then replay offline. But it is built for Nix and its store is a **lockfile of hashes you commit** — which is the hand-maintained manifest this exists to delete. |
| [`mtib/mitm-cache`](https://github.com/mtib/mitm-cache), [`skorotkiewicz/proxy-cache`](https://github.com/skorotkiewicz/proxy-cache) | General MITM caching proxies, but no Actions packaging, no CI-event-driven record/strict modes, no persistence story, and a new binary dependency to vet. |
| mitmproxy's own [`server_replay`](https://docs.mitmproxy.org/stable/concepts/options/) | Genuinely close, and `server_replay_kill_extra` gives strict mode for free. But the store is **one monolithic flow file**: a cache action re-uploads all of it whenever anything changes, one entry cannot be inspected or pruned, and recording writes at exit, so a killed job loses everything it downloaded. |
| `vcrpy`, `pytest-recording`, MockServer | Mature, but per-test decoration — metadata in every test file, the shape of the problem being removed — and they cannot cover `curl`/`wget` in example shell scripts at all. |
| `squid` with SSL-bump | The classic answer, and documented for self-hosted runners. Needs root and a system package, and its cache format is not something a cache action restores usefully. |

So: the *mechanism* is well-trodden and the engine is off the shelf
(mitmproxy). What does not exist is the packaging — CI-event-driven modes, a
per-entry store a cache action can persist incrementally, and the counts a job
can assert on. That is what this directory is.

## Inputs

See `action.yml` and `report/action.yml`. The only required input is `hosts`:
which hosts are worth caching is a property of the project, and caching
everything that passes through would blow the cache budget.

## Locally

```bash
export HTTP_CACHE_HOSTS=example.org
eval "$(./http_cache.sh start)"
# ... run whatever downloads ...
./http_cache.sh stop
```

The scripts need `mitmproxy` on the path (or `HTTP_CACHE_MITMDUMP` pointing at
it); the action installs it into a virtual environment of its own.

`HTTP_CACHE_MODE=strict` with the network removed (`unshare -n`, or
`docker run --network none`) is how to prove a test needs nothing but the
cache.
