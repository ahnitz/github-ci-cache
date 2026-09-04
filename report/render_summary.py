"""Render what the caching proxy did, for the CI log and the job summary.

Reads the event log the proxy appends to as it runs -- one JSON object per
request -- and prints a markdown summary.  The counters in stats.json say how
many requests went each way; this says which ones, which is what someone
looking at an unexpected cache miss in a CI log actually needs.
"""

import json, os, sys

path, mode = sys.argv[1], sys.argv[2]
events = []
if os.path.exists(path):
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass

def human(count):
    """Bytes at a readable scale -- 2492 is 2.4 KB, not 0.0 MB."""
    for unit, scale in (('MB', 1e6), ('KB', 1e3)):
        if count >= scale:
            return f'{count / scale:.1f} {unit}'
    return f'{count} B'


LABELS = {
    'HIT': 'served from the cache',
    'STORE': 'fetched and added to the cache',
    'BLOCK': 'refused (not cached, strict mode)',
    'FORWARD': 'passed through, not cached',
    'ERROR': 'upstream failed',
}
by_kind = {}
for event in events:
    by_kind.setdefault(event['disposition'], []).append(event)

print(f'### HTTP cache ({mode} mode)')
print()
if not events:
    print('No requests reached the proxy.')
    raise SystemExit(0)

print('| outcome | requests | bytes |')
print('|---|---|---|')
for kind, label in LABELS.items():
    group = by_kind.get(kind)
    if group:
        total = sum(e.get('bytes', 0) for e in group)
        print(f'| {label} | {len(group)} | {human(total)} |')
print()

# Cached bytes are the ones that did not cross the network this run, which is
# the number the whole exercise is about.
saved = sum(e.get('bytes', 0) for e in by_kind.get('HIT', []))
print(f'**{human(saved)} served without touching the network.**')
print()

for kind, label in LABELS.items():
    group = by_kind.get(kind)
    if not group:
        continue
    print(f'<details><summary>{len(group)} {label}</summary>')
    print()
    print('| bytes | time | url | note |')
    print('|---|---|---|---|')
    for event in group:
        note = event.get('note', '').replace('|', '\\|')
        elapsed = event.get('elapsed_ms') or 0
        print(
            f"| {human(event.get('bytes', 0))} "
            f"| {str(int(elapsed)) + 'ms' if elapsed else '-'} "
            f"| `{event['url']}` | {note} |"
        )
    print()
    print('</details>')
    print()
