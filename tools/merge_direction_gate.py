#!/usr/bin/env python3
"""Direction-of-resolution audit.

gate.py asks "is this symbol still defined?" -- which a file taken wholesale
from the wrong side passes trivially, because the DEFINITION survives while
every CALLER came from the other branch.

This asks the question that actually decides the merge: for every file BOTH
branches changed, which side did the merged tree end up equal to, and how much
of the other side's work went with it?
"""
import subprocess, sys, os

BASE, ALPHA, DEV = '1af2ffe7de', '681df4a0a', 'bd3a1d6e9'

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout

def changed(a, b):
    return set(sh('git', 'diff', '--name-only', a, b).split())

def blob(rev, f):
    return sh('git', 'show', f'{rev}:{f}')

def churn(a, b, f):
    out = sh('git', 'diff', '--numstat', a, b, '--', f).split()
    return int(out[0]) + int(out[1]) if len(out) >= 2 and out[0].isdigit() else 0

ok = set()
try:
    for line in open(os.path.join(os.path.dirname(__file__),
                                  'merge-direction-adjudicated.txt')):
        line = line.split('#')[0].strip()
        if line:
            ok.add(line)
except FileNotFoundError:
    pass

both = sorted(changed(BASE, ALPHA) & changed(BASE, DEV))
rows = []
for f in both:
    try:
        cur = open(f, errors='replace').read()
    except IsADirectoryError:
        continue  # submodule gitlink, not a file this gate can compare
    except FileNotFoundError:
        rows.append((f, 'DELETED', churn(BASE, ALPHA, f), churn(BASE, DEV, f)))
        continue
    a_churn, d_churn = churn(BASE, ALPHA, f), churn(BASE, DEV, f)
    if cur == blob(ALPHA, f):
        side = 'alpha-verbatim'
    elif cur == blob(DEV, f):
        side = 'DEVELOP-VERBATIM'
    else:
        side = 'merged'
    if f not in ok:
        rows.append((f, side, a_churn, d_churn))

def show(title, sel):
    hits = [r for r in rows if sel(r)]
    print(f'\n=== {title}: {len(hits)} ===')
    for f, side, a, d in sorted(hits, key=lambda r: -(r[2] + r[3])):
        print(f'   {side:<17} alpha:{a:<5} develop:{d:<5} {f}')
    return hits

print(f'{len(both)} files changed by BOTH branches, '
      f'{len(ok)} already adjudicated (tools/merge-direction-adjudicated.txt)\n'
      + '=' * 72)
bad_a = show('alpha work DROPPED (took develop verbatim, alpha had changed it)',
             lambda r: r[1] == 'DEVELOP-VERBATIM')
bad_d = show('develop work AT RISK (took alpha verbatim, develop had changed it)',
             lambda r: r[1] == 'alpha-verbatim')
show('genuinely merged', lambda r: r[1] == 'merged')
show('deleted', lambda r: r[1] == 'DELETED')

print('\n' + '=' * 72)
print(f'{len(bad_a)} files took develop wholesale over alpha changes')
print(f'{len(bad_d)} files took alpha wholesale over develop changes')
sys.exit(1 if (bad_a or bad_d) else 0)
