#!/usr/bin/env python3
"""Direction-of-resolution audit.

gate.py asks "is this symbol still defined?" -- which a file taken wholesale
from the wrong side passes trivially, because the DEFINITION survives while
every CALLER came from the other branch.

This asks the question that actually decides the merge: for every file BOTH
branches changed, which side did the merged tree end up equal to, and how much
of the other side's work went with it?

Every read below is a PRECONDITION, not a best effort. The three revisions are
hardcoded short SHAs; an auditor's clone (or a shallow/branch-limited CI fetch)
that lacks one of them used to make every git call return '', so `both` came out
empty and the gate printed "0 files took develop wholesale" and exited 0 -- the
same output as a real audit of a clean merge. A gate that compared nothing must
abort, never pass.
"""
import subprocess, sys, os

BASE, ALPHA, DEV = '1af2ffe7de', '681df4a0a', 'bd3a1d6e9'

# Anchor everything to the checkout this script lives in, so the answer does
# not depend on the caller's CWD. Reading files relative to the CWD was a
# second, independent path to the same false green: from any other directory
# every file raised FileNotFoundError and scored 'DELETED', which feeds neither
# bad_a nor bad_d.
_root = subprocess.run(('git', '-C', os.path.dirname(os.path.abspath(__file__)),
                        'rev-parse', '--show-toplevel'),
                       capture_output=True, text=True)
if _root.returncode:
    sys.exit(f'FATAL: not inside a git checkout: {_root.stderr.strip()}')
ROOT = _root.stdout.strip()

def sh(*a):
    # git only, at ROOT, and fatal on failure with stderr surfaced.
    p = subprocess.run(('git', '-C', ROOT) + a, capture_output=True, text=True)
    if p.returncode:
        sys.exit(f'FATAL: git {" ".join(a)} failed: {p.stderr.strip()}')
    return p.stdout

def changed(a, b):
    return set(sh('diff', '--name-only', a, b).split())

def blob(rev, f):
    # None when the path does not exist at rev. A file one side deleted is a
    # legitimate answer to "which side is this equal to" (the answer is
    # "neither"), unlike a failed diff, which means the audit is broken -- so
    # this one read is deliberately tolerant while sh() stays fatal.
    p = subprocess.run(('git', '-C', ROOT, 'show', f'{rev}:{f}'),
                       capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None

def churn(a, b, f):
    out = sh('diff', '--numstat', a, b, '--', f).split()
    return int(out[0]) + int(out[1]) if len(out) >= 2 and out[0].isdigit() else 0

# The three revisions must actually be in this clone, or every comparison below
# is vacuous.
for rev in (BASE, ALPHA, DEV):
    sh('rev-parse', '--verify', f'{rev}^{{commit}}')

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
if not both:
    sys.exit(f'FATAL: no file was changed by both {ALPHA} and {DEV} since '
             f'{BASE} -- there is nothing to adjudicate, which means the '
             f'revisions are wrong, not that the merge is clean')
rows = []
for f in both:
    try:
        cur = open(os.path.join(ROOT, f), errors='replace').read()
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
