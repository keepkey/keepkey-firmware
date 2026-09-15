#!/usr/bin/env python3
"""Symbol-survival gate for the alpha<-develop merge.

A symbol alpha defined may only be dropped if nothing in the merged tree still
references it.

READ THIS BEFORE TRUSTING A GREEN RUN. This gate is necessary and NOT
sufficient. It reached 0 while 24 of 79 contested files had been taken
byte-identical from the wrong side, because:

  - Both branches define the SAME function names. A file swapped wholesale keeps
    every name and only weakens the bodies, so nothing is ever "referenced but
    undefined".
  - A static function dropped together with its only callers scores as a SAFE
    DROP. That is how nine EIP-712 type-validation helpers vanished silently.
  - A symbol whose DEFINITION survives while its CALL SITES came from the other
    side is invisible here. That is how the whole Maya EVM branch became
    unreachable dead code with the gate still green.

Run tools/merge_direction_gate.py FIRST. It asks the question that actually
decides a merge: which side did each contested FILE come from.

It also OVER-reports: it does not evaluate #if guards and does not look inside
deps/, so a platform-guarded or vendored definition reads as missing.

Every read below is a PRECONDITION, not a best effort. An unfetched OLD or a
run from the wrong directory used to yield an empty baseline and an empty
corpus, which printed "REGRESSIONS: 0" and exited 0 -- byte-identical to a
genuinely clean run. A gate that read nothing must abort, never pass.
"""
import subprocess, re, sys, os, collections

OLD = '681df4a0a'
DEF = re.compile(r'^[A-Za-z_][\w \*]*\s+\**(\w+)\s*\([^;]*\)\s*\{', re.M)

# Anchor everything to the checkout this script lives in, so the answer does
# not depend on the caller's CWD.
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

def defs_in(src):
    return set(DEF.findall(src))

# 0. the baseline commit must actually be in this clone. A shallow or
#    branch-limited fetch is the common way OLD goes missing.
sh('rev-parse', '--verify', f'{OLD}^{{commit}}')

# 1. baseline: every function alpha defined
base = {}
for f in sh('ls-tree','-r','--name-only',OLD,'lib/','include/').split():
    if not f.endswith(('.c','.h')): continue
    for s in defs_in(sh('show',f'{OLD}:{f}')):
        base.setdefault(s, f)
if not base:
    sys.exit(f'FATAL: {OLD} yielded no function definitions under lib/ or '
             f'include/ -- the baseline is empty, nothing was compared')

# 2. merged tree: definitions + all text
#    Paths stay ROOT-relative: the TEST-ONLY classification below keys off the
#    'unittests'/'tools' prefix, and absolute paths would silently promote every
#    test-only regression to REAL.
now_defs, corpus = set(), {}
for root in ('lib','include','unittests','tools'):
    for dp,_,fns in os.walk(os.path.join(ROOT, root)):
        if 'deps' in dp.split(os.sep): continue
        for fn in fns:
            if not fn.endswith(('.c','.h','.cpp','.cc')): continue
            p = os.path.relpath(os.path.join(dp,fn), ROOT)
            src = open(os.path.join(ROOT,p), errors='replace').read()
            corpus[p] = src
            if p.startswith(('lib','include')): now_defs |= defs_in(src)
if not corpus:
    sys.exit(f'FATAL: walked {ROOT} and found no sources -- the corpus is '
             f'empty, nothing was compared')

# 3. dropped symbols that are still referenced
regressions = collections.defaultdict(list)
for sym, f in sorted(base.items()):
    if sym in now_defs: continue
    hits = []
    pat = re.compile(r'\b%s\s*\(' % re.escape(sym))
    for p, src in corpus.items():
        n = len(pat.findall(src))
        if n: hits.append((p, n))
    if hits:
        regressions[(f, sym)] = hits

test_only = {k: v for k, v in regressions.items()
             if all(p.startswith(('unittests','tools')) for p, _ in v)}
real = {k: v for k, v in regressions.items() if k not in test_only}

print(f'REGRESSIONS: {len(regressions)}  (real: {len(real)}, test-only: {len(test_only)})\n')
for label, group in (('REAL -- called from lib/', real), ('TEST-ONLY', test_only)):
    print(f'== {label} ==')
    for (f, sym), hits in sorted(group.items()):
        n = sum(h for _, h in hits)
        print(f'   {f:<48} {sym:<42} {n} site(s)')
    print()
sys.exit(1 if real else 0)
