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
"""
import subprocess, re, sys, os, collections

OLD = '681df4a0a'
DEF = re.compile(r'^[A-Za-z_][\w \*]*\s+\**(\w+)\s*\([^;]*\)\s*\{', re.M)

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True).stdout

def defs_in(src):
    return set(DEF.findall(src))

# 1. baseline: every function alpha defined
base = {}
for f in sh('git','ls-tree','-r','--name-only',OLD,'lib/','include/').split():
    if not f.endswith(('.c','.h')): continue
    for s in defs_in(sh('git','show',f'{OLD}:{f}')):
        base.setdefault(s, f)

# 2. merged tree: definitions + all text
now_defs, corpus = set(), {}
for root in ('lib','include','unittests','tools'):
    for dp,_,fns in os.walk(root):
        if 'deps' in dp.split(os.sep): continue
        for fn in fns:
            if not fn.endswith(('.c','.h','.cpp','.cc')): continue
            p = os.path.join(dp,fn)
            src = open(p, errors='replace').read()
            corpus[p] = src
            if dp.startswith(('lib','include')): now_defs |= defs_in(src)

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
