#!/usr/bin/env python3
"""Regenerate unittests/firmware/uniswap_ur_vectors.h from real Universal Router calls.

An independent Python decoder (no shared code with lib/firmware/uniswap_ur.c): the
C unit tests pass only when the two implementations agree on real calldata.

  gen_ur_vectors.py fetch DIR        # save recent Base router txs (base.blockscout.com) into DIR
  gen_ur_vectors.py header DIR > unittests/firmware/uniswap_ur_vectors.h
  gen_ur_vectors.py pack DIR > unittests/firmware/uniswap_ur_sample.bin
  gen_ur_vectors.py expect unittests/firmware/uniswap_ur_sample.bin > unittests/firmware/uniswap_ur_expected.txt
"""
import glob, json, os, sys, urllib.request

# UR 2.0, UR 1.2, and UR 2.1.2 (the router the Uniswap app sends to on Base).
ROUTERS = ["0x6fF5693b99212Da76ad316178A184AB56D299b43", "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
           "0xd6145b2D3F379919E8CdEda7B97e37c4b2Ca9c40"]
KIND = {0x00: 'UR_V3_SWAP_EXACT_IN', 0x01: 'UR_V3_SWAP_EXACT_OUT', 0x0a: 'UR_PERMIT2_PERMIT',
        0x0b: 'UR_WRAP_ETH', 0x0c: 'UR_UNWRAP_WETH', 0x04: 'UR_SWEEP',
        0x06: 'UR_PAY_PORTION', 0x08: 'UR_V2_SWAP_EXACT_IN', 0x09: 'UR_V2_SWAP_EXACT_OUT'}


def w(b, i):
    return int.from_bytes(b[i:i + 32], 'big')


def dyn(b, base, off):
    o = base + off
    n = w(b, o)
    return b[o + 32:o + 32 + n]


def decode(raw):
    """[(cmd, fields...)] for an execute(bytes,bytes[],uint256) call."""
    b = bytes.fromhex(raw[10:])
    cmds = dyn(b, 0, w(b, 0))
    arr = w(b, 32)
    out = []
    for k in range(w(b, arr)):
        inp = dyn(b, arr + 32, w(b, arr + 32 + 32 * k))
        c = cmds[k] & 0x3f
        if c in (0x00, 0x01):
            path = dyn(inp, 0, w(inp, 96))
            toks = [path[0:20].hex()] + [path[i + 3:i + 23].hex() for i in range(20, len(path) - 22, 23)]
            if c == 0x01:
                toks = toks[::-1]
            out.append((c, toks[0], toks[-1], w(inp, 32), w(inp, 64)))
        elif c == 0x0a:
            out.append((c, inp[12:32].hex(), '', w(inp, 32), None))
        elif c in (0x0b, 0x0c):
            out.append((c, '', '', w(inp, 32), None))
        elif c in (0x08, 0x09):
            # (recipient, amount, limit, address[] path, payerIsUser); the V2
            # path runs input -> output for both directions.
            o = w(inp, 96)
            n = w(inp, o)
            path = [inp[o + 32 + 32 * j + 12:o + 64 + 32 * j].hex() for j in range(n)]
            out.append((c, path[0], path[-1], w(inp, 32), w(inp, 64)))
        elif c in (0x04, 0x06):
            # SWEEP (token, recipient, amountMin); PAY_PORTION (token, recipient, bips)
            out.append((c, inp[12:32].hex(), '', w(inp, 64), None))
        else:
            out.append((c,))
    return out


def fetch(d, pages=8):
    """Save `pages` explorer pages (50 txs each) per router as DIR/<router>-<n>.json."""
    import urllib.parse
    os.makedirs(d, exist_ok=True)
    for r in ROUTERS:
        params = {'filter': 'to'}
        for n in range(pages):
            url = 'https://base.blockscout.com/api/v2/addresses/%s/transactions?%s' % (r, urllib.parse.urlencode(params))
            req = urllib.request.Request(url, headers={'user-agent': 'keepkey-ur-vectors/1'})
            body = urllib.request.urlopen(req, timeout=30).read()
            open(os.path.join(d, '%s-%d.json' % (r, n)), 'wb').write(body)
            nxt = json.loads(body).get('next_page_params')
            if not nxt:
                break
            params = dict(nxt, filter='to')


# Pinned: signed_metadata.cpp builds its end-to-end review on the first; the
# second is a Permit2 swap between reviewed Base tokens (USDC -> USDbC) that
# KeepKey Desktop's certified-attach tests need.
ALWAYS = ('0xd873988f8c2a7ef53ce52a0bc890a029e0bde5e731ad30c17e4991fb080dbbab',
          '0x81fa9e1f87d0b269986082edbdaebbf6c0b005918f389f6762601b47139d27e1')


def header(d, limit=250, v4_limit=10):
    """Deterministic subset: pinned calls, then app-shaped (permit/wrap), then the rest."""
    ok, v4, seen = [], [], set()
    for f in sorted(glob.glob(os.path.join(d, '0x*.json'))):
        for it in json.load(open(f)).get('items', []):
            raw, h = it.get('raw_input') or '', it.get('hash')
            if not raw.startswith(('0x3593564c', '0x24856bc3')) or h in seen:
                continue
            seen.add(h)
            steps = decode(raw)
            if any(s[0] == 0x10 for s in steps):
                v4.append(raw)
            elif all(s[0] in KIND for s in steps):
                ok.append((h, (it.get('to') or {}).get('hash', '').lower()[2:], int(it.get('value') or 0), raw, steps))
    def rank(v):
        app = any(st[0] in (0x0a, 0x0b) for st in v[4])
        rare = any(st[0] in (0x04, 0x06, 0x08, 0x09) for st in v[4])
        return (v[0] not in ALWAYS, not rare, not app, v[0])
    ok = sorted(ok, key=rank)[:limit]
    v4 = sorted(v4)[:v4_limit]
    p = print
    p('// Generated from real Base Universal Router calls (base.blockscout.com, 2026-10-03)')
    p('// by an independent Python decoder (scripts/uniswap/gen_ur_vectors.py). Do not regenerate')
    p('// from the C decoder: the point is two implementations agreeing.')
    p('#include <cstdint>\n#include <string>\n#include <vector>\nnamespace urv {')
    p('struct Step { int kind; std::string token_in, token_out, amount, limit; };')
    p('struct Vec { std::string tx, router, value, calldata; std::vector<Step> steps; };')
    p('inline const std::vector<Vec>& accepted() { static const std::vector<Vec> v = {')
    for h, to, val, raw, steps in ok:
        out = []
        for s in steps:
            lim = '' if s[4] is None else '%064x' % s[4]
            out.append('{%s,"%s","%s","%064x","%s"}' % (KIND[s[0]], s[1], s[2], s[3], lim))
        p('  {"%s", "%s", "%064x", "%s", {%s}},' % (h, to, val, raw[2:], ','.join(out)))
    p('}; return v; }')
    p('inline const std::vector<std::string>& v4_rejected() { static const std::vector<std::string> v = {')
    for raw in v4:
        p('  "%s",' % raw[2:])
    p('}; return v; }\n}  // namespace urv')


def pack(d):
    """Every execute() call in DIR as compact binary records, sorted by tx hash:
    hash(32) | status(1: 1 ok, 0 reverted) | msg.value(32) | length(4, big-endian) | calldata.
    The differential test (uniswap_ur.cpp) and v4_classify.py read it."""
    recs = {}
    for f in glob.glob(os.path.join(d, '0x*.json')):
        for it in json.load(open(f)).get('items', []):
            raw = it.get('raw_input') or ''
            if raw.startswith(('0x3593564c', '0x24856bc3')):
                recs[it['hash'].lower()] = (it.get('status') == 'ok', int(it.get('value') or 0), bytes.fromhex(raw[2:]))
    out = sys.stdout.buffer
    for h in sorted(recs):
        ok, value, cd = recs[h]
        out.write(bytes.fromhex(h[2:]) + bytes([ok]) + value.to_bytes(32, 'big') + len(cd).to_bytes(4, 'big') + cd)


# ---- Full model: plan + review, written from the router's Solidity source ----
# Universal Router 2.1.2 on Base (verified source, base.blockscout.com, the
# contract at 0xd6145b2D...9c40): Dispatcher.sol, V4SwapRouter.sol and the
# v4-periphery it was built with (V4Router.sol, IV4Router.sol, PathKey.sol,
# ActionConstants.sol, Actions.sol, DeltaResolver.sol, BipsLibrary.sol).
# Independent of lib/firmware/uniswap_ur.c; uniswap_ur.cpp requires the two to
# agree on every sample call (`expect`).

class Refused(Exception):
    pass


def need(cond):
    if not cond:
        raise Refused()


# UrKind, in the order of uniswap_ur.h
(V3_IN, V3_OUT, V2_IN, V2_OUT, PERMIT, WRAP, UNWRAP, SWEEP, PAY_PORTION, TRANSFER,
 V4_IN, V4_OUT, V4_TAKE_PORTION) = range(13)
MAX_STEPS, MAX_HOOKS, V4_MAX_PATH = 6, 3, 4
CONTRACT_BALANCE = 1 << 255
MSG_SENDER, ADDRESS_THIS = 1, 2


class Body:
    """A byte string read the way abi.decode reads it: every value must fit its
    declared type (the router reverts otherwise; the device refuses)."""
    def __init__(self, b):
        self.b = b

    def word(self, off):
        need(0 <= off and off + 32 <= len(self.b))
        return int.from_bytes(self.b[off:off + 32], 'big')

    def uint(self, off, bits):
        v = self.word(off)
        need(v < (1 << bits))
        return v

    def int24(self, off):
        v = self.word(off)
        need(v < (1 << 23) or v >= (1 << 256) - (1 << 23))

    def addr(self, off):
        return self.uint(off, 160)

    def boolean(self, off):
        v = self.word(off)
        need(v <= 1)
        return v == 1

    def ofs(self, off):
        return self.uint(off, 32)

    def bytes_at(self, base, head):
        """`bytes` whose offset word is at base+head, relative to base."""
        o = base + self.ofs(base + head)
        n = self.ofs(o)
        need(o + 32 + n <= len(self.b))
        return self.b[o + 32:o + 32 + n]


def step(kind, token_in=0, token_out=0, recipient=0, amount=0, limit=0, payer=False, expiration=0):
    return dict(kind=kind, token_in=token_in, token_out=token_out, recipient=recipient,
                amount=amount, limit=limit, payer=payer, expiration=expiration)


def v4_steps(inp, hooks):
    """V4_SWAP input: abi.encode(bytes actions, bytes[] params) (V4Router)."""
    b = Body(inp)
    actions = b.bytes_at(0, 0)
    po = b.ofs(32)
    n = b.ofs(po)
    need(len(actions) == n)
    params = [b.bytes_at(po + 32, 32 * k) for k in range(n)]
    acts = list(actions)
    SW_IN, SW_OUT, SETTLE, TAKE, TAKE_PORTION = 0x07, 0x09, 0x0b, 0x0e, 0x10
    shapes = [[SW_IN, SETTLE, TAKE], [SW_OUT, SETTLE, TAKE], [SETTLE, SW_IN, TAKE],
              [SW_IN, SETTLE, TAKE_PORTION, TAKE], [SETTLE, SW_IN, TAKE_PORTION, TAKE]]
    need(acts in shapes)
    swap = fee = None
    settle = take = None
    for a, p in zip(acts, params):
        q = Body(p)
        if a in (SW_IN, SW_OUT):
            # Exact{In,Out}putParams(currency, PathKey[] path, uint256[] minHopPriceX36,
            # uint128 amount, uint128 limit), abi-encoded as one dynamic struct.
            sb = q.ofs(0)
            cur = q.addr(sb)
            pth = sb + q.ofs(sb + 32)
            q.ofs(sb + 64)
            amount = q.uint(sb + 96, 128)
            limit = q.uint(sb + 128, 128)
            npath = q.ofs(pth)
            need(1 <= npath <= V4_MAX_PATH)
            path = []
            for k in range(npath):
                e = pth + 32 + q.ofs(pth + 32 + 32 * k)
                # PathKey(intermediateCurrency, uint24 fee, int24 tickSpacing, hooks, bytes hookData)
                c = q.addr(e)
                q.uint(e + 32, 24)
                q.int24(e + 64)
                h = q.addr(e + 96)
                need(len(q.bytes_at(e, 128)) == 0)
                path.append(c)
                if h and h not in hooks:
                    need(len(hooks) < MAX_HOOKS)
                    hooks.append(h)
            if a == SW_IN:
                swap = step(V4_IN, cur, path[-1], amount=amount, limit=limit)
                need(amount != 0 if acts[0] != SETTLE else amount == 0)
            else:
                swap = step(V4_OUT, path[0], cur, amount=amount, limit=limit)
                need(amount != 0)
        elif a == SETTLE:
            settle = (q.addr(0), q.word(32), q.boolean(64))
        elif a == TAKE:
            take = (q.addr(0), q.addr(32), q.word(64))
        else:
            fee = step(V4_TAKE_PORTION, q.addr(0), recipient=q.addr(32), amount=q.word(64))
    cur, amt, payer = settle
    if acts[0] == SETTLE:
        need(amt != 0 and not (payer and amt == CONTRACT_BALANCE))
        swap['amount'] = amt
    else:
        need(amt == 0)
    need(cur == swap['token_in'] and take[0] == swap['token_out'] and swap['token_in'] != swap['token_out'])
    need(take[2] == 0 or (swap['kind'] == V4_OUT and take[2] == swap['amount']))
    swap['recipient'] = take[1]
    swap['payer'] = payer and cur != 0
    if fee:
        need(fee['token_in'] == swap['token_out'])
        return [swap, fee]
    return [swap]


def decode_plan(raw):
    """(steps, hooks, deadline) for an execute() call, or Refused."""
    cd = bytes.fromhex(raw[2:] if raw.startswith('0x') else raw)
    need(len(cd) >= 4)
    sel = cd[:4].hex()
    need(sel in ('3593564c', '24856bc3'))
    b = Body(cd[4:])
    cmds = b.bytes_at(0, 0)
    io = b.ofs(32)
    deadline = b.uint(64, 64) if sel == '3593564c' else None
    n = b.ofs(io)
    need(1 <= len(cmds) <= MAX_STEPS and n == len(cmds))
    steps, hooks = [], []
    for k, c in enumerate(cmds):
        need(c & 0xc0 == 0)
        inp = Body(b.bytes_at(io + 32, 32 * k))
        if c in (0x00, 0x01):
            # (recipient, amountIn|Out, amountOutMin|InMax, bytes path, payerIsUser[, uint256[]])
            path = inp.bytes_at(0, 96)
            need(len(path) >= 43 and (len(path) - 20) % 23 == 0)
            first, last = int.from_bytes(path[:20], 'big'), int.from_bytes(path[-20:], 'big')
            st = step(V3_IN if c == 0 else V3_OUT, first if c == 0 else last, last if c == 0 else first,
                      inp.addr(0), inp.word(32), inp.word(64), inp.boolean(128))
        elif c in (0x08, 0x09):
            po = inp.ofs(96)
            m = inp.ofs(po)
            need(2 <= m <= 8)
            toks = [inp.addr(po + 32 + 32 * j) for j in range(m)]
            st = step(V2_IN if c == 0x08 else V2_OUT, toks[0], toks[-1], inp.addr(0), inp.word(32),
                      inp.word(64), inp.boolean(128))
        elif c == 0x0a:
            # PermitSingle{details{token, uint160 amount, uint48 expiration, uint48 nonce}, spender, sigDeadline}, bytes sig
            st = step(PERMIT, inp.addr(0), inp.addr(128), amount=inp.uint(32, 160), expiration=inp.uint(64, 48))
            inp.uint(96, 48)
            inp.word(160)
            inp.bytes_at(0, 192)
        elif c in (0x0b, 0x0c):
            st = step(WRAP if c == 0x0b else UNWRAP, recipient=inp.addr(0), amount=inp.word(32))
        elif c in (0x04, 0x05, 0x06):
            st = step({4: SWEEP, 5: TRANSFER, 6: PAY_PORTION}[c], inp.addr(0), recipient=inp.addr(32),
                      amount=inp.word(64))
        elif c == 0x10:
            steps += v4_steps(inp.b, hooks)
            need(len(steps) <= MAX_STEPS)
            continue
        else:
            raise Refused()
        steps.append(st)
    need(len(steps) <= MAX_STEPS)
    return steps, hooks, deadline


def is_router(a, router):
    return a == ADDRESS_THIS or a == router


SWAPS = (V3_IN, V3_OUT, V2_IN, V2_OUT, V4_IN, V4_OUT)
EXACT_IN = (V3_IN, V2_IN, V4_IN)


def summarize(steps, hooks, router, value):
    """The review: see ur_summarize() in uniswap_ur.h for the rules."""
    U = (1 << 256) - 1
    swaps = [s for s in steps if s['kind'] in SWAPS]
    need(swaps and all(s['kind'] in SWAPS + (PERMIT, WRAP, UNWRAP, SWEEP, PAY_PORTION, V4_TAKE_PORTION)
                       for s in steps))
    exact_in = swaps[0]['kind'] in EXACT_IN
    need(all((s['kind'] in EXACT_IN) == exact_in for s in swaps))
    permits = [k for k, s in enumerate(steps) if s['kind'] == PERMIT]
    need(permits in ([], [0]))
    eth = value != 0
    # V4 layouts were checked against UR 2.1.2 only (older routers encode
    # ExactInputParams without minHopPriceX36).
    need(router == int(ROUTERS[2], 16) or all(s['kind'] not in (V4_IN, V4_OUT) for s in swaps))
    for s in swaps:
        if s['kind'] not in (V4_IN, V4_OUT):
            need(s['token_in'] != 0 and s['token_out'] != 0)
    for s in steps:
        if s['kind'] == WRAP:
            need(is_router(s['recipient'], router) and (s['amount'] == CONTRACT_BALANCE or (eth and s['amount'] == value)))
    user = [s for s in swaps if s['payer']]
    out = {}
    if eth:
        need(not user and not permits)
        need(any(s['kind'] == WRAP for s in steps) or
             any(s['kind'] in (V4_IN, V4_OUT) and s['token_in'] == 0 and not s['payer'] for s in swaps))
        if not exact_in:
            need(sum(s['limit'] for s in swaps) <= value)
        out.update(in_is_eth=True, token_in=swaps[0]['token_in'], amount_in=value)
    else:
        need(user)
        a = user[0]['token_in']
        need(all(s['token_in'] == a and s['amount'] != CONTRACT_BALANCE for s in user))
        spent = sum(s['amount'] if exact_in else s['limit'] for s in user)
        need(spent <= U)
        out.update(in_is_eth=False, token_in=a, amount_in=spent)
    if permits:
        p = steps[0]
        need(p['token_out'] == router and p['token_in'] == out['token_in'])
        out.update(has_permit=True, permit_token=p['token_in'], permit_amount=p['amount'],
                   permit_expiration=p['expiration'])
    # The delivered asset ('ETH' or a token) and its one recipient.
    direct = [s for s in swaps if not is_router(s['recipient'], router)]
    assets = {('ETH' if s['kind'] in (V4_IN, V4_OUT) and s['token_out'] == 0 else s['token_out']) for s in direct}
    need(len(assets) <= 1)
    if assets:
        z = assets.pop()
    else:
        z = None
        for s in steps:
            if s['kind'] == SWEEP:
                z = 'ETH' if s['token_in'] == 0 else s['token_in']
                break
            if s['kind'] == UNWRAP and not is_router(s['recipient'], router):
                z = 'ETH'
                break
        need(z is not None)
    rcpts = set()
    swept = held = direct_sum = 0
    router_delivery = consumed = unswept = False   # unswept: left in the router after its last SWEEP
    fees = [s for s in steps if s['kind'] in (PAY_PORTION, V4_TAKE_PORTION)]
    need(len(fees) <= 1)
    for f in fees:
        need(1 <= f['amount'] <= 10000 and not is_router(f['recipient'], router))
    for k, s in enumerate(steps):
        if s['kind'] in (SWEEP, UNWRAP):
            if s['kind'] == UNWRAP and is_router(s['recipient'], router):
                consumed = consumed or z != 'ETH'
                continue
            need(not is_router(s['recipient'], router))
            rcpts.add(s['recipient'])
            asset = 'ETH' if s['kind'] == UNWRAP or s['token_in'] == 0 else s['token_in']
            if asset != z:
                need(asset == 'ETH')   # clean-up: leftover ETH back to the recipient
                continue
            need(s['amount'] != CONTRACT_BALANCE)
            swept += s['amount']
            router_delivery = True
            unswept = False
        elif s['kind'] in SWAPS:
            g = s['limit'] if exact_in else s['amount']
            if not is_router(s['recipient'], router):
                rcpts.add(s['recipient'])
                if k + 1 < len(steps) and steps[k + 1]['kind'] == V4_TAKE_PORTION:
                    need(exact_in)
                    g -= g * steps[k + 1]['amount'] // 10000
                direct_sum += g
            elif z != 'ETH' and s['token_out'] == z:
                held += g
                unswept = True
            if not s['payer'] and z != 'ETH' and s['token_in'] == z:
                consumed = True
    need(len(rcpts) == 1 and not unswept)
    r = rcpts.pop()
    fee = fees[0] if fees else None
    if fee and fee['kind'] == PAY_PORTION:
        ok = fee['token_in'] == z if z != 'ETH' else (
            fee['token_in'] == 0 or any(s['kind'] in SWAPS and is_router(s['recipient'], router) and
                                        s['token_out'] == fee['token_in'] for s in steps))
        need(ok and router_delivery)
    elif fee:
        k = steps.index(fee)
        need(k > 0 and steps[k - 1]['kind'] == V4_IN and not is_router(steps[k - 1]['recipient'], router))
    from_router = swept
    if (not fee or fee['kind'] != PAY_PORTION) and not consumed and z != 'ETH' and held > swept:
        from_router = held
    total = direct_sum + from_router
    need(total <= U and swept <= U and held <= U)
    out.update(exact_in=exact_in, out_is_eth=z == 'ETH',
               token_out=swaps[-1]['token_out'] if z == 'ETH' else z, amount_out=total,
               recipient=r, recipient_is_sender=r == MSG_SENDER, hooks=list(hooks))
    if fee:
        out.update(has_fee=True, fee_bips=fee['amount'], fee_recipient=fee['recipient'])
    return out


def v4_mutants(raw, rng, count):
    """Byte edits inside a call's V4_SWAP inputs (offsets, lengths, action
    bytes, amounts, currencies): [(offset, byte), ...] per mutant."""
    cd = bytes.fromhex(raw)
    b = cd[4:]
    cmds = dyn(b, 0, w(b, 0))
    io = w(b, 32)
    spans = []
    for k, c in enumerate(cmds):
        if c == 0x10:
            o = io + 32 + w(b, io + 32 + 32 * k)
            spans.append((4 + o, 4 + o + 32 + w(b, o)))
    out = []
    for _ in range(count):
        edits = []
        for _ in range(rng.randint(1, 3)):
            lo, hi = rng.choice(spans)
            if rng.random() < 0.75:
                at = lo + 32 * rng.randrange((hi - lo) // 32) + 31   # a word's low byte
                v = (cd[at] + rng.choice([-64, -32, -1, 1, 32, 64])) & 0xff
            else:
                at = rng.randrange(lo, hi)
                v = rng.randrange(256)
            edits.append((at, v))
        out.append(edits)
    return out


def expect_line(key, raw, router, value):
    """One line of uniswap_ur_expected.txt: the plan (or D 0) and the review (or S 0)."""
    h = lambda v, n: '%0*x' % (2 * n, v)
    try:
        steps, hooks, deadline = decode_plan(raw)
    except Refused:
        return '%s D 0' % key
    parts = [key, 'D', '1', str(len(steps))]
    for s in steps:
        parts += [str(s['kind']), h(s['token_in'], 20), h(s['token_out'], 20), h(s['recipient'], 20),
                  h(s['amount'], 32), h(s['limit'], 32), str(int(s['payer'])), str(s['expiration'])]
    parts += ['H', str(len(hooks))] + [h(x, 20) for x in hooks]
    try:
        o = summarize(steps, hooks, router, value)
    except Refused:
        return ' '.join(parts + ['S', '0'])
    parts += ['S', '1', str(int(o['exact_in'])), str(int(o['in_is_eth'])), str(int(o['out_is_eth'])),
              h(o['token_in'], 20), h(o['token_out'], 20), h(o['amount_in'], 32), h(o['amount_out'], 32),
              h(o['recipient'], 20), str(int(o['recipient_is_sender'])),
              str(int(o.get('has_permit', False))), h(o.get('permit_token', 0), 20),
              h(o.get('permit_amount', 0), 32), str(o.get('permit_expiration', 0)),
              str(int(o.get('has_fee', False))), str(o.get('fee_bips', 0)), h(o.get('fee_recipient', 0), 20)]
    return ' '.join(parts)


def expect(sample_bin):
    """Expected plans and reviews for every sample call (and every vector) as
    the Python model reads them: unittests/firmware/uniswap_ur_expected.txt."""
    b = open(sample_bin, 'rb').read()
    i = 0
    router = int(ROUTERS[2], 16)
    while i < len(b):
        n = int.from_bytes(b[i + 65:i + 69], 'big')
        value = int.from_bytes(b[i + 33:i + 65], 'big')
        print(expect_line('0x' + b[i:i + 32].hex(), b[i + 69:i + 69 + n].hex(), router, value))
        i += 69 + n
    # Mutated V4 calls: the C decoder may refuse more (it reads forward only),
    # never accept something this model reads differently.
    import random
    rng = random.Random(7730)
    i = k = 0
    while i < len(b):
        n = int.from_bytes(b[i + 65:i + 69], 'big')
        value = int.from_bytes(b[i + 33:i + 65], 'big')
        raw = b[i + 69:i + 69 + n].hex()
        key = '0x' + b[i:i + 32].hex()
        i += 69 + n
        if b'\x10' not in Body(bytes.fromhex(raw[8:])).bytes_at(0, 0):
            continue
        for edits in v4_mutants(raw, rng, 8):
            cd = bytearray(bytes.fromhex(raw))
            for at, v in edits:
                cd[at] = v
            line = expect_line('mut%d' % k, cd.hex(), router, value)
            print(line.replace('mut%d ' % k, 'mut%d %s %d %s ' % (
                k, key, len(edits), ' '.join('%d:%d' % e for e in edits)), 1))
            k += 1
    import re
    hdr = open(os.path.join(os.path.dirname(sample_bin), 'uniswap_ur_vectors.h')).read()
    for k, m in enumerate(re.finditer(r'\{"(0x[0-9a-f]{64})", "([0-9a-f]{40})", "([0-9a-f]{64})", "([0-9a-f]+)"', hdr)):
        print(expect_line('acc%d' % k, m.group(4), int(m.group(2), 16), int(m.group(3), 16)))
    v4 = hdr[hdr.index('v4_rejected()'):]
    for k, m in enumerate(re.finditer(r'"([0-9a-f]{100,})"', v4)):
        print(expect_line('v4r%d' % k, m.group(1), router, 0))


if __name__ == '__main__':
    {'fetch': fetch, 'header': header, 'pack': pack, 'expect': expect}[sys.argv[1]](sys.argv[2])
