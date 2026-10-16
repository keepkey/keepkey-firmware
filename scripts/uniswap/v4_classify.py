# One-off measurement for D-019 / D-021: classify real Base Universal Router calls.
#   v4_classify.py DIR                                   # Blockscout pages (gen_ur_vectors.py fetch)
#   v4_classify.py unittests/firmware/uniswap_ur_sample.bin   # the same calls, packed (gen_ur_vectors.py pack)
import json, glob, sys, collections
CMD = {0:'V3_IN',1:'V3_OUT',2:'P2_XFER',3:'P2_PERMIT_BATCH',4:'SWEEP',5:'TRANSFER',6:'PAY_PORTION',8:'V2_IN',9:'V2_OUT',
       0x0a:'P2_PERMIT',0x0b:'WRAP',0x0c:'UNWRAP',0x0d:'P2_XFER_BATCH',0x0e:'BAL_CHECK',0x10:'V4_SWAP',0x11:'V3_POS_PERMIT',
       0x12:'V3_POS_CALL',0x13:'V4_INIT_POOL',0x14:'V4_POS_CALL',0x21:'EXECUTE_SUB'}
ACT = {0x06:'IN_SINGLE',0x07:'IN',0x08:'OUT_SINGLE',0x09:'OUT',0x0b:'SETTLE',0x0c:'SETTLE_ALL',0x0d:'SETTLE_PAIR',
       0x0e:'TAKE',0x0f:'TAKE_ALL',0x10:'TAKE_PORTION',0x11:'TAKE_PAIR',0x12:'CLOSE_CURRENCY',0x13:'CLEAR_OR_TAKE',
       0x14:'SWEEP',0x15:'WRAP',0x16:'UNWRAP',0x19:'UNWIND'}
SUPPORTED = {0,1,4,5,6,8,9,0x0a,0x0b,0x0c}          # uniswap_ur.c decode_step() today
w = lambda b,o: int.from_bytes(b[o:o+32],'big')
def dyn_bytes(b, base, off):                         # bytes at relative offset
    p = base + off; n = w(b,p); return b[p+32:p+32+n]
def dyn_array_bytes(b, base, off):                   # bytes[] at relative offset
    p = base + off; n = w(b,p); out=[]
    for i in range(n): out.append(dyn_bytes(b, p+32, w(b, p+32+32*i)))
    return out
def ur(raw):
    b = bytes.fromhex(raw[10:]); cmds = dyn_bytes(b,0,w(b,0)); inputs = dyn_array_bytes(b,0,w(b,32)); return cmds, inputs
def v4(inp):
    acts = dyn_bytes(inp,0,w(inp,0)); params = dyn_array_bytes(inp,0,w(inp,32)); hooks=[]
    for a,p in zip(acts,params):
        try:
            t = w(p,0)                                  # struct is dynamic -> head offset
            if a in (0x06,0x08): hooks.append(p[t+4*32+12:t+5*32])          # PoolKey.hooks
            elif a in (0x07,0x09):
                path = t + w(p,t+32); n = w(p,path)
                for i in range(n):
                    e = path+32 + w(p, path+32+32*i); hooks.append(p[e+3*32+12:e+4*32])  # PathKey.hooks
        except Exception: hooks.append(b'?')
    return [ACT.get(a,hex(a)) for a in acts], hooks
stats = collections.Counter(); shapes = collections.Counter(); urshapes = collections.Counter(); lens = []; nonzero_hooks = 0
def calls(src):
    if src.endswith('.bin'):                         # hash(32) status(1) value(32) len(4) calldata
        b = open(src,'rb').read(); i = 0
        while i < len(b):
            n = int.from_bytes(b[i+65:i+69],'big')
            yield {'hash':'0x'+b[i:i+32].hex(), 'status':'ok' if b[i+32] else 'error', 'raw_input':'0x'+b[i+69:i+69+n].hex()}
            i += 69 + n
    else:
        for f in sorted(glob.glob(src+'/*.json')): yield from json.load(open(f)).get('items',[])
if True:
    for it in calls(sys.argv[1]):
        raw = it.get('raw_input') or ''
        if not raw.startswith(('0x3593564c','0x24856bc3')): stats['not execute()'] += 1; continue
        try: cmds, inputs = ur(raw)
        except Exception: stats['unparseable'] += 1; continue
        n = (len(raw)-2)//2; c = [x & 0x3f for x in cmds]; stats['execute total'] += 1
        if it.get('status') != 'ok': stats['  (reverted/failed)'] += 1
        if set(c) <= SUPPORTED: stats['decodable today (V2/V3 subset)'] += 1; continue
        if 0x10 in c:
            stats['contains V4_SWAP'] += 1; lens.append(n)
            stats['  V4 fits 1472 B buffer' if n <= 1472 else '  V4 over 1472 B'] += 1
            urshapes['+'.join(CMD.get(x,hex(x)) for x in c)] += 1
            for x,inp in zip(c,inputs):
                if x == 0x10:
                    acts, hooks = v4(inp); shapes[' > '.join(acts)] += 1
                    if any(h not in (b'\0'*20,) for h in hooks): nonzero_hooks += 1
        else:
            stats['other unsupported'] += 1; urshapes['OTHER: '+'+'.join(CMD.get(x,hex(x)) for x in c)] += 1
for k,v in stats.items(): print(f'{v:5}  {k}')
print(f'{nonzero_hooks:5}  V4 swaps touching a non-zero hooks address')
if lens: lens.sort(); print('V4 calldata bytes: min %d median %d p90 %d max %d' % (lens[0], lens[len(lens)//2], lens[int(len(lens)*.9)], lens[-1]))
print('\nUR command shapes (V4 / other unsupported):'); [print(f'{v:5}  {k}') for k,v in urshapes.most_common(12)]
print('\nV4 action sequences:'); [print(f'{v:5}  {k}') for k,v in shapes.most_common(15)]
