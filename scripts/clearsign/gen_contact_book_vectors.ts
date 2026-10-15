import crypto from 'node:crypto'
// Usage: node gen_contact_book_vectors.ts <keepkey-vault>/src/bun/addressbook-clearsign.ts
// Prints the body of unittests/firmware/contact_book_vectors.h (Node >= 23).
import { pathToFileURL } from 'node:url'
const { buildCertificationRequest, buildContactProof, manifestBytes, CONTACT_DESTINATION } =
  await import(pathToFileURL(process.argv[2]).href)

const N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141')
const hx = (b: Buffer) => b.toString('hex')
function derive(mnemonic: string, path: number[]): Buffer {
  const seed = crypto.pbkdf2Sync(mnemonic.normalize('NFKD'), 'mnemonic', 2048, 64, 'sha512')
  let I = crypto.createHmac('sha512', 'Bitcoin seed').update(seed).digest()
  let k = I.subarray(0, 32), c = I.subarray(32)
  for (const idx of path) {
    const data = Buffer.concat([Buffer.from([0]), k, Buffer.from([(idx >>> 24) & 255, (idx >>> 16) & 255, (idx >>> 8) & 255, idx & 255])])
    I = crypto.createHmac('sha512', c).update(data).digest()
    const kk = (BigInt('0x' + hx(I.subarray(0, 32))) + BigInt('0x' + hx(k))) % N
    k = Buffer.from(kk.toString(16).padStart(64, '0'), 'hex'); c = I.subarray(32)
  }
  return k
}
function keyObjects(priv: Buffer) {
  const ecdh = crypto.createECDH('secp256k1'); ecdh.setPrivateKey(priv)
  const pub = ecdh.getPublicKey()
  const b64 = (b: Buffer) => b.toString('base64url')
  const jwk = { kty: 'EC', crv: 'secp256k1', x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)), d: b64(priv) }
  return { priv: crypto.createPrivateKey({ key: jwk, format: 'jwk' }), compressed: ecdh.getPublicKey(null, 'compressed') as Buffer }
}
function sign(priv: crypto.KeyObject, msg: Buffer): Buffer {
  const sig = crypto.sign('sha256', msg, { key: priv, dsaEncoding: 'ieee-p1363' })
  let s = BigInt('0x' + hx(sig.subarray(32)))
  if (s > N / 2n) s = N - s
  return Buffer.concat([sig.subarray(0, 32), Buffer.from(s.toString(16).padStart(64, '0'), 'hex')])
}
const H = 0x80000000
const attPriv = derive('all all all all all all all all all all all all', [H | 0x4b4b, H | 0x4353, H | 0])
const att = keyObjects(attPriv)
const other = keyObjects(derive('all all all all all all all all all all all all', [H | 0x4b4b, H | 0x4353, H | 1]))

const addr = (n: number) => '0x' + n.toString(16).padStart(2, '0').repeat(20)
function cert(contacts: any[], revision: number, key = att) {
  const req = buildCertificationRequest(contacts, revision)
  const c: any = { version: 1, revision, contacts: contacts.map(x => ({ ...x, destination: x.destination.toLowerCase().replace(/^0x/, '') })), root: hx(req.root) }
  c.signature = hx(sign(key.priv, manifestBytes(c))); c.publicKey = hx(key.compressed); c.certifiedAt = 0
  return { req, c }
}
const out: string[] = []
const emit = (name: string, b: Buffer | string) => out.push(`static const char ${name}[] =\n    "${typeof b === 'string' ? b : hx(b)}";`)
emit('ATTESTOR_PUBKEY_ALL', att.compressed)
emit('OTHER_PUBKEY', other.compressed)
const E = CONTACT_DESTINATION.EVM_ADDRESS
const A = [
  { network: 'eip155:1', destinationType: E, destination: '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045', label: 'Alice' },
  { network: 'eip155:8453', destinationType: E, destination: addr(0x22), label: 'Bob Base' },
  { network: 'eip155:1', destinationType: E, destination: addr(0x33), label: 'Carol' },
]
const a = cert(A, 7)
emit('REQ3', a.req.payload); emit('ROOT3', a.req.root); emit('SIG3', a.c.signature)
for (let i = 0; i < A.length; i++) emit(`PROOF3_${i}`, buildContactProof(a.c, A[i].network, E, A[i].destination)!)
const B = Array.from({ length: 16 }, (_, i) => ({ network: i % 2 ? 'eip155:8453' : 'eip155:1', destinationType: E, destination: addr(0x40 + i), label: `Contact ${i + 1}` }))
const b = cert(B, 2)
emit('REQ16', b.req.payload)
emit('PROOF16_0', buildContactProof(b.c, B[0].network, E, B[0].destination)!)
emit('PROOF16_15', buildContactProof(b.c, B[15].network, E, B[15].destination)!)
const C = B.slice(0, 5)
const cc = cert(C, 3)
emit('PROOF5_4', buildContactProof(cc.c, C[4].network, E, C[4].destination)!)
const d = cert(A.slice(0, 1), 1)
emit('PROOF1_0', buildContactProof(d.c, A[0].network, E, A[0].destination)!)
const w = cert(A, 7, other) // a certification made by another wallet's attestor key
emit('PROOF3_0_OTHER_KEY', buildContactProof(w.c, A[0].network, E, A[0].destination)!)
// 17 entries: the vault refuses; hand-extend REQ16 with a 17th entry.
let r17 = Buffer.from(b.req.payload); r17[13] = 17
const extra = buildCertificationRequest([{ network: 'eip155:1', destinationType: E, destination: addr(0x7f), label: 'Extra' }], 1).payload.subarray(14)
emit('REQ17', Buffer.concat([r17, extra]))
console.log(out.join('\n'))
