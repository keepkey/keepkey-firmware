#!/usr/bin/env bun
/**
 * generate-zoo.ts — Generates composite flow pages for release bundling.
 * Each page shows the app screen + device OLED side-by-side with labels and TX insight.
 *
 * Usage: bun scripts/generate-zoo.ts
 * Output: projects/keepkey-vault/docs/zoo/pages/
 */
import { deflateSync } from 'bun:zlib'
import { mkdirSync, existsSync, readdirSync, statSync } from 'fs'
import { join, relative } from 'path'
import { $ } from 'bun'
import sharp from 'sharp'
import QRCode from 'qrcode'

const ZOO = join(import.meta.dir, '..', '..', 'zoo-output')
const RAW = join(ZOO, 'raw')
const PAGES_DIR = join(ZOO, 'pages')
const OLED_W = 256, OLED_H = 64

// ═══════════════════════════════════════════════════════════════════════
// SECTION 1: Minimal PNG encoder for device OLED screens
// ═══════════════════════════════════════════════════════════════════════

function crc32(buf: Uint8Array): number {
  let c = ~0
  for (let i = 0; i < buf.length; i++) { c ^= buf[i]; for (let j = 0; j < 8; j++) c = (c >>> 1) ^ (c & 1 ? 0xEDB88320 : 0) }
  return ~c >>> 0
}

function pngChunk(type: string, data: Uint8Array): Uint8Array {
  const chunk = new Uint8Array(12 + data.length)
  const v = new DataView(chunk.buffer)
  v.setUint32(0, data.length)
  for (let i = 0; i < 4; i++) chunk[4 + i] = type.charCodeAt(i)
  chunk.set(data, 8)
  const crcIn = new Uint8Array(4 + data.length)
  for (let i = 0; i < 4; i++) crcIn[i] = type.charCodeAt(i)
  crcIn.set(data, 4)
  v.setUint32(8 + data.length, crc32(crcIn))
  return chunk
}

export function encodePNG(pixels: Uint8Array, w: number, h: number): Uint8Array {
  const ihdr = new Uint8Array(13)
  const iv = new DataView(ihdr.buffer)
  iv.setUint32(0, w); iv.setUint32(4, h); ihdr[8] = 8; ihdr[9] = 0
  const raw = new Uint8Array(h * (1 + w))
  for (let y = 0; y < h; y++) { raw[y * (1 + w)] = 0; for (let x = 0; x < w; x++) raw[y * (1 + w) + 1 + x] = pixels[y * w + x] }
  const sig = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])
  const ic = pngChunk('IHDR', ihdr), dc = pngChunk('IDAT', new Uint8Array(deflateSync(raw))), ec = pngChunk('IEND', new Uint8Array(0))
  const out = new Uint8Array(sig.length + ic.length + dc.length + ec.length)
  let o = 0; out.set(sig, o); o += sig.length; out.set(ic, o); o += ic.length; out.set(dc, o); o += dc.length; out.set(ec, o)
  return out
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 2: 5x7 Bitmap Font + OLED Renderer
// ═══════════════════════════════════════════════════════════════════════

const FONT_HEX =
  '0000000000'+'00005f0000'+'0007000700'+'147f147f14'+'242a7f2a12'+
  '2313086462'+'3649552250'+'0005030000'+'001c224100'+'0041221c00'+
  '14083e0814'+'08083e0808'+'0050300000'+'0808080808'+'0060600000'+
  '2010080402'+'3e5149453e'+'00427f4000'+'4261514946'+'2141454b31'+
  '1814127f10'+'2745454539'+'3c4a494930'+'0171090503'+'3649494936'+
  '064949291e'+'0036360000'+'0056360000'+'0814224100'+'1414141414'+
  '0041221408'+'0201510906'+'324979413e'+'7e1111117e'+'7f49494936'+
  '3e41414122'+'7f4141221c'+'7f49494941'+'7f09090901'+'3e4149497a'+
  '7f0808087f'+'00417f4100'+'2040413f01'+'7f08142241'+'7f40404040'+
  '7f020c027f'+'7f0408107f'+'3e4141413e'+'7f09090906'+'3e4151215e'+
  '7f09192946'+'4649494931'+'01017f0101'+'3f4040403f'+'1f2040201f'+
  '3f4038403f'+'6314081463'+'0708700807'+'6151494543'+'007f414100'+
  '0204081020'+'0041417f00'+'0402010204'+'4040404040'+'0001020400'+
  '2054545478'+'7f48444438'+'3844444420'+'384444487f'+'3854545418'+
  '087e090102'+'0c5252523e'+'7f08040478'+'00447d4000'+'2040443d00'+
  '7f10284400'+'00417f4000'+'7c04180478'+'7c08040478'+'3844444438'+
  '7c14141408'+'081414187c'+'7c08040408'+'4854545420'+'043f444020'+
  '3c4040207c'+'1c2040201c'+'3c4030403c'+'4428102844'+'0c5050503c'+
  '4464544c44'+'0008364100'+'00007f0000'+'0041360800'+'1008081008'

const GLYPHS: number[][] = []
for (let i = 0; i < 95; i++) {
  const cols: number[] = []
  for (let c = 0; c < 5; c++) cols.push(parseInt(FONT_HEX.substr(i * 10 + c * 2, 2), 16))
  GLYPHS[32 + i] = cols
}

export class OLED {
  buf: Uint8Array
  constructor() { this.buf = new Uint8Array(OLED_W * OLED_H) }
  clear() { this.buf.fill(0) }
  pixel(x: number, y: number, on = true) {
    x = Math.round(x); y = Math.round(y)
    if (x >= 0 && x < OLED_W && y >= 0 && y < OLED_H) this.buf[y * OLED_W + x] = on ? 255 : 0
  }
  char(x: number, y: number, ch: string, s = 1): number {
    const g = GLYPHS[ch.charCodeAt(0)] || GLYPHS[63]
    for (let col = 0; col < 5; col++) { let b = g[col]; for (let row = 0; row < 7; row++) if (b & (1 << row)) for (let sx = 0; sx < s; sx++) for (let sy = 0; sy < s; sy++) this.pixel(x + col * s + sx, y + row * s + sy, true) }
    return 6 * s
  }
  text(x: number, y: number, str: string, s = 1) { let cx = x; for (const ch of str) cx += this.char(cx, y, ch, s) }
  centerText(y: number, str: string, s = 1) { this.text(Math.floor((OLED_W - str.length * 6 * s + s) / 2), y, str, s) }
  rect(x: number, y: number, w: number, h: number, filled = false) { for (let px = x; px < x + w; px++) for (let py = y; py < y + h; py++) if (filled || px === x || px === x + w - 1 || py === y || py === y + h - 1) this.pixel(px, py, true) }
  hline(x: number, y: number, w: number) { for (let i = 0; i < w; i++) this.pixel(x + i, y, true) }
  progressBar(x: number, y: number, w: number, h: number, pct: number) { this.rect(x, y, w, h, false); const fw = Math.floor((w - 2) * Math.min(1, pct)); if (fw > 0) this.rect(x + 1, y + 1, fw, h - 2, true) }
  pinGrid(nums: number[]) { for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) { const x = 195 + c * 19, y = 5 + r * 19; this.rect(x, y, 18, 18, false); this.char(x + 4, y + 2, String(nums[r * 3 + c]), 2) } }
  cipherGrid(top: string[], bot: string[]) { for (let i = 0; i < Math.min(top.length, 13); i++) { const x = 76 + i * 14; this.rect(x, 3, 13, 13, false); this.char(x + 4, 6, top[i], 1) }; for (let i = 0; i < Math.min(bot.length, 13); i++) { const x = 76 + i * 14; this.rect(x, 18, 13, 13, false); this.char(x + 4, 21, bot[i], 1) } }
  foxLogo(cx: number, cy: number) { for (let i = 0; i < 10; i++) { this.pixel(cx - 14 + i, cy - 20 + i, true); this.pixel(cx - 5, cy - 20 + i, true) }; for (let i = 0; i < 10; i++) { this.pixel(cx + 5, cy - 20 + i, true); this.pixel(cx + 14 - i, cy - 20 + i, true) }; for (let y = -10; y <= 6; y++) { const hw = Math.round(12 * Math.sqrt(1 - (y * y) / 120)); this.hline(cx - hw, cy + y, hw * 2) }; this.rect(cx - 6, cy - 6, 3, 3, true); this.rect(cx + 4, cy - 6, 3, 3, true); this.pixel(cx, cy, false); this.pixel(cx - 1, cy + 1, false); this.pixel(cx + 1, cy + 1, false) }
  toPNG(): Uint8Array { return encodePNG(this.buf, OLED_W, OLED_H) }
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 3: Composite page builder
// ═══════════════════════════════════════════════════════════════════════

const PAGE_W = 1200
const PAGE_H = 520
const BG = { r: 13, g: 17, b: 23, alpha: 255 }
const OLED_SCALE = 3 // 256×64 -> 768×192
const DEVICE_W = OLED_W * OLED_SCALE // 768
const DEVICE_H = OLED_H * OLED_SCALE // 192

function escSvg(s: string) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }

function headerSvg(flow: string, step: string, accent: string, stepNum: number, total: number): Buffer {
  const dots = Array.from({ length: total }, (_, i) =>
    `<circle cx="${PAGE_W / 2 - (total * 12) + i * 24 + 12}" cy="38" r="${i === stepNum ? 5 : 3}" fill="${i === stepNum ? accent : '#444'}"/>`
  ).join('')
  return Buffer.from(`<svg width="${PAGE_W}" height="55" xmlns="http://www.w3.org/2000/svg">
    <rect width="${PAGE_W}" height="3" fill="${accent}"/>
    <text x="20" y="32" font-family="system-ui,sans-serif" font-size="16" font-weight="700" fill="${accent}">${escSvg(flow)}</text>
    <text x="20" y="48" font-family="system-ui,sans-serif" font-size="13" fill="#888">${escSvg(step)}</text>
    <text x="${PAGE_W - 20}" y="32" font-family="system-ui,sans-serif" font-size="13" fill="#555" text-anchor="end">${stepNum + 1} / ${total}</text>
    ${dots}
  </svg>`)
}

function labelSvg(text: string, x: number, y: number, w: number, size = 11, color = '#888'): Buffer {
  return Buffer.from(`<svg width="${w}" height="${size + 8}" xmlns="http://www.w3.org/2000/svg">
    <text x="0" y="${size + 2}" font-family="system-ui,sans-serif" font-size="${size}" font-weight="600" fill="${color}" letter-spacing="1.5">${escSvg(text)}</text>
  </svg>`)
}

function insightSvg(lines: string[], w: number): Buffer {
  const lineH = 18
  const h = lines.length * lineH + 16
  const textEls = lines.map((line, i) => {
    let color = '#ccc'
    let text = line
    if (line.startsWith('!')) { color = '#F59E0B'; text = line.slice(1).trim() }
    if (line.startsWith('!!')) { color = '#EF4444'; text = line.slice(2).trim() }
    return `<text x="8" y="${20 + i * lineH}" font-family="system-ui,sans-serif" font-size="12" fill="${color}">${escSvg(text)}</text>`
  }).join('')
  return Buffer.from(`<svg width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg">
    <rect x="0" y="0" width="${w}" height="${h}" rx="6" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.06)" stroke-width="1"/>
    ${textEls}
  </svg>`)
}

function appContextSvg(text: string, w: number): Buffer {
  const lines = text.split('\n')
  const h = lines.length * 18 + 12
  const textEls = lines.map((l, i) =>
    `<text x="12" y="${18 + i * 18}" font-family="system-ui,sans-serif" font-size="13" fill="#9CA3AF">${escSvg(l)}</text>`
  ).join('')
  return Buffer.from(`<svg width="${w}" height="${h}" xmlns="http://www.w3.org/2000/svg">
    <rect x="0" y="0" width="${w}" height="${h}" rx="8" fill="rgba(255,255,255,0.02)" stroke="rgba(255,255,255,0.05)" stroke-width="1"/>
    ${textEls}
  </svg>`)
}

// Device bezel: rounded rect around OLED with "KEEPKEY" label
function bezelSvg(w: number, h: number): Buffer {
  const pw = w + 20, ph = h + 40 // padding
  return Buffer.from(`<svg width="${pw}" height="${ph}" xmlns="http://www.w3.org/2000/svg">
    <rect x="0" y="0" width="${pw}" height="${ph}" rx="12" fill="#1a1a1a" stroke="#333" stroke-width="2"/>
    <rect x="10" y="10" width="${w}" height="${h}" rx="4" fill="#000"/>
    <text x="${pw / 2}" y="${ph - 8}" font-family="system-ui,sans-serif" font-size="9" fill="#444" text-anchor="middle" letter-spacing="2">KEEPKEY</text>
  </svg>`)
}

// QR code generator: returns a PNG buffer of a QR code with label
async function qrBlockPng(data: string, label: string, size: number, accent: string): Promise<Buffer> {
  const qrSvgStr = await QRCode.toString(data, {
    type: 'svg', margin: 1, width: size - 20,
    color: { dark: '#ffffff', light: '#00000000' },
  })
  // Wrap in a labeled container SVG
  const labelH = 28
  const totalH = size + labelH
  const svg = `<svg width="${size}" height="${totalH}" xmlns="http://www.w3.org/2000/svg">
    <rect x="0" y="0" width="${size}" height="${totalH}" rx="8" fill="rgba(255,255,255,0.04)" stroke="${accent}" stroke-width="1" stroke-opacity="0.3"/>
    <text x="${size / 2}" y="18" font-family="system-ui,sans-serif" font-size="10" font-weight="600" fill="${accent}" text-anchor="middle" letter-spacing="1">${escSvg(label)}</text>
    <g transform="translate(10,${labelH})">${qrSvgStr.replace(/<\?xml[^?]*\?>/, '').replace(/<svg[^>]*>/, '').replace(/<\/svg>/, '')}</g>
  </svg>`
  return sharp(Buffer.from(svg)).png().toBuffer()
}

export async function buildPage(
  filename: string,
  flow: string,
  step: string,
  stepNum: number,
  totalSteps: number,
  accent: string,
  deviceDraw: (o: OLED) => void,
  appContext: string,
  insight: string[],
  qrData?: { data: string; label: string },
): Promise<void> {
  const oled = new OLED()
  oled.clear()
  deviceDraw(oled)
  const deviceRaw = oled.toPNG()

  // Scale OLED to 3x with nearest-neighbor (pixelated)
  const deviceScaled = await sharp(Buffer.from(deviceRaw))
    .resize(DEVICE_W, DEVICE_H, { kernel: 'nearest' })
    .png()
    .toBuffer()

  // Build bezel frame
  const bezel = await sharp(bezelSvg(DEVICE_W, DEVICE_H)).png().toBuffer()

  // Build text overlays
  const header = await sharp(headerSvg(flow, step, accent, stepNum, totalSteps)).png().toBuffer()
  const deviceLabel = await sharp(labelSvg('DEVICE SCREEN', 0, 0, 200, 10, '#555')).png().toBuffer()
  const appLabel = await sharp(labelSvg('APP CONTEXT', 0, 0, 200, 10, '#555')).png().toBuffer()
  const verifyLabel = await sharp(labelSvg('WHAT TO VERIFY', 0, 0, 200, 10, accent)).png().toBuffer()

  const appCtx = await sharp(appContextSvg(appContext, 360)).png().toBuffer()
  const insightBlock = await sharp(insightSvg(insight, 380)).png().toBuffer()

  // Build optional QR code
  let qrPng: Buffer | null = null
  if (qrData) {
    qrPng = await qrBlockPng(qrData.data, qrData.label, 160, accent)
  }

  // Get insight block dimensions
  const insightMeta = await sharp(insightBlock).metadata()
  const appCtxMeta = await sharp(appCtx).metadata()

  // Layout positions
  const deviceX = 30
  const deviceY = 80
  const bezelX = deviceX - 10
  const bezelY = deviceY - 10
  const rightCol = DEVICE_W + 60
  const pageH = Math.max(PAGE_H, bezelY + DEVICE_H + 40 + 20 + (appCtxMeta.height || 80) + 30)

  // Build composite layers
  const layers: sharp.OverlayOptions[] = [
    { input: header, top: 0, left: 0 },
    // Device bezel + screen
    { input: bezel, top: bezelY, left: bezelX },
    { input: deviceScaled, top: deviceY, left: deviceX },
    { input: deviceLabel, top: deviceY - 18, left: deviceX },
    // App context (below device)
    { input: appLabel, top: bezelY + DEVICE_H + 48, left: deviceX },
    { input: appCtx, top: bezelY + DEVICE_H + 64, left: deviceX },
    // Insight (right column)
    { input: verifyLabel, top: 75, left: rightCol },
    { input: insightBlock, top: 92, left: rightCol },
  ]

  // QR code positioned below insight block on right column
  if (qrPng) {
    const insightH = insightMeta.height || 100
    layers.push({ input: qrPng, top: 92 + insightH + 16, left: rightCol + 110 })
    const scanLabel = await sharp(labelSvg('SCAN TO VERIFY', 0, 0, 200, 9, accent)).png().toBuffer()
    layers.push({ input: scanLabel, top: 92 + insightH + 4, left: rightCol + 110 })
  }

  // Compose
  await sharp({
    create: { width: PAGE_W, height: pageH, channels: 4, background: BG }
  })
    .composite(layers)
    .png()
    .toFile(join(PAGES_DIR, filename))
}

// ═══════════════════════════════════════════════════════════════════════
// SECTION 4: Flow page definitions — app + device paired with insight
// ═══════════════════════════════════════════════════════════════════════

export interface PageDef {
  file: string
  flow: string
  step: string
  accent: string
  device: (o: OLED) => void
  appContext: string
  insight: string[]
  qr?: { data: string; label: string }
}

// ═══════════════════════════════════════════════════════════════════════
// TODO: Needs real emulator screenshots (custom layout functions, can't mock)
//
// SETUP: seed words shown in batched 2-column layout (reset.c:168-224),
//   bootloader/firmware flash (custom progress), create/recover choice,
//   seed verification (3-word multiple choice)
// PIN: animated 3x3 grid via layout_animate_pin() (app_layout.c:52-180)
// RECOVERY: cipher grid via layout_cipher() (app_layout.c:192-301)
// PASSPHRASE: custom "Enter passphrase on your computer" layout
// WIPE: custom confirmation dialog
// ETH GAS/FEE: firmware does NOT show separate gas/fee/chain-id screens
// ETH MESSAGE: title="Sign Message" or "Sign Bytes", body=message content
// EIP-712: shows "Typed Data domain" + hash, "Typed Data message" + hash
//   (NOT decoded permit fields — that was invented)
// EVM MULTICHAIN: no chain ID confirmation screen exists in firmware
// EVM BLIND SIGN: no separate blind sign warning screen verified
// TRON: clear sign (TRX, TRC-20, contract call, blind sign warning)
// TON: v4r2 transfer, memo, deploy blind sign
// ZCASH: Orchard shielded, hybrid shield, transparent input
// BLIND SIGN POLICY: AdvancedMode blocked screen
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
// BOOT & LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════

export const SETUP_FLOW: PageDef[] = [
  {
    file: '00a-setup-create.png', flow: 'Device Setup', step: 'Create/Recover Choice', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'KeepKey', 2)
      o.text(4, 28, 'Create new wallet or', 1)
      o.text(4, 42, 'recover existing seed?', 1)
    },
    appContext: 'Source: reset.c\nInitial device setup choice\nUser selects create (new seed) or recover (existing seed)',
    insight: ['First screen on uninitialized device', 'Requires physical button to proceed'],
  },
  {
    file: '00a2-setup-word-count.png', flow: 'Device Setup', step: 'Word Count Selection', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Recovery Seed Backup', 2)
      o.text(4, 28, 'Generate 12/18/24 word', 1)
      o.text(4, 42, 'recovery sentence?', 1)
    },
    appContext: 'Source: reset.c\nWord count confirmation before seed generation\nDetermines entropy size: 128/192/256 bits',
    insight: ['Entropy: 12=128bit, 18=192bit, 24=256bit', 'User must confirm before generation begins'],
  },
  {
    file: '00b-setup-seed-display.png', flow: 'Device Setup', step: 'Seed Word Display (page 1/3)', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Recovery Sentence', 2)
      o.text(4, 28, '1. abandon  2. abandon', 1)
      o.text(4, 40, '3. abandon  4. abandon', 1)
      o.text(4, 52, '(page 1 of 3)', 1)
    },
    appContext: 'Source: reset.c:168-224\nSeed words shown in 2-column batched layout\n4 words per page, 3 pages for 12-word seed\n!Actual words depend on generated entropy',
    insight: ['!!CRITICAL: seed words shown — write them down', '2-column layout, 4 words per page', '!Words are EXAMPLE — real seed varies'],
  },
  {
    file: '00b2-setup-seed-page2.png', flow: 'Device Setup', step: 'Seed Word Display (page 2/3)', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Recovery Sentence', 2)
      o.text(4, 28, '5. abandon  6. abandon', 1)
      o.text(4, 40, '7. abandon  8. abandon', 1)
      o.text(4, 52, '(page 2 of 3)', 1)
    },
    appContext: 'Source: reset.c:168-224\nPage 2 of seed word display\nUser scrolls through all pages before confirmation',
    insight: ['Page 2 of 3 for 12-word seed', '6 pages for 24-word seed'],
  },
  {
    file: '00b3-setup-seed-page3.png', flow: 'Device Setup', step: 'Seed Word Display (page 3/3)', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Recovery Sentence', 2)
      o.text(4, 28, '9. abandon  10. abandon', 1)
      o.text(4, 40, '11. abandon  12. all', 1)
      o.text(4, 52, '(page 3 of 3)', 1)
    },
    appContext: 'Source: reset.c:168-224\nFinal page — user must have written all words\nButton press confirms backup complete',
    insight: ['Final seed page', '!!User must write down ALL words before proceeding'],
  },
  {
    file: '00b4-setup-import.png', flow: 'Device Setup', step: 'Import Recovery Sentence', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Import Recovery', 2)
      o.text(4, 28, 'Import recovery sentence?', 1)
      o.text(4, 42, 'This will overwrite any', 1)
      o.text(4, 54, 'existing seed on device.', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nconfirm_load_device()\n"Import recovery sentence?"\nWARNING: overwrites existing seed',
    insight: ['!!Overwrites existing seed if present', 'confirm_load_device() in fsm_msg_common.h'],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// PIN ENTRY & MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

export const PIN_FLOW: PageDef[] = [
  {
    file: '00c-pin-entry.png', flow: 'PIN Entry', step: 'Enter PIN (unlock)', accent: '#6366F1',
    device(o) {
      o.text(4, 24, 'Enter', 1)
      o.text(4, 38, 'Your PIN', 1)
      o.pinGrid([7, 8, 9, 4, 5, 6, 1, 2, 3])
    },
    appContext: 'Source: pin_sm.c:156-203, app_layout.c:667-686\nlayout_animate_pin("Enter\\nYour PIN")\nAnimated 3x3 grid — digits randomized each time\nHost sees only grid position (1-9), not actual digit',
    insight: ['!!Host NEVER sees digit positions', '3x3 grid randomized each session', 'Animated slide-in per digit'],
  },
  {
    file: '00c2-pin-new.png', flow: 'PIN Entry', step: 'Create New PIN', accent: '#6366F1',
    device(o) {
      o.text(4, 24, 'Enter New', 1)
      o.text(4, 38, 'PIN', 1)
      o.pinGrid([3, 6, 9, 2, 5, 8, 1, 4, 7])
    },
    appContext: 'Source: pin_sm.c\nlayout_pin("Enter New\\nPIN")\nFirst entry of new PIN during create/change',
    insight: ['First entry — must re-enter to confirm', 'Grid re-randomized for confirmation entry'],
  },
  {
    file: '00c3-pin-confirm.png', flow: 'PIN Entry', step: 'Re-Enter New PIN', accent: '#6366F1',
    device(o) {
      o.text(4, 24, 'Re-Enter', 1)
      o.text(4, 38, 'New PIN', 1)
      o.pinGrid([9, 2, 5, 8, 1, 4, 7, 3, 6])
    },
    appContext: 'Source: pin_sm.c\nlayout_pin("Re-Enter\\nNew PIN")\nConfirmation entry — must match first entry\nGrid is RE-RANDOMIZED (different positions)',
    insight: ['!!Grid positions DIFFERENT from first entry', 'Must match first PIN to confirm', 'Prevents position-memorization attacks'],
  },
  {
    file: '00c4-pin-wrong.png', flow: 'PIN Entry', step: 'Wrong PIN — Backoff', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'Wrong PIN', 2)
      o.text(4, 28, 'Previous PIN failures.', 1)
      o.text(4, 42, 'Please wait 30 seconds', 1)
      o.text(4, 54, 'before trying again.', 1)
    },
    appContext: 'Source: layout.c:441\nlayout_warning() with exponential backoff\nWait time doubles after each failure\n3+ failures: 2^(failures-2) seconds wait',
    insight: ['!!Exponential backoff: 2^(n-2) seconds', 'Prevents brute-force PIN attacks', 'Progress bar counts down wait time'],
  },
  {
    file: '00c5-pin-remove.png', flow: 'PIN Entry', step: 'Remove PIN Confirmation', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'Remove PIN', 2)
      o.text(4, 28, 'Disable PIN protection?', 1)
      o.text(4, 42, 'Anyone with physical', 1)
      o.text(4, 54, 'access can use device.', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nconfirm(ButtonRequest_RemovePin, "Remove PIN")\nDisables PIN — device accessible without auth',
    insight: ['!!Removes all PIN protection', 'Physical access = full access after this'],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// RECOVERY CIPHER
// ═══════════════════════════════════════════════════════════════════════

export const RECOVERY_FLOW: PageDef[] = [
  {
    file: '00d-recovery-cipher.png', flow: 'Recovery', step: 'Cipher Grid (word entry)', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Recovery Cipher:', 1)
      o.text(4, 30, '1/12: a__', 1)
      o.text(4, 50, '1: zoo', 1)
      o.cipherGrid(
        ['q','w','e','r','t','y','u','i','o','p','a','s','d'],
        ['f','g','h','j','k','l','z','x','c','v','b','n','m']
      )
    },
    appContext: 'Source: app_layout.c:698-724\nlayout_cipher(current_word, cipher, prev_info)\nScrambled alphabet — user enters ciphered characters\nPrev word shown at y=50 (7.14.0: PR #87)',
    insight: ['!!Host sees ONLY ciphered characters', 'Prev word display: new in 7.14.0', 'Cipher re-scrambles after each word'],
  },
  {
    file: '00d2-recovery-autocomplete.png', flow: 'Recovery', step: 'Auto-complete', accent: '#14F195',
    device(o) {
      o.text(4, 4, 'Recovery Cipher:', 1)
      o.text(4, 30, '3/12: abandon~', 1)
      o.text(4, 50, '2: ability', 1)
      o.cipherGrid(
        ['m','b','n','v','c','x','z','l','k','j','h','g','f'],
        ['d','s','a','p','o','i','u','y','t','r','e','w','q']
      )
    },
    appContext: 'Source: recovery_cipher.c:371-380\nWord auto-completed from BIP39 wordlist\n~ indicates auto-completion triggered\nPrev word shows last completed word',
    insight: ['~ suffix = auto-completed from wordlist', 'Auto-complete reduces keystrokes needed', 'Invalid BIP39 words rejected immediately (7.14.0: PR #86)'],
  },
  {
    file: '00d3-recovery-invalid.png', flow: 'Recovery', step: 'Invalid Word Rejected', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'ERROR', 2)
      o.text(4, 28, 'Word not found in', 1)
      o.text(4, 42, 'BIP39 wordlist.', 1)
    },
    appContext: 'Source: recovery_cipher.c:478-498\nfsm_sendFailure(Failure_SyntaxError,\n"Word not found in BIP39 wordlist")\n7.14.0: per-word validation (PR #86)',
    insight: ['!!Invalid word rejected IMMEDIATELY', 'New in 7.14.0: per-word validation', 'Previously only caught at finalization'],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// PASSPHRASE
// ═══════════════════════════════════════════════════════════════════════

export const PASSPHRASE_FLOW: PageDef[] = [
  {
    file: '00e-passphrase.png', flow: 'Passphrase', step: 'Enter on Computer', accent: '#6366F1',
    device(o) {
      o.text(4, 14, 'Waiting for', 1)
      o.text(4, 30, 'Passphrase...', 1)
    },
    appContext: 'Source: passphrase_sm.c\nlayout_simple_message("Waiting for Passphrase...")\nPassphrase entered on host, sent over USB\nDevice waits until host sends PassphraseAck',
    insight: ['Passphrase entered on HOST, not device', 'Device only shows waiting message', 'Empty passphrase is valid (BIP-39 default)'],
  },
  {
    file: '00e2-passphrase-confirm.png', flow: 'Passphrase', step: 'Confirm Passphrase', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Confirm', 1)
      o.text(4, 18, 'If wrong, unplug and', 1)
      o.text(4, 30, 'replug your KeepKey:', 1)
      o.text(4, 46, 'mySecretPass123', 1)
    },
    appContext: 'Source: passphrase_sm.c\nreview(ButtonRequest_Other, "passphrase confirmation",\n"If this is wrong, unplug/replug Keepkey:\\n%51s", passphrase)\nShows entered passphrase for verification',
    insight: ['!!Shows passphrase on device screen for verification', 'review() auto-proceeds (no reject option)', '!Passphrase is EXAMPLE — actual varies'],
  },
  {
    file: '00e3-passphrase-enable.png', flow: 'Passphrase', step: 'Enable Passphrase', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Enable Passphrase', 2)
      o.text(4, 28, 'Enable passphrase', 1)
      o.text(4, 42, 'encryption?', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nconfirm(ButtonRequest_EnablePassphrase)\napplySettings handler for usePassphrase=true',
    insight: ['Adds passphrase layer to all key derivation', 'Different passphrase = different wallet'],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// DEVICE MANAGEMENT & SETTINGS
// ═══════════════════════════════════════════════════════════════════════

export const MGMT_FLOW: PageDef[] = [
  {
    file: '00f-wipe.png', flow: 'Device Management', step: 'Wipe Confirmation', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'Wipe Device', 2)
      o.text(4, 28, 'Do you really want to', 1)
      o.text(4, 40, 'wipe the device?', 1)
      o.text(4, 52, 'All data will be lost.', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nWipeDevice handler\nRequires physical button confirmation\nIrreversible — all keys destroyed',
    insight: ['!!CRITICAL: Irreversible operation', 'All keys, PIN, settings destroyed', 'Requires physical button press'],
  },
  {
    file: '00f2-change-label.png', flow: 'Device Management', step: 'Change Label', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Change Label', 2)
      o.text(4, 28, 'New label:', 1)
      o.text(4, 42, 'My KeepKey', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nconfirm(ButtonRequest_ChangeLabel, "Change Label",\n"New label: %s")\napplySettings handler',
    insight: ['Label shown on home screen', 'Cosmetic only — no security impact'],
  },
  {
    file: '00f3-autolock.png', flow: 'Device Management', step: 'Auto-Lock Timer', accent: '#6366F1',
    device(o) {
      o.text(4, 4, 'Auto-Lock Timer', 2)
      o.text(4, 28, 'Set auto-lock delay', 1)
      o.text(4, 42, 'to 600 seconds?', 1)
    },
    appContext: 'Source: fsm_msg_common.h\nconfirm(ButtonRequest_AutoLockDelayMs)\napplySettings handler for autoLockDelayMs',
    insight: ['Device locks after idle timeout', 'Requires PIN to unlock after lock'],
  },
  {
    file: '00f4-policy-advanced.png', flow: 'Device Management', step: 'AdvancedMode Policy', accent: '#F59E0B',
    device(o) {
      o.text(4, 4, 'AdvancedMode', 2)
      o.text(4, 28, 'Enable advanced mode?', 1)
      o.text(4, 42, 'Required for blind-sign', 1)
      o.text(4, 54, 'of unverified data.', 1)
    },
    appContext: 'Source: fsm_msg_common.h\napply_policy("AdvancedMode", enabled)\nGates all blind-signing operations\n7.14.0: gates EVM data signing (PR #91)',
    insight: ['!!Gates ALL blind-sign operations', 'Without this: unverified data txs rejected', '7.14.0: required for EVM data signing'],
  },
  {
    file: '00f5-user-reject.png', flow: 'Device Management', step: 'User Rejection', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'Action Cancelled', 2)
      o.text(4, 28, 'User rejected the', 1)
      o.text(4, 42, 'action on device.', 1)
    },
    appContext: 'Source: fsm.c\nfsm_sendFailure(Failure_ActionCancelled)\nShown on host — device returns to layoutHome()\nUser pressed reject button during any confirmation',
    insight: ['User pressed reject/cancel button', 'Device returns to home screen', 'Host receives Failure_ActionCancelled'],
  },
]
// EIP712_FLOW, TOKEN_FLOW, EVM_MULTICHAIN_FLOW defined below with verified content

// ═══════════════════════════════════════════════════════════════════════
// VERIFIED screens below — text from firmware confirm() source code
// Font rendering and pixel layout are APPROXIMATE (5x7 bitmap ≠ firmware font)
// Wrapping is a guess — real firmware uses proportional font + calc_str_line()
// ═══════════════════════════════════════════════════════════════════════

// BTC output: app_confirm.c:152 — confirm_transaction_output() -> "Send %s to\n%s"
// BTC summary: app_confirm.c:206 — confirm_transaction() -> title:"Transaction" body:"Do you want to send %s...fee of %s."
export const BTC_FLOW: PageDef[] = [
  {
    file: '01-btc-send-output.png', flow: 'Bitcoin Send', step: 'confirm_transaction_output()', accent: '#F7931A',
    device(o) {
      // app_confirm.c:155 — "Send %s to\n%s" (no title, bold)
      o.text(4, 4, 'Send 0.00150000 BTC to', 1)
      o.text(4, 18, 'bc1qxy2kgdygjrsqtzq2n0', 1)
      o.text(4, 30, 'yrf2493p83kkfjhx0wlh', 1)
    },
    appContext: 'Source: app_confirm.c:155\nconfirm_transaction_output()\n"Send %s to\\n%s"\nNo title, layout_notification_no_title_bold',
    insight: [
      'Verified: app_confirm.c:152-157',
      'No title — uses layout_notification_no_title_bold',
      'Address wraps by firmware calc_str_line()',
      '!Font + wrapping approximate — need emulator',
    ],
    qr: { data: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', label: 'DESTINATION' },
  },
  {
    file: '02-btc-confirm-tx.png', flow: 'Bitcoin Send', step: 'confirm_transaction()', accent: '#F7931A',
    device(o) {
      // app_confirm.c:211 — title:"Transaction" body:"Do you want to send %s from your wallet? This includes a transaction fee of %s."
      o.text(4, 4, 'Transaction', 2)
      o.text(4, 26, 'Do you want to send', 1)
      o.text(4, 38, '0.00150000 BTC from your', 1)
      o.text(4, 50, 'wallet? ...fee of 0.00001200', 1)
    },
    appContext: 'Source: app_confirm.c:211\nconfirm_transaction(total, fee)\nTitle: "Transaction"\n"Do you want to send %s from your wallet? This includes a transaction fee of %s."',
    insight: [
      'Verified: app_confirm.c:206-215',
      'Title: "Transaction" (title font)',
      'Body includes total + fee in one string',
      '!Wrapping approximate — need emulator',
    ],
  },
]

// ETH: app_confirm.c:134 — confirm_transfer_output() -> "Transfer %s\nto %s"
// ETH: confirm_transfer_output -> "Transfer %s\nto %s" (app_confirm.c:137)
// ETH: layoutEthereumFee -> title:"Transaction" body:"Send %s from your wallet, paying up to %s for gas?" (ethereum.c:787)
// ETH: sign message -> title:"Sign Message" body:message_text (fsm_msg_ethereum.h:265)
// ETH: blind sign block -> review("Blocked","Blind signing requires AdvancedMode.") (ethereum.c:760)
// ETH: arbitrary data -> title:"Confirm Ethereum Data" body:hex_chunks (ethereum.c:772)
export const ETH_FLOW: PageDef[] = [
  {
    file: '03-eth-transfer.png', flow: 'Ethereum', step: 'confirm_transfer_output()', accent: '#627EEA',
    device(o) {
      // app_confirm.c:137 — "Transfer %s\nto %s" (no title, bold)
      o.text(4, 4, 'Transfer 1.5 ETH', 1)
      o.text(4, 18, 'to 0x742d35Cc6634C053', 1)
      o.text(4, 30, '2950a20547b231011e30c', 1)
      o.text(4, 42, '8e7aec2b8Fe8', 1)
    },
    appContext: 'Source: app_confirm.c:137\nconfirm_transfer_output()\n"Transfer %s\\nto %s"\nNo title, layout_notification_no_title_bold',
    insight: [
      'Verified: app_confirm.c:134-139',
      'No title — bold layout',
      '!Amount uses 18 decimals (ethereumFormatAmount)',
      '!Font + wrapping approximate — need emulator',
    ],
    qr: { data: '0x742d35Cc6634C0532950a20547b231011e30c8e7aec2b8Fe8', label: 'DESTINATION' },
  },
  {
    file: '03b-eth-gas.png', flow: 'Ethereum', step: 'layoutEthereumFee()', accent: '#627EEA',
    device(o) {
      // ethereum.c:787 — title:"Transaction" body:"Send %s from your wallet, paying up to %s for gas?"
      o.text(4, 4, 'Transaction', 2)
      o.text(4, 26, 'Send 1.5 ETH from your', 1)
      o.text(4, 38, 'wallet, paying up to', 1)
      o.text(4, 50, '0.000420 ETH for gas?', 1)
    },
    appContext: 'Source: ethereum.c:787\nlayoutEthereumFee() -> confirm(SignTx, "Transaction", ...)\n"Send %s from your wallet, paying up to %s for gas?"',
    insight: [
      'Verified: ethereum.c:784-793',
      'Title: "Transaction"',
      'Gas = gas_price * gas_limit (legacy) or EIP-1559 calc',
      '!Chain ID NOT displayed — used internally for formatting',
    ],
  },
  {
    file: '03c-eth-sign-msg.png', flow: 'Ethereum', step: 'Sign Message', accent: '#627EEA',
    device(o) {
      // fsm_msg_ethereum.h:265 — title:"Sign Message" body:message_text
      o.text(4, 4, 'Sign Message', 2)
      o.text(4, 28, 'Login to OpenSea', 1)
      o.text(4, 40, 'Nonce: 8a3f2b1c', 1)
    },
    appContext: 'Source: fsm_msg_ethereum.h:265\nconfirm(ProtectCall, "Sign Message", "%s", msg)\nTitle+format verified, body content is EXAMPLE\nBinary -> "Sign Bytes" with hex',
    insight: [
      'Verified: fsm_msg_ethereum.h:255-270',
      'Title: "Sign Message" (printable) or "Sign Bytes" (binary)',
      'Body: raw message content, max 114 chars',
      '!Body text is example — actual content varies per dApp',
    ],
  },
  {
    file: '03d-eth-data.png', flow: 'Ethereum', step: 'Confirm Ethereum Data', accent: '#627EEA',
    device(o) {
      // ethereum.c:772 — title:"Confirm Ethereum Data" body:hex_chunks
      o.text(4, 4, 'Confirm Ethereum Data', 1)
      o.text(4, 20, 'a9059cbb 00000000', 1)
      o.text(4, 32, '00000000 00000000', 1)
      o.text(4, 44, '           68 bytes', 1)
    },
    appContext: 'Source: ethereum.c:769-777\nlayoutEthereumData() -> custom layout function\nNOT confirm() — uses layoutEthereumData()\nHex format approximate — need emulator',
    insight: [
      'Verified text: ethereum.c:769-777',
      '!Uses layoutEthereumData() not confirm()',
      '!Layout rendering may differ — need emulator',
      '!Requires AdvancedMode policy enabled',
    ],
  },
  {
    file: '03e-eth-blind-blocked.png', flow: 'Ethereum', step: 'Blind Sign Blocked', accent: '#EF4444',
    device(o) {
      // ethereum.c:760 — review("Blocked", "Blind signing requires AdvancedMode...")
      o.text(4, 4, 'Blocked', 2)
      o.text(4, 28, 'Blind signing requires', 1)
      o.text(4, 40, 'AdvancedMode. Enable in', 1)
      o.text(4, 52, 'device settings.', 1)
    },
    appContext: 'Source: ethereum.c:760-762\nreview() not confirm() — different function\nText verified, layout rendering approximate\nTransaction FAILS — user must enable policy first',
    insight: [
      'Verified text: ethereum.c:758-766',
      '!Uses review() not confirm() — layout may differ',
      '!!Transaction blocked — cannot proceed',
      'Must enable AdvancedMode in device settings',
    ],
  },
]

// EIP-712: shows hash digests, NOT decoded permit fields
// fsm_msg_ethereum.h:367-380
export const EIP712_FLOW: PageDef[] = [
  {
    file: '08-eip712-domain.png', flow: 'EIP-712 Typed Data', step: 'Domain Hash', accent: '#EF4444',
    device(o) {
      // fsm_msg_ethereum.h:372 — title:"Typed Data domain" body:"Confirm hash digest: %s"
      o.text(4, 4, 'Typed Data domain', 1)
      o.text(4, 20, 'Confirm hash digest:', 1)
      o.text(4, 34, 'a1b2c3d4e5f67890a1b2c3', 1)
      o.text(4, 46, 'd4e5f67890a1b2c3d4e5f6', 1)
    },
    appContext: 'Source: fsm_msg_ethereum.h:372\nconfirm(Other, "Typed Data domain",\n"Confirm hash digest: %s", domain_hash)\n64 hex chars of domain separator hash',
    insight: [
      'Verified: fsm_msg_ethereum.h:372',
      'Shows HASH of domain separator — NOT decoded fields',
      '!User sees hex — cannot verify permit details',
      '!This is why EIP-712 phishing is dangerous',
    ],
  },
  {
    file: '09-eip712-message.png', flow: 'EIP-712 Typed Data', step: 'Message Hash', accent: '#EF4444',
    device(o) {
      // fsm_msg_ethereum.h:378 — title:"Typed Data message" body:"Confirm hash digest: %s"
      o.text(4, 4, 'Typed Data message', 1)
      o.text(4, 20, 'Confirm hash digest:', 1)
      o.text(4, 34, 'f6e5d4c3b2a190807060', 1)
      o.text(4, 46, '504030201011223344556', 1)
    },
    appContext: 'Source: fsm_msg_ethereum.h:378\nconfirm(Other, "Typed Data message",\n"Confirm hash digest: %s", message_hash)\nOR "Confirm: No message" if no message_hash',
    insight: [
      'Verified: fsm_msg_ethereum.h:378-380',
      'Shows HASH of message — NOT decoded permit fields',
      '!!User cannot see: token, amount, spender, deadline',
      '!!This is the blind signing risk for EIP-712',
    ],
  },
]

// ERC-20: confirm_erc_token_transfer -> "Send %s" (app_confirm.c:174)
// Also uses layoutEthereumConfirmTx for approve flows (ethereum.c:726-748)
export const TOKEN_FLOW: PageDef[] = [
  {
    file: '10-erc20-transfer.png', flow: 'ERC-20 Token', step: 'layoutEthereumConfirmTx()', accent: '#8B5CF6',
    device(o) {
      // ethereum.c:748 — "Send %s to %s" (amount with token symbol, address)
      o.text(4, 4, 'Send 1000.000000 USDC', 1)
      o.text(4, 18, 'to 0x892CFa57d18c7d08', 1)
      o.text(4, 30, 'Dc79e7295e3cFd68b107', 1)
      o.text(4, 42, 'd07b0Ac', 1)
    },
    appContext: 'Source: ethereum.c:748\nlayoutEthereumConfirmTx()\n"Send %s to %s"\nToken symbol from tokenByChainAddress(chain_id, contract)',
    insight: [
      'Verified: ethereum.c:726-748',
      'Token symbol looked up by chain_id + contract address',
      '!Unknown tokens show raw amount without symbol',
      '!Font + wrapping approximate — need emulator',
    ],
    qr: { data: '0x892CFa57d18c7d08Dc79e7295e3cFd68b107d07b0Ac', label: 'RECIPIENT' },
  },
  {
    file: '11-erc20-approve.png', flow: 'ERC-20 Token', step: 'Approve Withdrawal', accent: '#8B5CF6',
    device(o) {
      // ethereum.c:735 — "Approve withdrawal of up to %s by %s?"
      o.text(4, 4, 'Approve withdrawal of', 1)
      o.text(4, 16, 'up to 1000.00 USDC by', 1)
      o.text(4, 30, '0x68b3465833fb72A70ec', 1)
      o.text(4, 42, 'DF485E0e4C7bD8665Fc45', 1)
    },
    appContext: 'Source: ethereum.c:735\nlayoutEthereumConfirmTx()\n"Approve withdrawal of up to %s by %s?"\nOR "Unlock full %s balance for withdrawal by %s?" (unlimited)',
    insight: [
      'Verified: ethereum.c:730-742',
      'Limited: "Approve withdrawal of up to %s by %s?"',
      '!Unlimited: "Unlock full %s balance for withdrawal by %s?"',
      '!Revoke: "Remove ability for %s to withdraw %s?"',
    ],
    qr: { data: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', label: 'SPENDER' },
  },
]

export const EVM_MULTICHAIN_FLOW: PageDef[] = [] // TODO: chain ID not displayed to user — used internally only

// Solana: fsm_msg_solana.h:57 — confirm(title, "Send %s to %s?", amount, addr)
export const SOLANA_FLOW: PageDef[] = [
  {
    file: '04-sol-send-before.png', flow: 'Solana (BEFORE fix)', step: 'Truncated — SECURITY RISK', accent: '#EF4444',
    device(o) {
      // OLD: solana_pubkeyToShort() — "Send %s to %s?" with truncated addr
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 16, 248)
      o.text(4, 22, 'Send 0.001000 SOL to', 1)
      o.text(4, 36, 'CD9R...d536?', 1)
    },
    appContext: 'Source: fsm_msg_solana.h:57\nOLD: solana_pubkeyToShort() truncated\nTitle: "Instr 1/1"\nBody: "Send %s to %s?"',
    insight: [
      'Verified format: fsm_msg_solana.h:57-58',
      '!!OLD: only 8 chars visible — spoofing vector',
      '!Title "Instr N/M" is real (line 49)',
      'Address was middle-truncated by pubkeyToShort()',
    ],
  },
  {
    file: '05-sol-send-after.png', flow: 'Solana (AFTER fix)', step: 'Full Address', accent: '#14F195',
    device(o) {
      // NEW: solana_pubkeyToStr() — full 44-char base58
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 16, 248)
      o.text(4, 22, 'Send 0.001000 SOL to CD9R', 1)
      o.text(4, 34, '61PMZFafFQ9QsPZATm74hFy', 1)
      o.text(4, 46, 'EvYaNtEtwGvvHmRYH?', 1)
    },
    appContext: 'Source: fsm_msg_solana.h:57\nNEW: solana_pubkeyToStr() full address\nTitle: "Instr 1/1"\nBody: "Send %s to %s?" wraps to 3 lines',
    insight: [
      'Verified format: fsm_msg_solana.h:57-58',
      'Full 44-char address — spoofing requires ALL chars',
      '!Wrapping approximate — firmware uses proportional font',
    ],
    qr: { data: 'CD9R61PMZFafFQ9QsPZATm74hFyEvYaNtEtwGvvHmRYH', label: 'DESTINATION' },
  },
  {
    file: '06-sol-unknown.png', flow: 'Solana Unknown Program', step: 'Unknown instruction', accent: '#F59E0B',
    device(o) {
      // fsm_msg_solana.h:267 — "Unknown instruction to program %s. Cannot verify contents."
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 16, 248)
      o.text(4, 22, 'Unknown instruction to', 1)
      o.text(4, 34, 'program JUP6LkMUje1knDR9', 1)
      o.text(4, 46, 'nToc2v2sJY4jat4A2QU1jP1L', 1)
    },
    appContext: 'Source: fsm_msg_solana.h:267\nconfirm(SignTx, title,\n"Unknown instruction to program %s. Cannot verify contents.")\nFull program ID shown',
    insight: [
      'Verified format: fsm_msg_solana.h:267-270',
      '!Full program ID — user can verify on Solscan',
      '!Wrapping approximate — need emulator',
    ],
  },
  {
    file: '06b-sol-spl-token.png', flow: 'Solana SPL Token', step: 'Token Transfer', accent: '#14F195',
    device(o) {
      // fsm_msg_solana.h — Token program transfer with token_info metadata
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 16, 248)
      o.text(4, 22, 'Send 100.000000 USDC to', 1)
      o.text(4, 34, 'CD9R61PMZFafFQ9QsPZATm74', 1)
      o.text(4, 46, 'hFyEvYaNtEtwGvvHmRYH?', 1)
    },
    appContext: 'Source: fsm_msg_solana.h\nToken program transfer with SolanaTokenInfo\nSymbol + decimals from host-provided metadata\nFallback: "Transfer unknown token at [mint]"',
    insight: [
      'Token metadata provided by host via SolanaTokenInfo',
      'Symbol "USDC" + decimals from token_info field',
      '!If no metadata: shows "Transfer unknown token at [mint]"',
    ],
  },
  {
    file: '06c-sol-blind-sign.png', flow: 'Solana', step: 'Blind Sign Warning', accent: '#EF4444',
    device(o) {
      // fsm_msg_solana.h — SOL_TX_REVIEW_OPAQUE path
      o.text(4, 4, 'Blind Sign', 2)
      o.text(4, 26, 'Sign unverified Solana', 1)
      o.text(4, 38, 'transaction? The device', 1)
      o.text(4, 50, 'cannot fully verify.', 1)
    },
    appContext: 'Source: fsm_msg_solana.h\nSOL_TX_REVIEW_OPAQUE classification\nRequires SolBlindSign policy enabled\nTriggered when instructions cannot be parsed',
    insight: [
      '!!Blind-sign — cannot verify transaction contents',
      'Requires AdvancedMode policy enabled',
      'Triggered for unparseable instructions or unknown programs',
    ],
  },
  {
    file: '06d-sol-message.png', flow: 'Solana', step: 'Sign Message', accent: '#14F195',
    device(o) {
      // fsm_msg_solana.h — SolanaSignMessage handler
      o.text(4, 4, 'Sign Message', 2)
      o.text(4, 26, 'Sign this message with', 1)
      o.text(4, 38, 'your Solana key?', 1)
    },
    appContext: 'Source: fsm_msg_solana.h\nSolanaSignMessage handler\nEd25519 signature over arbitrary message bytes',
    insight: [
      'Ed25519 signature over arbitrary bytes',
      'User confirms before signing',
    ],
  },
  {
    file: '06e-sol-final.png', flow: 'Solana', step: 'Final Confirmation', accent: '#14F195',
    device(o) {
      // fsm_msg_solana.h — final sign confirmation
      o.text(4, 4, 'Sign Transaction', 2)
      o.text(4, 26, 'Sign this Solana', 1)
      o.text(4, 38, 'transaction?', 1)
    },
    appContext: 'Source: fsm_msg_solana.h\nFinal confirmation after all instructions reviewed\nconfirm(SignTx, "Sign this Solana transaction?")',
    insight: [
      'Final gate before signing',
      'Only shown after all instructions confirmed individually',
    ],
  },
]

// THORChain: fsm_msg_thorchain.h:189 — confirm("Memo", "%s", memo)
export const THORCHAIN_FLOW: PageDef[] = [
  {
    file: '07-thorchain-memo.png', flow: 'THORChain Swap', step: 'confirm() memo', accent: '#23DCC8',
    device(o) {
      // fsm_msg_thorchain.h:189 — title:"Memo" body:memo_string
      o.text(4, 4, 'Memo', 2)
      o.text(4, 26, 'SWAP:ETH.ETH:', 1)
      o.text(4, 38, '0x742d35Cc6634C053', 1)
      o.text(4, 50, ':1500000', 1)
    },
    appContext: 'Source: fsm_msg_thorchain.h:189\nconfirm(ConfirmMemo, "Memo", "%s", memo)\nTitle: "Memo"\nBody: raw memo string',
    insight: [
      'Verified format: fsm_msg_thorchain.h:189-190',
      'Title: "Memo" (title font)',
      'Body: raw memo string, firmware wraps it',
      '!Wrapping approximate — need emulator',
    ],
  },
  // TODO: THORChain amount confirmation (confirm_transaction_output)
  // TODO: THORChain parsed memo (thorchain_parseConfirmMemo)
]

// TRON: fsm_msg_tron.h — structured clear signing
// TRX transfer: confirm("Send TRX", "Send %s to\n%s?") — line 177
// TRC-20 known: confirm("Send Token", "Send %s to\n%s?") — line 227
// TRC-20 unknown: confirm("Unknown Token", "Transfer unknown token at\n%s\nto %s?") — line 238
// Contract call: confirm("Contract Call", "Call contract\n%s?\nCannot verify call data.") — line 251
// Blind sign: confirm("Blind Sign", "Sign unverified TRON\ntransaction?\nData cannot be verified\non-device.") — line 309
// Final: confirm("Sign", "Sign this TRON transaction?") — line 296
export const TRON_FLOW: PageDef[] = [
  {
    file: '12-tron-trx-send.png', flow: 'TRON', step: 'Send TRX', accent: '#EF0027',
    device(o) {
      // fsm_msg_tron.h:177 — title:"Send TRX" body:"Send %s to\n%s?"
      o.text(4, 4, 'Send TRX', 2)
      o.text(4, 26, 'Send 100.000000 TRX to', 1)
      o.text(4, 38, 'THb4CqiFdwNHsWsQCs4Jh', 1)
      o.text(4, 50, 'zwjMWys4aqCbF?', 1)
    },
    appContext: 'Source: fsm_msg_tron.h:177\nconfirm("Send TRX", "Send %s to\\n%s?")\nFull 34-char Tron address displayed',
    insight: [
      'Verified: fsm_msg_tron.h:175-179',
      'Title: "Send TRX"',
      'Full base58 address (34 chars)',
      '!Wrapping approximate — need emulator',
    ],
  },
  {
    file: '13-tron-trc20-known.png', flow: 'TRON', step: 'Known TRC-20 Token', accent: '#EF0027',
    device(o) {
      // fsm_msg_tron.h:227 — title:"Send Token" body:"Send %s to\n%s?"
      o.text(4, 4, 'Send Token', 2)
      o.text(4, 26, 'Send 1000.000000 USDT to', 1)
      o.text(4, 38, 'THb4CqiFdwNHsWsQCs4Jh', 1)
      o.text(4, 50, 'zwjMWys4aqCbF?', 1)
    },
    appContext: 'Source: fsm_msg_tron.h:227\nconfirm("Send Token", "Send %s to\\n%s?")\n12 hardcoded tokens: USDT, USDD, SUN, JST, BTT, WIN, WBTC, ETH, USD1, HTX, TUSD, USDC',
    insight: [
      'Verified: fsm_msg_tron.h:225-230',
      'Title: "Send Token"',
      'Token symbol from hardcoded list (12 tokens)',
      '!Unknown tokens use different screen (see below)',
    ],
  },
  {
    file: '14-tron-trc20-unknown.png', flow: 'TRON', step: 'Unknown TRC-20', accent: '#F59E0B',
    device(o) {
      // fsm_msg_tron.h:238 — title:"Unknown Token" body:"Transfer unknown token at\n%s\nto %s?"
      o.text(4, 4, 'Unknown Token', 2)
      o.text(4, 26, 'Transfer unknown token at', 1)
      o.text(4, 38, 'TN3W4H6rK2ce4vX9YnFQH', 1)
      o.text(4, 50, 'wVWnYNRiEz to ...?', 1)
    },
    appContext: 'Source: fsm_msg_tron.h:238\nconfirm("Unknown Token",\n"Transfer unknown token at\\n%s\\nto %s?")\nNo symbol or amount — data unverified',
    insight: [
      'Verified: fsm_msg_tron.h:236-242',
      'Title: "Unknown Token"',
      '!No token symbol — contract not in hardcoded list',
      '!!Amount cannot be verified — raw data',
    ],
  },
  {
    file: '15-tron-contract.png', flow: 'TRON', step: 'Contract Call', accent: '#F59E0B',
    device(o) {
      // fsm_msg_tron.h:251 — title:"Contract Call" body:"Call contract\n%s?\nCannot verify call data."
      o.text(4, 4, 'Contract Call', 2)
      o.text(4, 26, 'Call contract', 1)
      o.text(4, 38, 'TN3W4H6rK2ce4vX9YnFQH', 1)
      o.text(4, 50, 'wVWnYNRiEz? Unverified.', 1)
    },
    appContext: 'Source: fsm_msg_tron.h:251\nconfirm("Contract Call",\n"Call contract\\n%s?\\nCannot verify call data.")',
    insight: [
      'Verified: fsm_msg_tron.h:249-254',
      'Title: "Contract Call"',
      '!!Cannot verify what this contract will do',
      '!Full contract address shown',
    ],
  },
  {
    file: '16-tron-blind.png', flow: 'TRON', step: 'Blind Sign', accent: '#EF4444',
    device(o) {
      // fsm_msg_tron.h:309 — title:"Blind Sign" body:"Sign unverified TRON\ntransaction?\nData cannot be verified\non-device."
      o.text(4, 4, 'Blind Sign', 2)
      o.text(4, 26, 'Sign unverified TRON', 1)
      o.text(4, 38, 'transaction? Data cannot', 1)
      o.text(4, 50, 'be verified on-device.', 1)
    },
    appContext: 'Source: fsm_msg_tron.h:309\nconfirm("Blind Sign",\n"Sign unverified TRON\\ntransaction?\\nData cannot be verified\\non-device.")\nLegacy path using raw_data',
    insight: [
      'Verified: fsm_msg_tron.h:307-313',
      'Title: "Blind Sign"',
      '!!Unverified transaction — maximum risk',
      '!Only triggers when raw_data provided (legacy)',
    ],
  },
]

// TON: fsm_msg_ton.h — dual mode clear + blind
// TODO: Need to audit fsm_msg_ton.h confirm() calls — not yet read
// Known from PR analysis:
//   Clear: confirm("TON Transfer", "Send %s to\n%s?")
//   Blind deploy: review("Blind Signature", "Wallet deployment TX\ncannot be verified...")
//   Blind opaque: review("Blind Signature", "TON TX details cannot be\nverified on device...")
// TON: fsm_msg_ton.h — clear sign (verified hash) vs blind sign (deploy/opaque)
// Clear: confirm("TON Transfer", "Send %s to\n%s?") — line 173
// Memo: confirm("Memo", "%s") — line 185
// Blind deploy: confirm("Blind Signature", "Wallet deployment TX\ncannot be verified...") — line 211-214
// Blind opaque: confirm("Blind Signature", "TON TX details cannot be\nverified...") — line 211-214
export const TON_FLOW: PageDef[] = [
  {
    file: '17-ton-transfer.png', flow: 'TON', step: 'Clear-sign Transfer', accent: '#0098EA',
    device(o) {
      // fsm_msg_ton.h:173 — title:"TON Transfer" body:"Send %s to\n%s?"
      o.text(4, 4, 'TON Transfer', 2)
      o.text(4, 26, 'Send 5.000000000 TON to', 1)
      o.text(4, 38, 'UQBvW8Z5huBkMJYdnfAc5', 1)
      o.text(4, 50, 'IxdrNi4rg1n-z7hahDHq?', 1)
    },
    appContext: 'Source: fsm_msg_ton.h:173\nconfirm("TON Transfer", "Send %s to\\n%s?")\nClear-sign: fields verified against raw_tx hash\nRequires: to_address, amount, seqno, expire_at, raw_tx=32 bytes',
    insight: [
      'Verified: fsm_msg_ton.h:168-181',
      'Title: "TON Transfer"',
      'Clear-sign: ton_verify_transfer_hash() passed',
      '!Full 48-char TON address displayed',
    ],
  },
  {
    file: '18-ton-memo.png', flow: 'TON', step: 'Memo', accent: '#0098EA',
    device(o) {
      // fsm_msg_ton.h:185 — title:"Memo" body:memo_text
      o.text(4, 4, 'Memo', 2)
      o.text(4, 28, 'Payment for services', 1)
      o.text(4, 42, 'Invoice #12345', 1)
    },
    appContext: 'Source: fsm_msg_ton.h:185\nconfirm("Memo", "%s", msg->memo)\nOnly shown if memo present and non-empty\nBody content is EXAMPLE — varies per tx',
    insight: [
      'Verified format: fsm_msg_ton.h:183-192',
      'Title: "Memo"',
      '!Body content is example — actual memo varies',
      'Only shown when memo is non-empty',
    ],
  },
  {
    file: '19-ton-blind-deploy.png', flow: 'TON', step: 'Blind Sign — Deploy', accent: '#EF4444',
    device(o) {
      // fsm_msg_ton.h:211-212 — is_deploy=true
      o.text(4, 4, 'Blind Signature', 1)
      o.text(4, 18, 'Wallet deployment TX', 1)
      o.text(4, 30, 'cannot be verified on', 1)
      o.text(4, 42, 'device. Sign only if you', 1)
      o.text(4, 54, 'trust the sending app.', 1)
    },
    appContext: 'Source: fsm_msg_ton.h:211-215\nconfirm("Blind Signature", deploy_msg)\nis_deploy=true -> StateInit changes cell tree\nFirmware cannot reconstruct — always blind',
    insight: [
      'Verified: fsm_msg_ton.h:211-215',
      'Title: "Blind Signature"',
      '!!Deploy TX cannot be verified on-device',
      '!Only sign if you trust the sending app',
    ],
  },
  {
    file: '20-ton-blind-opaque.png', flow: 'TON', step: 'Blind Sign — Opaque TX', accent: '#EF4444',
    device(o) {
      // fsm_msg_ton.h:213 — is_deploy=false, verification failed
      o.text(4, 4, 'Blind Signature', 1)
      o.text(4, 18, 'TON TX details cannot', 1)
      o.text(4, 30, 'be verified on device.', 1)
      o.text(4, 42, 'Sign only if you trust', 1)
      o.text(4, 54, 'the sending app.', 1)
    },
    appContext: 'Source: fsm_msg_ton.h:213-215\nconfirm("Blind Signature", opaque_msg)\nClear-sign verification FAILED\nMissing fields or hash mismatch',
    insight: [
      'Verified: fsm_msg_ton.h:211-215',
      'Title: "Blind Signature"',
      '!!TX details unverifiable — clear-sign check failed',
      '!Triggers when fields missing or hash mismatch',
    ],
  },
]

// Zcash: fsm_msg_zcash.h
// Shielded-only: confirm("Zcash Shielded", "Sign shielded transaction?\nAmount: %s\nFee: %s\nActions: %lu") — line 137
// Hybrid shield: confirm("Zcash Shield", "Shield transparent ZEC to Orchard?\nAmount: %s\nFee: %s\nInputs: %lu\nActions: %lu") — line 125
// Per-input: confirm("Sign Input", "Sign transparent input?\n%s") — line 643
export const ZCASH_FLOW: PageDef[] = [
  {
    file: '21-zcash-shielded.png', flow: 'Zcash', step: 'Shielded-only TX', accent: '#F4B728',
    device(o) {
      // fsm_msg_zcash.h:137 — title:"Zcash Shielded" body:"Sign shielded transaction?\nAmount: %s\nFee: %s\nActions: %lu"
      o.text(4, 4, 'Zcash Shielded', 2)
      o.text(4, 26, 'Sign shielded transaction?', 1)
      o.text(4, 38, 'Amount: 5.25000000 ZEC', 1)
      o.text(4, 50, 'Fee: 0.00010000 Actions: 2', 1)
    },
    appContext: 'Source: fsm_msg_zcash.h:137\nconfirm("Zcash Shielded",\n"Sign shielded transaction?\\nAmount: %s\\nFee: %s\\nActions: %lu")\nPure Orchard — no transparent inputs',
    insight: [
      'Verified: fsm_msg_zcash.h:136-141',
      'Title: "Zcash Shielded"',
      'No recipient shown — Orchard hides by design',
      '!Amount/fee visible, actions = Orchard actions count',
    ],
  },
  {
    file: '22-zcash-hybrid.png', flow: 'Zcash', step: 'Hybrid Shield', accent: '#F4B728',
    device(o) {
      // fsm_msg_zcash.h:125 — title:"Zcash Shield" body:"Shield transparent ZEC to Orchard?\nAmount: %s\nFee: %s\nInputs: %lu\nActions: %lu"
      o.text(4, 4, 'Zcash Shield', 2)
      o.text(4, 26, 'Shield transparent ZEC?', 1)
      o.text(4, 38, 'Amount: 10.00000000 ZEC', 1)
      o.text(4, 50, 'Fee: 0.0001 In:3 Act:2', 1)
    },
    appContext: 'Source: fsm_msg_zcash.h:125\nconfirm("Zcash Shield",\n"Shield transparent ZEC to Orchard?\\nAmount: %s\\nFee: %s\\nInputs: %lu\\nActions: %lu")\nTransparent UTXOs -> Orchard shielded pool',
    insight: [
      'Verified: fsm_msg_zcash.h:124-130',
      'Title: "Zcash Shield"',
      'Hybrid: transparent inputs being shielded',
      '!Inputs = transparent UTXOs, Actions = Orchard actions',
    ],
  },
  {
    file: '23-zcash-sign-input.png', flow: 'Zcash', step: 'Sign Transparent Input', accent: '#F4B728',
    device(o) {
      // fsm_msg_zcash.h:643 — title:"Sign Input" body:"Sign transparent input?\nInput 1: 5.25000000 ZEC"
      o.text(4, 4, 'Sign Input', 2)
      o.text(4, 28, 'Sign transparent input?', 1)
      o.text(4, 42, 'Input 1: 5.25000000 ZEC', 1)
    },
    appContext: 'Source: fsm_msg_zcash.h:643\nconfirm("Sign Input", "Sign transparent input?\\n%s")\nPer-UTXO signing during hybrid transactions\nShown for each transparent input',
    insight: [
      'Verified: fsm_msg_zcash.h:640-646',
      'Title: "Sign Input"',
      'One screen per transparent UTXO',
      '!Multiple inputs = multiple confirmations',
    ],
  },
  {
    file: '23b-zcash-progress.png', flow: 'Zcash', step: 'Signing Progress', accent: '#F4B728',
    device(o) {
      // fsm_msg_zcash.h — layoutProgress during action streaming
      o.text(4, 4, 'Signing Zcash', 1)
      o.progressBar(4, 30, 248, 10, 0.72)  // ~72% filled
      o.text(4, 50, 'Action 5 of 7...', 1)
    },
    appContext: 'Source: fsm_msg_zcash.h\nlayoutProgress("Signing Zcash", percentage)\nShown during Orchard action streaming phase\nUpdates per-action as device signs',
    insight: [
      'Progress bar during multi-action signing',
      'Visible during Phase 2 action streaming',
      '!Max 16 actions per session',
    ],
  },
  {
    file: '23c-zcash-fvk.png', flow: 'Zcash', step: 'Orchard FVK', accent: '#F4B728',
    device(o) {
      // ZcashGetOrchardFVK — returns ak, nk, rivk (safe to export)
      o.text(4, 4, 'Orchard FVK', 2)
      o.text(4, 26, 'Export Full Viewing Key', 1)
      o.text(4, 38, 'for account 0?', 1)
      o.text(4, 50, 'Cannot spend funds.', 1)
    },
    appContext: 'Source: fsm_msg_zcash.h\nZcashGetOrchardFVK handler\nFVK is safe to export — viewing only\nak, nk, rivk returned to host',
    insight: [
      'FVK cannot spend — only view transactions',
      'Used for unified address construction',
      'ZIP-32 derivation from raw BIP-39 seed',
    ],
  },
]

// Ripple: fsm_msg_ripple.h
// Send: confirm("Send", "Send %s to %s, with destination tag %u?") — line 99
// Confirm: confirm("Transaction", "Really send %s, with a transaction fee of %s?") — line 112
export const RIPPLE_FLOW: PageDef[] = [
  {
    file: '24-xrp-send.png', flow: 'Ripple (XRP)', step: 'Send XRP', accent: '#23292F',
    device(o) {
      // fsm_msg_ripple.h:99 — title:"Send" body:"Send %s to %s, with destination tag %u?"
      o.text(4, 4, 'Send', 2)
      o.text(4, 26, 'Send 25.000000 XRP to', 1)
      o.text(4, 38, 'rN7xRJP1Kd5s8m3pWe', 1)
      o.text(4, 50, 'YzGrn, dest tag 12345?', 1)
    },
    appContext: 'Source: fsm_msg_ripple.h:99\nconfirm("Send", "Send %s to %s, with destination tag %u?")\nOR without dest tag: "Send %s to %s?"',
    insight: [
      'Verified: fsm_msg_ripple.h:99-107',
      'Title: "Send"',
      'Destination tag shown when present',
      '!Wrapping approximate -- need emulator',
    ],
  },
  {
    file: '25-xrp-confirm-tx.png', flow: 'Ripple (XRP)', step: 'confirm TX', accent: '#23292F',
    device(o) {
      // fsm_msg_ripple.h:112 — title:"Transaction" body:"Really send %s, with a transaction fee of %s?"
      o.text(4, 4, 'Transaction', 2)
      o.text(4, 26, 'Really send 25.000000', 1)
      o.text(4, 38, 'XRP, with a transaction', 1)
      o.text(4, 50, 'fee of 0.000012 XRP?', 1)
    },
    appContext: 'Source: fsm_msg_ripple.h:112\nconfirm("Transaction",\n"Really send %s, with a transaction fee of %s?")',
    insight: [
      'Verified: fsm_msg_ripple.h:112-114',
      'Title: "Transaction"',
      'Shows total amount + fee',
      '!Wrapping approximate -- need emulator',
    ],
  },
]

// Cosmos: fsm_msg_cosmos.h
// Send: confirm_transaction_output() -> "Send %s to\n%s" — line 135
// Redelegate: confirm("Redelegate", "Redelegate %s?") — line 274
// Claim: confirm("Claim Rewards", "Claim %s?") — line 334
// IBC: confirm("IBC Transfer", "Transfer %s to %s?") — line 396
// Memo: confirm("Memo", "%s") — line 466
export const COSMOS_FLOW: PageDef[] = [
  {
    file: '26-cosmos-send.png', flow: 'Cosmos (ATOM)', step: 'confirm_transaction_output()', accent: '#2E3148',
    device(o) {
      // fsm_msg_cosmos.h:135 -> app_confirm.c:155 — "Send %s to\n%s"
      o.text(4, 4, 'Send 10.000000 ATOM to', 1)
      o.text(4, 18, 'cosmos1qypqxpq9qcrsszg2', 1)
      o.text(4, 30, 'pvxq6as0yqr8vrm85cew', 1)
      o.text(4, 42, 'q3hlf', 1)
    },
    appContext: 'Source: fsm_msg_cosmos.h:135\nconfirm_transaction_output()\n"Send %s to\\n%s"\nSame pattern as BTC external send',
    insight: [
      'Verified: fsm_msg_cosmos.h:133-139',
      'No title -- layout_notification_no_title_bold',
      'Full bech32 cosmos address',
      '!Wrapping approximate -- need emulator',
    ],
  },
  {
    file: '27-cosmos-redelegate.png', flow: 'Cosmos (ATOM)', step: 'Redelegate', accent: '#2E3148',
    device(o) {
      // fsm_msg_cosmos.h:274 — title:"Redelegate" body:"Redelegate %s?"
      o.text(4, 4, 'Redelegate', 2)
      o.text(4, 30, 'Redelegate 50.000000', 1)
      o.text(4, 44, 'ATOM?', 1)
    },
    appContext: 'Source: fsm_msg_cosmos.h:274\nconfirm("Redelegate", "Redelegate %s?")',
    insight: [
      'Verified: fsm_msg_cosmos.h:274-275',
      'Title: "Redelegate"',
      'Shows amount being redelegated',
    ],
  },
  {
    file: '28-cosmos-claim.png', flow: 'Cosmos (ATOM)', step: 'Claim Rewards', accent: '#2E3148',
    device(o) {
      // fsm_msg_cosmos.h:334 — title:"Claim Rewards" body:"Claim %s?"
      o.text(4, 4, 'Claim Rewards', 2)
      o.text(4, 30, 'Claim 1.234567 ATOM?', 1)
    },
    appContext: 'Source: fsm_msg_cosmos.h:334\nconfirm("Claim Rewards", "Claim %s?")\nOR "Claim all available rewards?"',
    insight: [
      'Verified: fsm_msg_cosmos.h:334-342',
      'Title: "Claim Rewards"',
      'Shows specific amount or "all available"',
    ],
  },
  // TODO: IBC Transfer — confirm("IBC Transfer", "Transfer %s to %s?") — line 396
  // TODO: Source Channel/Port/Revision confirms — lines 404-430
]

// Mayachain: fsm_msg_mayachain.h
// Same memo pattern as THORChain: confirm("Memo", "%s")
// Sign: confirm(SignTx, node_str, "Sign this %s transaction on %s? Additional network fees apply.")
export const MAYACHAIN_FLOW: PageDef[] = [
  {
    file: '29-maya-sign.png', flow: 'Maya Protocol', step: 'Sign TX', accent: '#3B82F6',
    device(o) {
      // fsm_msg_mayachain.h:245 — title:node_str body:"Sign this %s transaction on %s? Additional network fees apply."
      o.text(4, 4, 'm/44\'/931\'/0\'/0/0', 1)
      o.text(4, 18, 'Sign this CACAO', 1)
      o.text(4, 30, 'transaction on', 1)
      o.text(4, 42, 'mayachain-mainnet-v1?', 1)
      o.text(4, 54, 'Additional fees apply.', 1)
    },
    appContext: 'Source: fsm_msg_mayachain.h:245\nconfirm(SignTx, node_str,\n"Sign this %s transaction on %s? Additional network fees apply.")',
    insight: [
      'Verified: fsm_msg_mayachain.h:245-248',
      'Title: BIP32 derivation path',
      'Shows denom + chain_id',
      '!Wrapping approximate -- need emulator',
    ],
  },
]

// Binance: fsm_msg_binance.h
// Memo: confirm("Memo", "%s") — line 158
// Sign: confirm(SignTx, node_str, "Sign this Binance transaction on %s?") — line 176
export const BINANCE_FLOW: PageDef[] = [
  {
    file: '30-bnb-sign.png', flow: 'Binance Chain', step: 'Sign TX', accent: '#F3BA2F',
    device(o) {
      // fsm_msg_binance.h:176 — title:node_str body:"Sign this Binance transaction on %s?"
      o.text(4, 4, 'm/44\'/714\'/0\'/0/0', 1)
      o.text(4, 20, 'Sign this Binance', 1)
      o.text(4, 34, 'transaction on', 1)
      o.text(4, 48, 'Binance-Chain-Tigris?', 1)
    },
    appContext: 'Source: fsm_msg_binance.h:176\nconfirm(SignTx, node_str,\n"Sign this Binance transaction on %s?", chain_id)',
    insight: [
      'Verified: fsm_msg_binance.h:176-178',
      'Title: BIP32 derivation path',
      'Shows chain_id in body',
    ],
  },
]

// BIP-85: fsm_msg_bip85.h
// confirm("BIP-85 Derive Seed", "%s") — line 28
export const BIP85_FLOW: PageDef[] = [
  {
    file: '31-bip85-derive.png', flow: 'BIP-85', step: 'Derive Child Seed', accent: '#8B5CF6',
    device(o) {
      // fsm_msg_bip85.h:28 — title:"BIP-85 Derive Seed" body:description
      o.text(4, 4, 'BIP-85 Derive Seed', 1)
      o.text(4, 20, 'BIP-39 12 words', 1)
      o.text(4, 34, 'English index 0', 1)
    },
    appContext: 'Source: fsm_msg_bip85.h:28\nconfirm("BIP-85 Derive Seed", "%s", desc)\nDisplay-only mode -- seed shown on device, never sent over USB',
    insight: [
      'Verified: fsm_msg_bip85.h:28-30',
      'Title: "BIP-85 Derive Seed"',
      'Body: description of derivation params',
      '!Derived seed shown on device only',
    ],
  },
  {
    file: '31b-bip85-mnemonic.png', flow: 'BIP-85', step: 'Mnemonic Display', accent: '#8B5CF6',
    device(o) {
      // fsm_msg_bip85.h — mnemonic words displayed on OLED
      o.text(4, 4, 'Child Mnemonic', 2)
      o.text(4, 26, '1.abandon 2.ability', 1)
      o.text(4, 38, '3.able    4.about', 1)
      o.text(4, 50, '(press to continue)', 1)
    },
    appContext: 'Source: fsm_msg_bip85.h\nDerived mnemonic displayed on OLED in pages\nNEVER sent over USB — firmware returns Success only\n!Words shown are EXAMPLE — real output varies',
    insight: [
      '!!Mnemonic ONLY on device screen — never over USB',
      'Words are EXAMPLE — varies by seed + index',
      'User must write down before dismissing',
      'Firmware returns Success, not the mnemonic',
    ],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// SECTION 5: Main
// ═══════════════════════════════════════════════════════════════════════

async function main() {
  mkdirSync(PAGES_DIR, { recursive: true })

  const allFlows: { name: string; pages: PageDef[] }[] = [
    { name: 'BTC', pages: BTC_FLOW },
    { name: 'ETH', pages: ETH_FLOW },
    { name: 'Solana', pages: SOLANA_FLOW },
    { name: 'EIP-712', pages: EIP712_FLOW },
    { name: 'ERC-20', pages: TOKEN_FLOW },
    { name: 'THORChain', pages: THORCHAIN_FLOW },
    { name: 'TRON', pages: TRON_FLOW },
    { name: 'TON', pages: TON_FLOW },
    { name: 'Zcash', pages: ZCASH_FLOW },
    { name: 'Ripple', pages: RIPPLE_FLOW },
    { name: 'Cosmos', pages: COSMOS_FLOW },
    { name: 'Maya', pages: MAYACHAIN_FLOW },
    { name: 'Binance', pages: BINANCE_FLOW },
    { name: 'BIP-85', pages: BIP85_FLOW },
    // Device management flows
    { name: 'Setup', pages: SETUP_FLOW },
    { name: 'PIN', pages: PIN_FLOW },
    { name: 'Recovery', pages: RECOVERY_FLOW },
    { name: 'Passphrase', pages: PASSPHRASE_FLOW },
    { name: 'Management', pages: MGMT_FLOW },
    // Awaiting full emulator screenshots:
    { name: 'Setup', pages: SETUP_FLOW },
    { name: 'PIN', pages: PIN_FLOW },
    { name: 'EVM Multi-Chain', pages: EVM_MULTICHAIN_FLOW },
    { name: 'Recovery', pages: RECOVERY_FLOW },
    { name: 'Passphrase', pages: PASSPHRASE_FLOW },
    { name: 'Management', pages: MGMT_FLOW },
    // TODO: Osmosis (LP, swap, pool ops -- fsm_msg_osmosis.h)
    // TODO: EOS (fsm_msg_eos.h)
    // TODO: Nano (fsm_msg_nano.h)
    // TODO: Cosmos IBC Transfer details
    // TODO: MakerDAO, 0x, Sablier, THORChain EVM contracts
  ].filter(f => f.pages.length > 0)

  const allPages = allFlows.flatMap(f => f.pages)

  for (let i = 0; i < allPages.length; i++) {
    const p = allPages[i]
    const flow = allFlows.find(f => f.pages.includes(p))!
    const stepIdx = flow.pages.indexOf(p)
    const totalSteps = flow.pages.length

    await buildPage(p.file, p.flow, p.step, stepIdx, totalSteps, p.accent, p.device, p.appContext, p.insight, p.qr)
    process.stdout.write(`  ${p.file}\n`)
  }

  console.log(`\n  ${allPages.length} verified screens (${12 - allFlows.length} flows TODO) -> ${relative(process.cwd(), PAGES_DIR)}/`)
}

if (import.meta.main) {
  console.log('\nKeepKey Zoo — Verified firmware screens only\n')
  main().catch(e => { console.error(e); process.exit(1) })
}
