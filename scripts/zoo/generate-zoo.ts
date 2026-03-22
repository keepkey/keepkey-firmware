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
const OLED_SCALE = 3 // 256×64 → 768×192
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

  // Compose
  await sharp({
    create: { width: PAGE_W, height: pageH, channels: 4, background: BG }
  })
    .composite([
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
    ])
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
}

export const SETUP_FLOW: PageDef[] = [
  {
    file: '01-setup-pin-tutorial.png', flow: 'First Launch', step: 'Tutorial: PIN Security', accent: '#C0A860',
    device(o) { o.text(4, 7, 'Enter PIN:', 2); o.pinGrid([8, 3, 6, 1, 5, 9, 4, 7, 2]) },
    appContext: 'Tutorial card: "Your PIN is Scrambled"\nShows scrambled PIN grid illustration\nGold accent, 1 of 3 intro cards',
    insight: [
      'Device shows numbers in a 3x3 grid',
      'Grid is RANDOMIZED every time',
      'App shows only dot positions (no numbers)',
      '!Screen-watchers see dots, not your PIN',
      '!Layout changes prevent memorization attacks',
    ],
  },
  {
    file: '02-setup-seed-tutorial.png', flow: 'First Launch', step: 'Tutorial: Recovery Phrase', accent: '#FC8181',
    device(o) { o.text(4, 4, 'Write down word 1:', 1); o.hline(4, 14, 248); o.centerText(22, 'abandon', 2); o.hline(4, 42, 248); o.centerText(50, 'Press for next word', 1) },
    appContext: 'Tutorial card: "Your Words = Your Wallet"\nShows 12 word-slot rectangles\nRed accent warning, 2 of 3 intro cards',
    insight: [
      'Device displays one word at a time',
      'Write EACH word on paper immediately',
      '!!NEVER photograph or type words digitally',
      '!!Anyone with these words controls your funds',
      '!Store paper in fireproof, waterproof safe',
    ],
  },
  {
    file: '03-setup-cipher-tutorial.png', flow: 'First Launch', step: 'Tutorial: Recovery Cipher', accent: '#23DCC8',
    device(o) { o.text(4, 4, 'Word 1', 1); o.text(4, 14, 'Char 1', 1); o.cipherGrid('abcdefghijklm'.split(''), 'tmarwdsebpcnk'.split('')); o.text(4, 46, 'Enter by', 1); o.text(4, 56, 'position', 1) },
    appContext: 'Tutorial card: "Scrambled Recovery Entry"\nShows scrambled letter grid diagram\nTeal accent, 3 of 3 — "Get Started" button',
    insight: [
      'Device shows SCRAMBLED alphabet grid',
      'App shows ordered a-z letter grid',
      'You tap POSITIONS on app, device reads scrambled letter',
      '!Keyloggers capture meaningless positions',
      '!Grid re-scrambles for every character',
    ],
  },
  {
    file: '04-setup-bootloader.png', flow: 'First Launch', step: 'Bootloader Update', accent: '#48BB78',
    device(o) { o.centerText(10, 'BOOTLOADER', 2); o.centerText(32, 'v2.1.4', 1); o.rect(2, 2, OLED_W - 4, OLED_H - 4, false) },
    appContext: 'Wizard step 1: "Enter Bootloader Mode"\nUser holds button on device during plug-in\n"Skip" available if bootloader already current',
    insight: [
      'Device displays BOOTLOADER with version',
      'Only enter bootloader intentionally',
      '!Do NOT disconnect during update',
    ],
  },
  {
    file: '05-setup-firmware.png', flow: 'First Launch', step: 'Firmware Flash', accent: '#48BB78',
    device(o) { o.centerText(8, 'Updating firmware...', 1); o.progressBar(20, 26, 216, 12, 0.62); o.centerText(48, 'Do NOT disconnect', 1) },
    appContext: 'Wizard step 2: Firmware download & flash\nShows chain logos + feature preview\nProgress bar mirrors device progress',
    insight: [
      'Device shows progress bar during flash',
      '!!Disconnecting during flash can BRICK device',
      '!Wait for "Update complete" before touching',
    ],
  },
  {
    file: '06-setup-create-wallet.png', flow: 'First Launch', step: 'Create or Recover', accent: '#48BB78',
    device(o) { o.text(4, 7, 'Create new wallet?', 1); o.text(4, 22, 'A new recovery phrase', 1); o.text(4, 32, 'will be generated.', 1); o.centerText(52, '[Press to confirm]', 1) },
    appContext: 'Wizard step 3: Two large buttons\n"Create New Wallet" — generate fresh seed\n"Recover Existing" — enter seed via cipher',
    insight: [
      'Device confirms wallet creation',
      'Press button only if you want a NEW wallet',
      '!Creating overwrites any existing seed on device',
    ],
  },
  {
    file: '07-setup-seed-display.png', flow: 'First Launch', step: 'Seed Word Display', accent: '#F59E0B',
    device(o) { o.text(4, 4, 'Write down word 6:', 1); o.hline(4, 14, 248); o.centerText(22, 'carbon', 2); o.hline(4, 42, 248); o.centerText(50, 'Press for next word', 1) },
    appContext: 'App shows: "Writing seed to device..."\nNo words visible on computer screen\nOnly the device displays the actual words',
    insight: [
      'Words appear ONLY on device screen',
      'Computer never sees the seed words',
      'Write word number + word on paper',
      '!Verify word number matches your list position',
      '!!If you miss a word, start setup over',
    ],
  },
  {
    file: '08-setup-verify-seed.png', flow: 'First Launch', step: 'Seed Verification', accent: '#F59E0B',
    device(o) { o.text(4, 4, 'Select word #3:', 1); o.hline(4, 14, 248); o.text(30, 20, '1.  ocean', 1); o.text(30, 32, '2.  carbon', 1); o.text(30, 44, '3.  cactus', 1); o.centerText(58, 'Press button to select', 1) },
    appContext: 'App asks: "Verify your recovery phrase?"\nOptional but strongly recommended\nSkip available but not advised',
    insight: [
      'Device shows 3 word choices',
      'Select the word matching your written list',
      '!Wrong answer means you wrote the seed incorrectly',
      '!If wrong, redo setup — do NOT continue',
    ],
  },
  {
    file: '09-setup-complete.png', flow: 'First Launch', step: 'Setup Complete', accent: '#48BB78',
    device(o) { o.foxLogo(128, 28); o.centerText(52, 'KeepKey', 1) },
    appContext: 'Confetti animation + "Setup Complete!"\nAuto-advances to dashboard in 5 seconds\nPost-tutorial security tips shown before this',
    insight: [
      'Device shows KeepKey logo — fully initialized',
      'Your wallet is ready to use',
      'Seed is stored securely on device',
    ],
  },
]

export const PIN_FLOW: PageDef[] = [
  {
    file: '10-pin-unlock.png', flow: 'PIN Unlock', step: 'Enter PIN to Access Device', accent: '#C0A860',
    device(o) { o.text(4, 7, 'Enter PIN:', 2); o.pinGrid([8, 3, 6, 1, 5, 9, 4, 7, 2]) },
    appContext: 'PIN overlay (z-index 2000) covers all content\n3x3 dot grid — NO numbers shown\nMasked PIN display: ● ● ● _\nSubmit / Cancel / Wipe Device buttons',
    insight: [
      'DEVICE: numbers in randomized 3x3 grid',
      'APP: shows only dot positions (no numbers)',
      'Match positions: tap app dot that matches device number',
      '!Grid randomizes EVERY time — positions change',
      '!Wrong PIN: limited attempts before auto-wipe',
      '!!After max failures, device wipes as theft protection',
    ],
  },
  {
    file: '11-pin-create.png', flow: 'PIN Create', step: 'Choose New PIN (Step 1 of 2)', accent: '#3B82F6',
    device(o) { o.text(4, 7, 'Create PIN:', 2); o.text(4, 30, '(4-9 digits)', 1); o.pinGrid([5, 1, 8, 9, 3, 7, 2, 6, 4]) },
    appContext: 'PIN overlay: "Create New PIN"\nSubtitle: "Step 1 of 2"\nSame dot grid — choose 4-9 digit sequence',
    insight: [
      'Choose a PIN you can REMEMBER',
      '4-9 digits recommended',
      'Match number positions on device to dots on app',
      '!In step 2, grid will CHANGE — same numbers, new positions',
    ],
  },
]

export const BTC_FLOW: PageDef[] = [
  {
    file: '12-btc-send-address.png', flow: 'Bitcoin Send', step: 'Verify Destination Address', accent: '#F7931A',
    device(o) { o.text(4, 4, 'Confirm sending to:', 1); o.hline(4, 14, 248); o.text(4, 20, 'bc1qxy2kgdygjrsqt', 1); o.text(4, 30, 'zq2n0yrf2493p83kk', 1); o.text(4, 40, 'fjhx0wlh', 1); o.centerText(54, '[Hold to confirm]', 1) },
    appContext: 'App shows: "Confirming on KeepKey..."\nNo action buttons — waiting for device\nPulsing green glow on KeepKey outline',
    insight: [
      'Compare EVERY character of the address',
      'Check first 8 + last 8 characters minimum',
      '!!Clipboard malware replaces addresses silently',
      '!!The address on your COMPUTER may be WRONG',
      '!The DEVICE screen shows the REAL destination',
      'This is the #1 attack vector for hardware wallets',
    ],
  },
  {
    file: '13-btc-send-amount.png', flow: 'Bitcoin Send', step: 'Verify Amount & Fee', accent: '#F7931A',
    device(o) { o.text(4, 4, 'Amount:', 1); o.centerText(18, '0.00150000 BTC', 2); o.hline(4, 38, 248); o.centerText(46, '[Hold to confirm]', 1) },
    appContext: 'App shows same "Confirming on KeepKey..."\nTransaction details visible in background\nAmount should match what you entered',
    insight: [
      'Amount matches what you entered in the app',
      'Watch decimal places: 0.01 vs 0.1 vs 1.0 BTC',
      '!A misplaced decimal is a 10x error',
      '!!Compromised app could change the amount',
      '!Device shows the REAL amount being signed',
    ],
  },
  {
    file: '14-btc-send-fee.png', flow: 'Bitcoin Send', step: 'Verify Transaction Fee', accent: '#F7931A',
    device(o) { o.text(4, 4, 'Transaction fee:', 1); o.centerText(18, '0.00001200 BTC', 2); o.text(4, 38, 'Fee rate: 12 sat/vB', 1); o.centerText(52, '[Hold to confirm]', 1) },
    appContext: 'Fee confirmation screen on device\nNormal BTC fees: 1-50 sat/vB\nApp showed fee tier: Economy/Normal/Priority',
    insight: [
      'Normal fees: 0.00001-0.0005 BTC',
      '!Abnormally high fee may indicate attack',
      '!!Fee siphoning: inflated fee goes to colluding miner',
      'Device shows exact fee — verify it is reasonable',
    ],
  },
  {
    file: '15-btc-send-success.png', flow: 'Bitcoin Send', step: 'Transaction Broadcast', accent: '#48BB78',
    device(o) { o.foxLogo(128, 28); o.centerText(52, 'KeepKey', 1) },
    appContext: 'App shows: "Transaction Sent!"\nTxID displayed with Copy button\n"View in Explorer" opens block explorer\nDevice returns to idle',
    insight: [
      'Transaction signed and broadcast to network',
      'TxID is proof of broadcast',
      '!!Bitcoin transactions are IRREVERSIBLE',
      'Confirm in block explorer for final verification',
    ],
  },
]

export const ETH_FLOW: PageDef[] = [
  {
    file: '16-eth-send-address.png', flow: 'Ethereum Send', step: 'Verify ETH Address', accent: '#627EEA',
    device(o) { o.text(4, 4, 'Send ETH to:', 1); o.hline(4, 14, 248); o.text(4, 20, '0x742d35Cc6634C053', 1); o.text(4, 30, '2950a20547b231011', 1); o.text(4, 40, 'e30c8e7aec2b8Fe8', 1); o.centerText(54, '[Hold to confirm]', 1) },
    appContext: 'App: "Confirming on KeepKey..."\nETH address: 42 chars (0x + 40 hex)\nSame clipboard hijacking risk as BTC',
    insight: [
      'Full 42-character address displayed',
      'ETH addresses lack built-in checksums',
      '!!One wrong character = lost funds FOREVER',
      '!Same clipboard attack risk as Bitcoin',
      'Verify the 0x address character by character',
    ],
  },
  {
    file: '17-eth-gas-chainid.png', flow: 'Ethereum Send', step: 'Gas Fee & Chain ID', accent: '#627EEA',
    device(o) { o.text(4, 4, 'Gas limit: 21000', 1); o.text(4, 16, 'Gas price: 20 Gwei', 1); o.hline(4, 28, 248); o.text(4, 34, 'Max fee:', 1); o.text(4, 46, '0.000420 ETH', 2) },
    appContext: 'Device shows gas parameters\nSimple sends: gas limit = 21000\nContract calls: gas limit varies\nChain ID shown on next screen',
    insight: [
      'Gas limit 21000 = simple ETH transfer',
      'Higher gas limit = contract interaction',
      '!Unusually high gas = overpaying',
      '!Low gas = may fail but still costs fee',
      'Chain ID 1=ETH, 137=Polygon, 42161=Arbitrum',
      '!!Wrong chain = funds on wrong network',
    ],
  },
]

export const TOKEN_FLOW: PageDef[] = [
  {
    file: '18-token-contract.png', flow: 'ERC-20 Token Transfer', step: 'Verify Token Contract', accent: '#8B5CF6',
    device(o) { o.text(4, 4, 'Token transfer:', 1); o.text(4, 16, 'USDC (USD Coin)', 1); o.hline(4, 26, 248); o.text(4, 30, '0xA0b86991c6218b36', 1); o.text(4, 40, 'c1d19D4a2e9Eb0cE36', 1); o.centerText(54, '[Hold to confirm]', 1) },
    appContext: 'App: Signing approval overlay\nBadge: "ERC-20 Transfer"\nShows token name + contract address',
    insight: [
      'CONTRACT ADDRESS is the only reliable token ID',
      'Fake tokens with same name exist!',
      '!Cross-reference contract address with Etherscan',
      '!!Token spoofing: fake USDC at different address',
      'Device shows the ACTUAL contract being called',
    ],
  },
]

export const EIP712_FLOW: PageDef[] = [
  {
    file: '19-eip712-permit.png', flow: 'EIP-712 Typed Data', step: 'Token Permit Signature', accent: '#EF4444',
    device(o) { o.text(4, 4, 'Permit:', 1); o.text(4, 16, 'Token:   USDC', 1); o.text(4, 26, 'Spender: 0x0000...2D4', 1); o.text(4, 36, 'Amount:  1000.00', 1); o.text(4, 46, 'Deadline: 2025-12-31', 1); o.centerText(58, '[Hold to sign]', 1) },
    appContext: 'App: Signing approval overlay\nBadge: "EIP-712 Typed Data"\nDomain: Uniswap\nShows decoded permit fields',
    insight: [
      'Permit = off-chain token spending approval',
      'Verify: token, amount, spender, deadline',
      '!!MAX_UINT256 amount = UNLIMITED spending!',
      '!!Far-future deadline = never expires',
      '!!Permit phishing: sign once, attacker drains later',
      'Only sign permits for protocols you trust',
    ],
  },
]

export const SOLANA_FLOW: PageDef[] = [
  {
    file: '24-sol-send-address-before.png', flow: 'Solana Send (BEFORE fix)', step: 'Truncated Address — SECURITY RISK', accent: '#EF4444',
    device(o) {
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 14, 248)
      o.text(4, 20, 'Send 0.001000 SOL', 1)
      o.text(4, 32, 'to CD9R...d536?', 1)
      o.hline(4, 44, 248)
      o.centerText(52, '[Hold to confirm]', 1)
    },
    appContext: 'OLD firmware: solana_pubkeyToShort()\nMiddle-truncated: first 4 + "..." + last 4\nAttacker crafts matching prefix+suffix\nUser cannot verify the real address',
    insight: [
      '!!BEFORE: "CD9R...d536" — only 8 chars visible',
      '!!Attacker crafts key with same prefix+suffix',
      '!!User sees identical truncated address, approves',
      '!Middle-ellipsis hides 36 characters of the address',
      'This is the #1 address spoofing vector',
    ],
  },
  {
    file: '25-sol-send-address-after.png', flow: 'Solana Send (AFTER fix)', step: 'Full Address Display', accent: '#14F195',
    device(o) {
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 14, 248)
      o.text(4, 20, 'Send 0.001000 SOL to', 1)
      o.text(4, 32, 'CD9R61PMZFafFQ9QsPZA', 1)
      o.text(4, 42, 'Tm74hFyEvYaNtEtwGvvHmRYH?', 1)
      o.centerText(56, '[Hold to confirm]', 1)
    },
    appContext: 'NEW firmware: solana_pubkeyToStr()\nFull 44-char base58 address displayed\nUser can verify every character\nMatches Ethereum full-address policy',
    insight: [
      'AFTER: full 44-character address shown',
      'User can compare every character with app',
      'Matches Ethereum address display security policy',
      '!Address wraps to 2 lines on 256px OLED — expected',
      'Spoofing attack now requires matching ALL 44 chars',
    ],
  },
  {
    file: '26-sol-spl-transfer.png', flow: 'Solana SPL Token', step: 'SPL Transfer — Full Address', accent: '#14F195',
    device(o) {
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 14, 248)
      o.text(4, 20, 'Send 1000.00 USDC to', 1)
      o.text(4, 32, '7UX2i7SucgLMQcfZ75s3', 1)
      o.text(4, 42, 'VFmb6TkJo5vYBhMNiXJj?', 1)
      o.centerText(56, '[Hold to confirm]', 1)
    },
    appContext: 'SPL Token transfer with metadata\nToken info: symbol + decimals from host\nFull recipient ATA address on device\nSame full-address policy as native SOL',
    insight: [
      'SPL token recipient shows FULL address',
      'Token symbol + decimals from host metadata',
      'Same spoofing protection as native SOL transfers',
      '!Verify token contract is the real one (USDC, etc)',
    ],
  },
  {
    file: '27-sol-unknown-program.png', flow: 'Solana Unknown Instruction', step: 'Unknown Program — Full ID', accent: '#F59E0B',
    device(o) {
      o.text(4, 4, 'Instr 1/1', 1)
      o.hline(4, 14, 248)
      o.text(4, 20, 'Unknown instruction', 1)
      o.text(4, 30, 'to program', 1)
      o.text(4, 40, 'JUP6LkMUje1knDR9nToc', 1)
      o.text(4, 50, '2v2sJY4jat4A2QU1jP1L', 1)
    },
    appContext: 'Unrecognized program ID — blind sign flow\nFull program ID lets user verify on Solscan\nOLD: "JUP6...1P1L" — unverifiable',
    insight: [
      'Unknown programs display FULL program ID',
      '!User can look up the program on Solscan/Explorer',
      '!!OLD: truncated ID was unverifiable',
      'Cannot verify instruction contents — use caution',
    ],
  },
]

export const THORCHAIN_FLOW: PageDef[] = [
  {
    file: '20-thorchain-swap-memo.png', flow: 'THORChain Swap', step: 'Verify Swap Memo', accent: '#23DCC8',
    device(o) { o.text(4, 4, 'Memo:', 1); o.text(4, 14, 'SWAP:ETH.ETH:', 1); o.text(4, 24, '0x742d35Cc6634C053', 1); o.text(4, 34, ':1500000', 1); o.hline(4, 46, 248); o.centerText(54, '[Hold to confirm]', 1) },
    appContext: 'App: "Confirming on KeepKey..."\nTHORChain swap via memo instruction\nMemo format: SWAP:CHAIN.ASSET:DEST:LIMIT',
    insight: [
      'Memo controls the ENTIRE swap operation',
      'SWAP:ETH.ETH = swap to Ethereum',
      'Destination address = where you receive',
      ':1500000 = minimum output (slip protection)',
      '!!Memo manipulation: attacker changes YOUR address',
      '!Verify destination address in memo matches yours',
    ],
  },
]

export const RECOVERY_FLOW: PageDef[] = [
  {
    file: '21-recovery-cipher.png', flow: 'Seed Recovery', step: 'Cipher Word Entry', accent: '#23DCC8',
    device(o) { o.text(4, 4, 'Word 1', 1); o.text(4, 14, 'Char 1', 1); o.cipherGrid('abcdefghijklm'.split(''), 'tmarwdsebpcnk'.split('')); o.text(4, 46, 'Enter by', 1); o.text(4, 56, 'position', 1) },
    appContext: 'Recovery overlay (z-index 2000)\n"Word 1 of 12 — Character 1"\n6-column a-z letter grid\nDelete / Done buttons',
    insight: [
      'DEVICE: scrambled alphabet in 2x13 grid',
      'APP: ordered a-z letter buttons',
      'Tap position on app → device reads scrambled letter',
      '!Grid re-scrambles for EVERY character entry',
      '!!Keyloggers capture meaningless positions',
      'After enough chars, device auto-completes the word',
    ],
  },
]

export const PASSPHRASE_FLOW: PageDef[] = [
  {
    file: '22-passphrase-entry.png', flow: 'Passphrase', step: 'Hidden Wallet Access', accent: '#8B5CF6',
    device(o) { o.centerText(14, 'Enter passphrase', 2); o.centerText(36, 'on your computer', 1); o.centerText(50, 'then confirm here', 1) },
    appContext: 'Passphrase overlay (z-index 2000)\nMasked text input with show/hide toggle\nSubmit sends to device for confirmation\n"If you forget this, funds are unrecoverable"',
    insight: [
      'Passphrase creates a SEPARATE wallet from same seed',
      'Empty passphrase "" is valid (default wallet)',
      '!!Wrong passphrase = different EMPTY wallet, NOT error',
      '!!There is NO recovery for a forgotten passphrase',
      '!Device confirms passphrase after you type it on computer',
    ],
  },
]

export const MGMT_FLOW: PageDef[] = [
  {
    file: '23-device-wipe.png', flow: 'Device Management', step: 'Wipe Device', accent: '#EF4444',
    device(o) { o.centerText(4, 'WIPE DEVICE?', 2); o.hline(4, 22, 248); o.text(4, 28, 'All data will be erased.', 1); o.text(4, 38, 'This cannot be undone.', 1); o.centerText(52, '[Hold button to wipe]', 1) },
    appContext: 'Settings drawer → Security section\nDouble-confirm dialog in app\nThen device requires button hold to wipe',
    insight: [
      'DESTRUCTIVE: permanently deletes all keys',
      '!!WITHOUT your seed phrase, ALL FUNDS ARE LOST',
      '!Verify you have your written seed backup FIRST',
      'Used for: factory reset, selling device, security',
    ],
  },
]

// ═══════════════════════════════════════════════════════════════════════
// SECTION 5: Main — generate all pages
// ═══════════════════════════════════════════════════════════════════════

async function main() {
  mkdirSync(PAGES_DIR, { recursive: true })

  const allFlows: { name: string; pages: PageDef[] }[] = [
    { name: 'Setup', pages: SETUP_FLOW },
    { name: 'PIN', pages: PIN_FLOW },
    { name: 'BTC', pages: BTC_FLOW },
    { name: 'ETH', pages: ETH_FLOW },
    { name: 'Token', pages: TOKEN_FLOW },
    { name: 'EIP-712', pages: EIP712_FLOW },
    { name: 'Solana', pages: SOLANA_FLOW },
    { name: 'THORChain', pages: THORCHAIN_FLOW },
    { name: 'Recovery', pages: RECOVERY_FLOW },
    { name: 'Passphrase', pages: PASSPHRASE_FLOW },
    { name: 'Management', pages: MGMT_FLOW },
  ]

  const allPages = allFlows.flatMap(f => f.pages)

  for (let i = 0; i < allPages.length; i++) {
    const p = allPages[i]
    // Find which flow this page belongs to for step counting
    const flow = allFlows.find(f => f.pages.includes(p))!
    const stepIdx = flow.pages.indexOf(p)
    const totalSteps = flow.pages.length

    await buildPage(p.file, p.flow, p.step, stepIdx, totalSteps, p.accent, p.device, p.appContext, p.insight)
    process.stdout.write(`  ${p.file}\n`)
  }

  console.log(`\n  ${allPages.length} composite flow pages → ${relative(process.cwd(), PAGES_DIR)}/`)
}

// Only run when invoked directly (not when imported by generate-zoo-report.ts)
if (import.meta.main) {
  console.log('\nKeepKey Zoo — Generating release flow pages...\n')
  main().catch(e => { console.error(e); process.exit(1) })
}
