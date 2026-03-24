#!/usr/bin/env bun
/**
 * generate-zoo-report.ts  -- Generates a PDF zoo report for firmware PRs.
 *
 * Renders all zoo OLED screen mockups into a polished PDF with:
 *   - Title page with PR metadata
 *   - Per-flow pages with device screen mockup + verification checklist
 *   - Security analysis summary
 *
 * Usage:
 *   bun scripts/generate-zoo-report.ts \
 *     --firmware-dir modules/keepkey-firmware \
 *     --output artifacts/zoo-report.pdf \
 *     [--pr-number 79] [--pr-title "fix(solana): full addresses"]
 *
 * Output: projects/keepkey-vault/docs/zoo/pages/ (PNGs) + artifacts/zoo-report.pdf
 */
import { mkdirSync, existsSync, readFileSync } from 'fs'
import { join, dirname } from 'path'
import sharp from 'sharp'
import {
  OLED, encodePNG, buildPage,
  SETUP_FLOW, PIN_FLOW, BTC_FLOW, ETH_FLOW, TOKEN_FLOW, EIP712_FLOW,
  EVM_MULTICHAIN_FLOW, TRON_FLOW, TON_FLOW, ZCASH_FLOW,
  RIPPLE_FLOW, COSMOS_FLOW, MAYACHAIN_FLOW, BINANCE_FLOW, BIP85_FLOW,
  SOLANA_FLOW, THORCHAIN_FLOW, RECOVERY_FLOW, PASSPHRASE_FLOW, MGMT_FLOW,
  type PageDef,
} from './generate-zoo'

// ═══════════════════════════════════════════════════════════════════════
// CLI arg parser
// ═══════════════════════════════════════════════════════════════════════

function parseArgs() {
  const args = process.argv.slice(2)
  const opts: Record<string, string> = {}
  for (const arg of args) {
    const m = arg.match(/^--(\S+?)=(.+)$/)
    if (m) opts[m[1]] = m[2]
  }
  return {
    firmwareDir: opts['firmware-dir'] || 'modules/keepkey-firmware',
    output: opts['output'] || 'artifacts/zoo-report.pdf',
    prNumber: opts['pr-number'] || '',
    prTitle: opts['pr-title'] || '',
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Flow metadata (for PDF annotations)
// ═══════════════════════════════════════════════════════════════════════

interface FlowMeta {
  name: string
  pages: PageDef[]
  accent: string
  securityLevel: 'critical' | 'high' | 'medium' | 'low'
  why: string
}

// Only verified flows  -- text confirmed from firmware confirm() source code.
// Font rendering + wrapping is approximate. Awaiting emulator for pixel-perfect.
const ALL_FLOWS: FlowMeta[] = ([
  {
    name: 'Bitcoin Send',
    pages: BTC_FLOW,
    accent: '#F7931A',
    securityLevel: 'high',
    why: 'Text verified from app_confirm.c:152 (confirm_transaction_output) and app_confirm.c:206 (confirm_transaction). Font/wrapping approximate.',
  },
  {
    name: 'Ethereum',
    pages: ETH_FLOW,
    accent: '#627EEA',
    securityLevel: 'high',
    why: 'Verified: confirm_transfer_output (app_confirm.c:134), layoutEthereumFee (ethereum.c:787), Sign Message (fsm_msg_ethereum.h:265), Confirm Data (ethereum.c:772), Blind block (ethereum.c:760).',
  },
  {
    name: 'EIP-712 Typed Data',
    pages: EIP712_FLOW,
    accent: '#EF4444',
    securityLevel: 'critical',
    why: 'CRITICAL: Firmware shows HASH DIGESTS only — NOT decoded permit fields. User sees hex, cannot verify token/amount/spender/deadline. Blind signing risk for EIP-712.',
  },
  {
    name: 'ERC-20 Tokens',
    pages: TOKEN_FLOW,
    accent: '#8B5CF6',
    securityLevel: 'high',
    why: 'Verified: ethereum.c:726-748 (layoutEthereumConfirmTx). Token transfer, approve, unlimited unlock, revoke. Token symbol from tokenByChainAddress().',
  },
  {
    name: 'Solana',
    pages: SOLANA_FLOW,
    accent: '#14F195',
    securityLevel: 'high',
    why: 'Text verified from fsm_msg_solana.h:57. Title "Instr N/M" from line 49. Before/after shows pubkeyToShort vs pubkeyToStr.',
  },
  {
    name: 'THORChain Swap',
    pages: THORCHAIN_FLOW,
    accent: '#23DCC8',
    securityLevel: 'medium',
    why: 'Text verified from fsm_msg_thorchain.h:189. confirm(ConfirmMemo, "Memo", "%s", memo). Font/wrapping approximate.',
  },
  {
    name: 'TRON',
    pages: TRON_FLOW,
    accent: '#EF0027',
    securityLevel: 'high',
    why: 'Verified: fsm_msg_tron.h. TRX transfer, 12 hardcoded TRC-20 tokens, unknown token, contract call, blind sign, fee limit. Full base58 addresses.',
  },
  {
    name: 'TON',
    pages: TON_FLOW,
    accent: '#0098EA',
    securityLevel: 'high',
    why: 'Verified: fsm_msg_ton.h. Clear-sign with hash verification, memo display, blind sign for deploy and opaque TXs. Full 48-char TON addresses.',
  },
  {
    name: 'Zcash Orchard',
    pages: ZCASH_FLOW,
    accent: '#F4B728',
    securityLevel: 'high',
    why: 'Verified: fsm_msg_zcash.h. Shielded-only, hybrid shield (transparent->Orchard), per-input signing. No recipient shown  -- Orchard hides by design.',
  },
  {
    name: 'Ripple (XRP)',
    pages: RIPPLE_FLOW,
    accent: '#23292F',
    securityLevel: 'medium',
    why: 'Verified: fsm_msg_ripple.h:99,112. Send with destination tag, transaction confirmation with fee.',
  },
  {
    name: 'Cosmos (ATOM)',
    pages: COSMOS_FLOW,
    accent: '#2E3148',
    securityLevel: 'medium',
    why: 'Verified: fsm_msg_cosmos.h. Send (confirm_transaction_output), redelegate, claim rewards.',
  },
  {
    name: 'Maya Protocol',
    pages: MAYACHAIN_FLOW,
    accent: '#3B82F6',
    securityLevel: 'medium',
    why: 'Verified: fsm_msg_mayachain.h:245. Sign TX with denom + chain_id.',
  },
  {
    name: 'Binance Chain',
    pages: BINANCE_FLOW,
    accent: '#F3BA2F',
    securityLevel: 'medium',
    why: 'Verified: fsm_msg_binance.h:176. Sign with chain_id confirmation.',
  },
  {
    name: 'BIP-85',
    pages: BIP85_FLOW,
    accent: '#8B5CF6',
    securityLevel: 'critical',
    why: 'CRITICAL: Displays derived child mnemonic on OLED. Never sent over USB. Incorrect display = user backs up wrong seed = permanent fund loss.',
  },
  {
    name: 'Device Setup',
    pages: SETUP_FLOW,
    accent: '#6366F1',
    securityLevel: 'critical',
    why: 'CRITICAL: Seed generation and display. Source: reset.c. Seed words shown on OLED — only opportunity to back up. Incorrect backup = permanent fund loss.',
  },
  {
    name: 'PIN Entry',
    pages: PIN_FLOW,
    accent: '#6366F1',
    securityLevel: 'critical',
    why: 'CRITICAL: PIN protects all device operations. Randomized 3x3 grid — host never sees digit positions. Wrong PIN = exponential backoff. Remove PIN = device unprotected.',
  },
  {
    name: 'Recovery Cipher',
    pages: RECOVERY_FLOW,
    accent: '#6366F1',
    securityLevel: 'critical',
    why: 'CRITICAL: Seed recovery entry. Cipher grid prevents host from learning seed words. Invalid word rejection (7.14.0). Incorrect recovery = wrong wallet or lost funds.',
  },
  {
    name: 'Passphrase',
    pages: PASSPHRASE_FLOW,
    accent: '#6366F1',
    securityLevel: 'critical',
    why: 'CRITICAL: Passphrase extends seed derivation. Wrong passphrase = different wallet (funds inaccessible). Empty passphrase is valid. Confirmation shown on device.',
  },
  {
    name: 'Device Management',
    pages: MGMT_FLOW,
    accent: '#EF4444',
    securityLevel: 'critical',
    why: 'CRITICAL: Wipe destroys all keys irreversibly. Policy toggles gate blind-signing. Label/autolock are cosmetic but included for completeness.',
  },
  // TODO: Osmosis LP/swap ops (fsm_msg_osmosis.h)
  // TODO: EOS, Nano
] as FlowMeta[]).filter(f => f.pages.length > 0)

// ═══════════════════════════════════════════════════════════════════════
// Render zoo pages to PNG buffers
// ═══════════════════════════════════════════════════════════════════════

const ZOO_PAGES_DIR = join(import.meta.dir, '..', '..', 'zoo-output', 'pages')

async function renderAllPages(): Promise<Map<string, Buffer>> {
  mkdirSync(ZOO_PAGES_DIR, { recursive: true })

  const allPages = ALL_FLOWS.flatMap(f => f.pages)
  const buffers = new Map<string, Buffer>()

  for (const p of allPages) {
    const flow = ALL_FLOWS.find(f => f.pages.includes(p))!
    const stepIdx = flow.pages.indexOf(p)

    await buildPage(
      p.file, p.flow, p.step, stepIdx, flow.pages.length,
      p.accent, p.device, p.appContext, p.insight, p.qr,
    )

    // Read the generated PNG back
    const pngPath = join(ZOO_PAGES_DIR, p.file)
    buffers.set(p.file, readFileSync(pngPath))
  }

  return buffers
}

// ═══════════════════════════════════════════════════════════════════════
// PDF composition (follows swap-report.ts pattern)
// ═══════════════════════════════════════════════════════════════════════

function sanitize(text: string): string {
  return text.replace(/[^\x20-\x7E]/g, '?')
}

async function composePdf(
  pngBuffers: Map<string, Buffer>,
  opts: { prNumber: string; prTitle: string },
): Promise<Buffer> {
  const { PDFDocument, StandardFonts, rgb } = await import('pdf-lib')

  const doc = await PDFDocument.create()
  const font = await doc.embedFont(StandardFonts.Helvetica)
  const bold = await doc.embedFont(StandardFonts.HelveticaBold)

  const W = 612   // Letter portrait
  const H = 792
  const ML = 40
  const MR = 40
  const MT = 50

  const white = rgb(1, 1, 1)
  const gray = rgb(0.5, 0.5, 0.5)
  const dark = rgb(0.15, 0.15, 0.15)
  const brand = rgb(0.08, 0.94, 0.58)  // KeepKey green

  const severityColor = {
    critical: rgb(0.93, 0.27, 0.27),
    high: rgb(0.96, 0.62, 0.10),
    medium: rgb(0.95, 0.73, 0.13),
    low: rgb(0.22, 0.50, 0.92),
  }

  // ── Title Page ────────────────────────────────────────────────────

  let page = doc.addPage([W, H])
  let y = H - MT

  // Dark header bar
  page.drawRectangle({ x: 0, y: H - 120, width: W, height: 120, color: rgb(0.07, 0.07, 0.10) })
  page.drawRectangle({ x: 0, y: H - 123, width: W, height: 3, color: brand })

  page.drawText('KeepKey Firmware', { x: ML, y: H - 55, font: bold, size: 24, color: white })
  page.drawText('Screen Review Report', { x: ML, y: H - 80, font: bold, size: 16, color: brand })

  const dateStr = new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
  page.drawText(dateStr, { x: ML, y: H - 105, font, size: 10, color: rgb(0.6, 0.6, 0.6) })

  if (opts.prNumber) {
    page.drawText(`PR #${opts.prNumber}`, { x: W - MR - 80, y: H - 55, font: bold, size: 14, color: white })
  }

  y = H - 160

  if (opts.prTitle) {
    page.drawText(sanitize(opts.prTitle), { x: ML, y, font: bold, size: 13, color: dark })
    y -= 24
  }

  // Summary stats
  page.drawText('Report Contents', { x: ML, y, font: bold, size: 13, color: dark })
  y -= 20

  const totalPages = ALL_FLOWS.reduce((n, f) => n + f.pages.length, 0)
  const criticalFlows = ALL_FLOWS.filter(f => f.securityLevel === 'critical')
  const highFlows = ALL_FLOWS.filter(f => f.securityLevel === 'high')
  const pdfPageCount = totalPages + 3 // +cover +coverage accounting +overflow
  const stats = [
    `Flows covered: ${ALL_FLOWS.length}`,
    `Total screen mockups: ${totalPages}`,
    `PDF pages: ${pdfPageCount} (${totalPages} screens + 3 report pages)`,
    `Critical security flows: ${criticalFlows.length} (${criticalFlows.map(f => f.name).join(', ')})`,
    `High priority flows: ${highFlows.length}`,
    `Medium priority flows: ${ALL_FLOWS.filter(f => f.securityLevel === 'medium').length}`,
  ]
  for (const s of stats) {
    page.drawText(s, { x: ML + 10, y, font, size: 10, color: dark })
    y -= 15
  }

  y -= 20

  // Flow index table
  page.drawText('Flow Index', { x: ML, y, font: bold, size: 13, color: dark })
  y -= 18

  page.drawRectangle({ x: ML, y: y + 2, width: W - ML - MR, height: 16, color: rgb(0.92, 0.92, 0.94) })
  page.drawText('Flow', { x: ML + 5, y: y + 4, font: bold, size: 9, color: dark })
  page.drawText('Screens', { x: ML + 240, y: y + 4, font: bold, size: 9, color: dark })
  page.drawText('Security', { x: ML + 320, y: y + 4, font: bold, size: 9, color: dark })
  y -= 16

  for (const flow of ALL_FLOWS) {
    if (y < 60) { page = doc.addPage([W, H]); y = H - MT }
    page.drawText(flow.name, { x: ML + 5, y, font, size: 9, color: dark })
    page.drawText(String(flow.pages.length), { x: ML + 250, y, font, size: 9, color: dark })
    page.drawText(flow.securityLevel.toUpperCase(), {
      x: ML + 320, y, font: bold, size: 9,
      color: severityColor[flow.securityLevel],
    })
    y -= 14
  }

  // ── Coverage Accounting Page ─────────────────────────────────────

  page = doc.addPage([W, H])
  y = H - MT

  page.drawText('Coverage Accounting', { x: ML, y, font: bold, size: 16, color: dark })
  y -= 24

  page.drawText('Claim: Comprehensive review of all user-visible device screens in normal firmware operation.', {
    x: ML, y, font, size: 9, color: dark, maxWidth: W - ML - MR })
  y -= 28

  // Covered
  page.drawRectangle({ x: ML, y: y + 2, width: W - ML - MR, height: 16, color: rgb(0.85, 0.95, 0.85) })
  page.drawText('COVERED', { x: ML + 5, y: y + 4, font: bold, size: 9, color: rgb(0.1, 0.5, 0.1) })
  y -= 16
  const covered = [
    'Transaction confirmations: BTC, ETH, ERC-20, EIP-712, Solana, TRON, TON, Zcash, XRP, Cosmos, THORChain, Maya, Binance',
    'Address display: all chains with QR codes where applicable',
    'PIN entry: create, verify, change, remove, wrong PIN backoff',
    'Recovery cipher: character entry, auto-complete, invalid word rejection, prev-word display',
    'Seed generation: word count selection, all display pages',
    'Passphrase: waiting prompt, confirmation display, enable/disable',
    'Device management: wipe, label change, auto-lock, policy toggles',
    'Blind-sign warnings: all chains (Solana, TRON, TON, EVM)',
    'BIP-85: child mnemonic derivation (display-only)',
    'User rejection / action cancelled path',
  ]
  for (const item of covered) {
    if (y < 60) { page = doc.addPage([W, H]); y = H - MT }
    page.drawText(`  • ${item}`, { x: ML, y, font, size: 8, color: dark, maxWidth: W - ML - MR - 10 })
    y -= 12
  }

  y -= 12
  page.drawRectangle({ x: ML, y: y + 2, width: W - ML - MR, height: 16, color: rgb(0.95, 0.93, 0.85) })
  page.drawText('NOT YET COVERED', { x: ML + 5, y: y + 4, font: bold, size: 9, color: rgb(0.7, 0.5, 0.1) })
  y -= 16
  const notCovered = [
    'Bootloader / firmware update prompt screens',
    'Firmware flash progress bars',
    'Lock / unlock transition animations',
    'Screensaver / idle state',
    'Sign Identity (U2F/WebAuthn) confirmation',
    'Encrypt/decrypt message screens',
    'OMNI token confirmations',
    'Osmosis LP/swap-specific screens',
    'EOS action confirmations',
    'Nano address confirmation',
  ]
  for (const item of notCovered) {
    if (y < 60) { page = doc.addPage([W, H]); y = H - MT }
    page.drawText(`  • ${item}`, { x: ML, y, font, size: 8, color: dark, maxWidth: W - ML - MR - 10 })
    y -= 12
  }

  y -= 12
  page.drawRectangle({ x: ML, y: y + 2, width: W - ML - MR, height: 16, color: rgb(0.9, 0.9, 0.92) })
  page.drawText('OUT OF SCOPE', { x: ML + 5, y: y + 4, font: bold, size: 9, color: gray })
  y -= 16
  const outOfScope = [
    'Cryptographic correctness (key derivation, signature math)',
    'Transport internals (USB/HID/WebUSB protocol)',
    'Host-side software behavior (wallet apps, SDKs)',
    'Every possible coin/token variant (1000+ ERC-20 tokens)',
    'Timing / side-channel analysis',
    'Physical tamper resistance',
  ]
  for (const item of outOfScope) {
    if (y < 60) { page = doc.addPage([W, H]); y = H - MT }
    page.drawText(`  • ${item}`, { x: ML, y, font, size: 8, color: gray, maxWidth: W - ML - MR - 10 })
    y -= 12
  }

  // ── Per-Flow Pages ────────────────────────────────────────────────

  for (const flow of ALL_FLOWS) {
    for (let i = 0; i < flow.pages.length; i++) {
      const pageDef = flow.pages[i]
      page = doc.addPage([W, H])
      y = H - MT

      // Flow header bar
      const accentRgb = hexToRgb(flow.accent)
      page.drawRectangle({ x: 0, y: H - 45, width: W, height: 45, color: rgb(0.07, 0.07, 0.10) })
      page.drawRectangle({ x: 0, y: H - 48, width: W, height: 3, color: rgb(accentRgb.r, accentRgb.g, accentRgb.b) })

      page.drawText(flow.name, { x: ML, y: H - 30, font: bold, size: 14, color: white })
      page.drawText(`${i + 1} / ${flow.pages.length}`, { x: W - MR - 40, y: H - 30, font, size: 11, color: rgb(0.6, 0.6, 0.6) })
      page.drawText(pageDef.step, { x: ML, y: H - 42, font, size: 9, color: rgb(0.7, 0.7, 0.7) })

      y = H - 70

      // Embed the composite PNG (scaled to fit page width)
      const pngBuf = pngBuffers.get(pageDef.file)
      if (pngBuf) {
        const pngImage = await doc.embedPng(pngBuf)
        const imgW = W - ML - MR
        const imgH = (pngImage.height / pngImage.width) * imgW

        page.drawImage(pngImage, { x: ML, y: y - imgH, width: imgW, height: imgH })
        y -= imgH + 15
      }

      // "Why This Matters" section
      if (y > 200) {
        page.drawText('Why This Matters', { x: ML, y, font: bold, size: 11, color: dark })
        y -= 16

        // Word-wrap the why text
        const words = flow.why.split(' ')
        let line = ''
        const maxLineW = W - ML - MR
        for (const word of words) {
          const test = line ? `${line} ${word}` : word
          if (font.widthOfTextAtSize(test, 9) > maxLineW) {
            page.drawText(line, { x: ML + 5, y, font, size: 9, color: dark })
            y -= 12
            line = word
          } else {
            line = test
          }
        }
        if (line) {
          page.drawText(line, { x: ML + 5, y, font, size: 9, color: dark })
          y -= 12
        }
        y -= 8
      }

      // Security badge
      if (y > 80) {
        const badge = `SECURITY: ${flow.securityLevel.toUpperCase()}`
        const badgeW = bold.widthOfTextAtSize(badge, 10) + 16
        page.drawRectangle({
          x: ML, y: y - 2, width: badgeW, height: 16, borderRadius: 3,
          color: severityColor[flow.securityLevel],
        })
        page.drawText(badge, { x: ML + 8, y: y + 2, font: bold, size: 10, color: white })
        y -= 24
      }

      // Page number footer
      const pageIdx = doc.getPageCount()
      page.drawText(`Page ${pageIdx}`, { x: W / 2 - 20, y: 25, font, size: 9, color: gray })
    }
  }

  // ── Security Summary Page ─────────────────────────────────────────

  page = doc.addPage([W, H])
  y = H - MT

  page.drawRectangle({ x: 0, y: H - 50, width: W, height: 50, color: rgb(0.07, 0.07, 0.10) })
  page.drawRectangle({ x: 0, y: H - 53, width: W, height: 3, color: rgb(0.93, 0.27, 0.27) })
  page.drawText('Security Analysis Summary', { x: ML, y: H - 35, font: bold, size: 16, color: white })

  y = H - 80

  const policies = [
    {
      title: 'Address Display Policy',
      text: 'All cryptocurrency addresses MUST be displayed in full on the device screen. Middle-truncation (XXXX...XXXX) is a known spoofing vector  -- attackers can craft keys with matching prefix and suffix. This applies to: BTC (bech32), ETH (hex), Solana (base58), Cosmos (bech32), and all other chains.',
      level: 'critical' as const,
    },
    {
      title: 'Amount & Fee Verification',
      text: 'Transaction amounts and fees must be clearly displayed with correct decimal placement. A misplaced decimal (0.1 vs 1.0) is a 10x financial error. Fee siphoning attacks inflate fees to benefit colluding miners.',
      level: 'critical' as const,
    },
    {
      title: 'Memo & Data Transparency',
      text: 'Transaction memos (THORChain, Cosmos) and calldata (Ethereum) control the operation. Memo manipulation can redirect swap output to an attacker address. Raw hex data should show enough bytes for identification.',
      level: 'high' as const,
    },
    {
      title: 'Chain & Network Identification',
      text: 'Chain ID must be prominently displayed to prevent wrong-network sends. EVM chains share the same address format  -- only the chain ID distinguishes Ethereum from Polygon/Arbitrum/etc.',
      level: 'high' as const,
    },
    {
      title: 'Typed Data & Permit Signing',
      text: 'EIP-712 typed data signing (permits, approvals) is the #1 phishing vector in DeFi. Unlimited approvals (MAX_UINT256) and far-future deadlines must trigger prominent warnings.',
      level: 'critical' as const,
    },
  ]

  for (const p of policies) {
    if (y < 120) { page = doc.addPage([W, H]); y = H - MT }

    // Policy title with severity badge
    const badge = p.level.toUpperCase()
    const badgeW = bold.widthOfTextAtSize(badge, 8) + 12
    page.drawRectangle({ x: ML, y: y - 1, width: badgeW, height: 14, color: severityColor[p.level] })
    page.drawText(badge, { x: ML + 6, y: y + 2, font: bold, size: 8, color: white })
    page.drawText(p.title, { x: ML + badgeW + 8, y, font: bold, size: 11, color: dark })
    y -= 18

    // Word-wrap the policy text
    const words = p.text.split(' ')
    let line = ''
    const maxW = W - ML - MR - 10
    for (const word of words) {
      const test = line ? `${line} ${word}` : word
      if (font.widthOfTextAtSize(test, 9) > maxW) {
        page.drawText(line, { x: ML + 5, y, font, size: 9, color: dark })
        y -= 12
        line = word
      } else {
        line = test
      }
    }
    if (line) {
      page.drawText(line, { x: ML + 5, y, font, size: 9, color: dark })
      y -= 12
    }
    y -= 16
  }

  // Final page number
  const lastIdx = doc.getPageCount()
  page.drawText(`Page ${lastIdx}`, { x: W / 2 - 20, y: 25, font, size: 9, color: gray })

  const pdfBytes = await doc.save()
  return Buffer.from(pdfBytes)
}

function hexToRgb(hex: string) {
  const h = hex.replace('#', '')
  return {
    r: parseInt(h.slice(0, 2), 16) / 255,
    g: parseInt(h.slice(2, 4), 16) / 255,
    b: parseInt(h.slice(4, 6), 16) / 255,
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════

async function main() {
  const opts = parseArgs()

  console.log('\nKeepKey Zoo Report  -- Generating screen review PDF...\n')

  // Step 1: Render all zoo pages to PNG
  console.log('  Rendering OLED mockups...')
  const pngBuffers = await renderAllPages()
  console.log(`  ${pngBuffers.size} pages rendered`)

  // Step 2: Compose PDF
  console.log('  Composing PDF report...')
  const pdfBuffer = await composePdf(pngBuffers, {
    prNumber: opts.prNumber,
    prTitle: opts.prTitle,
  })

  // Step 3: Write output
  const outDir = dirname(opts.output)
  mkdirSync(outDir, { recursive: true })
  await Bun.write(opts.output, pdfBuffer)

  const sizeMb = (pdfBuffer.length / (1024 * 1024)).toFixed(1)
  console.log(`\n  PDF: ${opts.output} (${sizeMb} MB, ${ALL_FLOWS.reduce((n, f) => n + f.pages.length, 0)} screens)`)
  console.log('  Done.\n')
}

main().catch(e => { console.error(e); process.exit(1) })
