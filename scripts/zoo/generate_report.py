#!/usr/bin/env python3
"""
generate_report.py — Firmware review PDF from real KeepKey emulator screenshots.

Generates a human-readable firmware release document with:
  - Executive summary of firmware capabilities
  - Per-chain sections with real OLED captures + security context
  - Feature highlights (what changed, why it matters)
  - Recovery cipher UX walkthrough

Usage:
  python3 generate_report.py \
    --screenshots /tmp/zoo-test \
    --output artifacts/firmware-review.pdf \
    --version "7.14.0"
"""
import os
import sys
import json
import argparse
import glob
from datetime import datetime

from fpdf import FPDF
from PIL import Image, ImageDraw


def safe(text):
    """Strip non-latin1 chars for PDF core fonts."""
    return str(text).encode('latin-1', errors='replace').decode('latin-1')


# ═══════════════════════════════════════════════════════════════════════
# Report content — what goes on each page
# ═══════════════════════════════════════════════════════════════════════

CHAIN_SECTIONS = [
    {
        'id': 'btc',
        'title': 'Bitcoin (BTC)',
        'accent': (247, 147, 26),
        'security': 'CRITICAL',
        'screenshots': ['btc-address.png', 'btc-segwit.png'],
        'what': 'Full address display with QR code. Supports legacy (P2PKH), SegWit (P2SH-P2WPKH), and native SegWit (bech32) address types.',
        'why': 'Address verification on the device screen is the primary defense against clipboard hijacking malware. The QR code enables air-gapped verification with a phone camera.',
        'details': [
            'Legacy, SegWit, and native SegWit addresses supported',
            'QR code rendered on device for mobile verification',
            'Full address shown - no truncation',
            'Account and address index displayed',
        ],
    },
    {
        'id': 'eth',
        'title': 'Ethereum (ETH)',
        'accent': (98, 126, 234),
        'security': 'CRITICAL',
        'screenshots': ['eth-address.png'],
        'what': 'Full 42-character hex address display. Supports EIP-155 chain ID for all EVM networks (Polygon, Arbitrum, Optimism, Avalanche, BSC, Base).',
        'why': 'ETH addresses lack built-in checksums. The device screen is the only reliable verification point. Chain ID display prevents cross-network sends.',
        'details': [
            'Full 0x-prefixed address (42 chars)',
            'EIP-155 chain ID for multi-chain EVM support',
            'Same derivation path m/44\'/60\'/0\'/0/0 for all EVM chains',
            'Gas price and limit shown during signing',
        ],
    },
    {
        'id': 'solana',
        'title': 'Solana (SOL)',
        'accent': (20, 241, 149),
        'security': 'CRITICAL',
        'new': True,
        'screenshots': ['solana-address.png'],
        'what': 'Full 44-character base58 address display. Native SOL transfers, SPL token transfers, and unknown program instruction handling with clear-signing.',
        'why': 'Solana base58 addresses are 32-44 characters. Middle-truncation (XXXX...XXXX) was a spoofing vector in older firmware -- attackers could craft keys with matching prefix+suffix. Full display eliminates this.',
        'details': [
            'Full 44-character base58 address (no truncation)',
            'Native SOL and SPL token transfer parsing',
            'Unknown programs show full program ID for verification',
            'Transaction instruction count displayed',
        ],
    },
    {
        'id': 'cosmos',
        'title': 'Cosmos (ATOM)',
        'accent': (100, 100, 200),
        'security': 'HIGH',
        'screenshots': ['cosmos-address.png'],
        'what': 'Cosmos bech32 address display with full address verification. Supports MsgSend with amount, recipient, and memo.',
        'why': 'Cosmos addresses use bech32 encoding with chain-specific prefixes. Full display ensures the user verifies the correct chain and address.',
        'details': [
            'Full bech32 address with cosmos1... prefix',
            'Amount, recipient, memo shown during signing',
            'QR code for mobile verification',
        ],
    },
    {
        'id': 'thorchain',
        'title': 'THORChain (RUNE)',
        'accent': (35, 220, 200),
        'security': 'HIGH',
        'screenshots': ['thorchain-address.png'],
        'what': 'THORChain address display and swap transaction signing with full memo verification.',
        'why': 'THORChain swap memos control the entire swap operation. Memo manipulation can redirect funds to an attacker address. Full memo display is essential.',
        'details': [
            'Full thor1... bech32 address',
            'Swap memo shown in full during signing',
            'Amount and fee verification',
        ],
    },
    {
        'id': 'maya',
        'title': 'Maya Protocol (CACAO)',
        'accent': (60, 180, 220),
        'security': 'HIGH',
        'screenshots': ['maya-address.png'],
        'what': 'Maya Protocol address display and cross-chain swap signing.',
        'why': 'Maya is a THORChain fork -- same memo-based swap architecture requires full memo verification.',
        'details': [
            'Full maya1... bech32 address',
            'Cross-chain swap memo verification',
        ],
    },
    {
        'id': 'osmosis',
        'title': 'Osmosis (OSMO)',
        'accent': (180, 80, 220),
        'security': 'HIGH',
        'screenshots': ['osmosis-address.png'],
        'what': 'Osmosis address display with IBC transfer and LP operation support.',
        'why': 'Osmosis IBC transfers cross chain boundaries. Full address and memo verification prevents fund loss to wrong chains.',
        'details': [
            'Full osmo1... bech32 address',
            'IBC transfer memo support',
        ],
    },
    {
        'id': 'xrp',
        'title': 'Ripple (XRP)',
        'accent': (35, 160, 230),
        'security': 'HIGH',
        'screenshots': ['xrp-address.png'],
        'what': 'XRP address display with destination tag support.',
        'why': 'XRP destination tags route funds to specific accounts on exchanges. Missing or wrong tags cause permanent fund loss.',
        'details': [
            'Full r... address display',
            'Destination tag shown when present',
            'Amount in drops converted to XRP',
        ],
    },
    {
        'id': 'ltc',
        'title': 'Litecoin (LTC)',
        'accent': (190, 190, 190),
        'security': 'HIGH',
        'screenshots': ['ltc-address.png'],
        'what': 'Litecoin address display with legacy and SegWit support.',
        'why': 'Same UTXO model as Bitcoin. Full address verification prevents address substitution attacks.',
        'details': ['Full L.../M.../ltc1... address with QR code'],
    },
    {
        'id': 'bch',
        'title': 'Bitcoin Cash (BCH)',
        'accent': (140, 200, 60),
        'security': 'HIGH',
        'screenshots': ['bch-address.png'],
        'what': 'Bitcoin Cash CashAddr format display.',
        'why': 'BCH and BTC share similar address formats. Device shows the coin name to prevent cross-chain sends.',
        'details': ['CashAddr format with coin identification'],
    },
    {
        'id': 'doge',
        'title': 'Dogecoin (DOGE)',
        'accent': (200, 180, 50),
        'security': 'HIGH',
        'screenshots': ['doge-address.png'],
        'what': 'Dogecoin address display with full verification.',
        'why': 'UTXO chain with Bitcoin-derived address format. Device verification prevents address swaps.',
        'details': ['Full D... address with QR code'],
    },
    {
        'id': 'dash',
        'title': 'Dash (DASH)',
        'accent': (0, 140, 230),
        'security': 'HIGH',
        'screenshots': ['dash-address.png'],
        'what': 'Dash address display.',
        'why': 'UTXO chain requiring device-side address verification.',
        'details': ['Full X... address with QR code'],
    },
]

FEATURE_SECTIONS = [
    {
        'id': 'recovery-cipher',
        'title': 'Recovery Cipher (Seed Entry)',
        'accent': (20, 241, 149),
        'security': 'CRITICAL',
        'new_in_release': True,
        'screenshots': {
            'dir': 'recovery-cipher-v10',
            'picks': ['01-recovery-reminder.png', '02-w01-c01-cipher-initial.png',
                       '07-w02-c01-cipher-initial.png', '63-w12-c01-cipher-initial.png',
                       '68-recovery-success.png'],
        },
        'what': 'Character-by-character seed phrase entry using a scrambled cipher grid. Previous completed word now displayed below current word progress (new in 7.14.0).',
        'why': 'The cipher grid reshuffles after every keystroke, preventing keylogger and screen-watching attacks. The new previous-word display (e.g. "11: anger") helps users track their position without losing context during the tedious 12/24 word entry process.',
        'highlights': [
            'NEW: Previous completed word shown below current progress',
            'Full auto-completed BIP39 word displayed (not truncated)',
            'Cipher grid reshuffles every character entry',
            'Auto-complete after 3-4 chars when unique BIP39 match found',
            'Per-word BIP39 validation rejects invalid words immediately',
        ],
    },
]

SECURITY_COLORS = {
    'CRITICAL': (220, 50, 50),
    'HIGH': (240, 160, 20),
    'MEDIUM': (240, 190, 30),
}


# ═══════════════════════════════════════════════════════════════════════
# PDF Builder
# ═══════════════════════════════════════════════════════════════════════

class FirmwareReport(FPDF):

    def __init__(self, version='7.14.0'):
        super().__init__(orientation='P', unit='mm', format='letter')
        self.fw_version = version
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        if self.page_no() <= 1:
            return
        self.set_font('Helvetica', '', 7)
        self.set_text_color(140, 140, 140)
        self.cell(0, 4, safe(f'KeepKey Firmware {self.fw_version} - Screen Review'), align='L')
        self.ln(6)

    def footer(self):
        self.set_y(-10)
        self.set_font('Helvetica', '', 7)
        self.set_text_color(160, 160, 160)
        self.cell(0, 4, f'Page {self.page_no()}', align='C')

    def _badge(self, x, y, text, color):
        self.set_fill_color(*color)
        w = self.get_string_width(text) + 6
        self.rect(x, y, w, 5, 'F')
        self.set_xy(x + 3, y + 0.5)
        self.set_font('Helvetica', 'B', 7)
        self.set_text_color(255, 255, 255)
        self.cell(0, 4, text)

    def _section_header(self, title, accent, security=None, is_new=False):
        self.set_fill_color(18, 18, 26)
        self.rect(0, self.get_y(), 216, 12, 'F')
        self.set_fill_color(*accent)
        self.rect(0, self.get_y() + 12, 216, 0.6, 'F')
        self.set_xy(10, self.get_y() + 2)
        self.set_font('Helvetica', 'B', 12)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, safe(title))
        if is_new:
            self._badge(self.get_string_width(title) + 16, self.get_y() + 3, 'NEW', (20, 180, 80))
        if security:
            sc = SECURITY_COLORS.get(security, (100, 100, 100))
            self.set_xy(180, self.get_y())
            self.set_font('Helvetica', 'B', 8)
            self.set_text_color(*sc)
            self.cell(0, 8, security)
        self.set_y(self.get_y() + 15)

    def _embed_screenshot(self, path, caption=None):
        """Embed a real emulator screenshot with device bezel."""
        if not os.path.exists(path):
            return
        try:
            img = Image.open(path)
            # Add black bezel
            pw, ph = img.width + 16, img.height + 12
            bezel = Image.new('RGB', (pw, ph), (0, 0, 0))
            bezel.paste(img, (8, 6))
            draw = ImageDraw.Draw(bezel)
            draw.rectangle([0, 0, pw - 1, ph - 1], outline=(80, 80, 80))

            tmp = path + '.tmp.png'
            bezel.save(tmp)

            w_mm = 140
            h_mm = w_mm * ph / pw
            if h_mm > 50:
                h_mm = 50
                w_mm = h_mm * pw / ph

            x = (216 - w_mm) / 2  # center
            self.image(tmp, x=x, y=self.get_y(), w=w_mm)
            self.set_y(self.get_y() + h_mm + 2)
            os.remove(tmp)

            if caption:
                self.set_font('Helvetica', 'I', 7)
                self.set_text_color(120, 120, 120)
                self.cell(0, 4, safe(caption), align='C')
                self.ln(5)
        except Exception as e:
            self.set_font('Helvetica', '', 8)
            self.set_text_color(200, 50, 50)
            self.cell(0, 4, f'[image error: {e}]')
            self.ln(5)

    # ── Pages ─────────────────────────────────────────────────────────

    def add_title_page(self, chain_count, feature_count, screenshot_count):
        self.add_page()

        # Header
        self.set_fill_color(18, 18, 26)
        self.rect(0, 0, 216, 40, 'F')
        self.set_fill_color(20, 241, 149)
        self.rect(0, 40, 216, 1.2, 'F')

        self.set_xy(14, 8)
        self.set_font('Helvetica', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, 'KeepKey Firmware')

        self.set_xy(14, 22)
        self.set_font('Helvetica', 'B', 14)
        self.set_text_color(20, 241, 149)
        self.cell(0, 10, safe(f'v{self.fw_version} Screen Review'))

        self.set_xy(160, 10)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(160, 160, 160)
        self.cell(0, 5, datetime.now().strftime('%Y-%m-%d'))

        # Summary box
        y = 50
        self.set_xy(14, y)
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(40, 40, 40)
        self.cell(0, 7, 'About This Report')
        y += 9
        self.set_xy(14, y)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(185, 5, safe(
            'This document presents real screenshots captured from the KeepKey firmware emulator '
            'via DebugLink. Every image is a pixel-accurate rendering of what users see on the '
            '256x64 OLED display during address verification, transaction signing, and device management. '
            'No synthetic mockups -- all screens are captured from running firmware.'
        ))
        y = self.get_y() + 6

        # Stats
        self.set_xy(14, y)
        self.set_font('Helvetica', 'B', 11)
        self.cell(0, 7, 'Coverage')
        y += 9
        stats = [
            (f'{chain_count} chains', 'Address display verified'),
            (f'{feature_count} features', 'Security-critical flows documented'),
            (f'{screenshot_count} screenshots', 'Real emulator captures (not mockups)'),
        ]
        for val, desc in stats:
            self.set_xy(18, y)
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(20, 140, 80)
            self.cell(30, 5, val)
            self.set_font('Helvetica', '', 9)
            self.set_text_color(80, 80, 80)
            self.cell(0, 5, desc)
            y += 6

    def add_chain_page(self, section, screenshots_dir):
        self.add_page()
        self._section_header(
            section['title'], section['accent'],
            section.get('security'), section.get('new', False))

        y = self.get_y()

        # What it shows
        self.set_xy(10, y)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, 'What The User Sees')
        self.ln(6)
        self.set_x(10)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(192, 5, safe(section['what']))
        self.ln(2)

        # Screenshots
        for fname in section.get('screenshots', []):
            path = os.path.join(screenshots_dir, fname)
            self._embed_screenshot(path, fname.replace('.png', '').replace('-', ' '))

        # Why it matters
        self.set_x(10)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, 'Why This Matters')
        self.ln(6)
        self.set_x(10)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(192, 5, safe(section['why']))
        self.ln(3)

        # Details
        if section.get('details'):
            self.set_x(10)
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(40, 40, 40)
            self.cell(0, 5, 'Details')
            self.ln(5)
            self.set_font('Helvetica', '', 8)
            self.set_text_color(60, 60, 60)
            for d in section['details']:
                self.set_x(14)
                self.cell(0, 4, safe(f'- {d}'))
                self.ln(5)

    def add_feature_page(self, section, screenshots_base):
        self.add_page()
        self._section_header(
            section['title'], section['accent'],
            section.get('security'),
            section.get('new_in_release', False))

        # What changed
        self.set_x(10)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, 'What Changed')
        self.ln(6)
        self.set_x(10)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(192, 5, safe(section['what']))
        self.ln(2)

        # Screenshots
        ss_conf = section.get('screenshots', {})
        ss_dir = os.path.join(screenshots_base, ss_conf.get('dir', ''))
        picks = ss_conf.get('picks', [])
        shown = 0
        for fname in picks:
            if shown >= 4:
                break  # Max 4 per feature page
            path = os.path.join(ss_dir, fname)
            if os.path.exists(path):
                caption = fname.replace('.png', '').replace('-', ' ')
                self._embed_screenshot(path, caption)
                shown += 1

                # Page break if getting long
                if self.get_y() > 220 and shown < len(picks):
                    self.add_page()

        # Why it matters
        if self.get_y() > 230:
            self.add_page()
        self.set_x(10)
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(40, 40, 40)
        self.cell(0, 5, 'Why This Matters')
        self.ln(6)
        self.set_x(10)
        self.set_font('Helvetica', '', 9)
        self.set_text_color(60, 60, 60)
        self.multi_cell(192, 5, safe(section['why']))
        self.ln(3)

        # Highlights
        if section.get('highlights'):
            self.set_x(10)
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(40, 40, 40)
            self.cell(0, 5, 'Highlights')
            self.ln(5)
            self.set_font('Helvetica', '', 8)
            for h in section['highlights']:
                color = (60, 60, 60)
                prefix = '-'
                if h.startswith('NEW:'):
                    color = (20, 150, 60)
                    prefix = '+'
                self.set_text_color(*color)
                self.set_x(14)
                self.cell(0, 4, safe(f'{prefix} {h}'))
                self.ln(5)


# ═══════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description='KeepKey Firmware Review PDF')
    parser.add_argument('--screenshots', required=True, help='Base dir with captured screenshots')
    parser.add_argument('--output', default='firmware-review.pdf', help='Output PDF path')
    parser.add_argument('--version', default='7.14.0', help='Firmware version')
    args = parser.parse_args()

    base = args.screenshots
    print(f'\nKeepKey Firmware {args.version} - Report Generator\n')

    # Find available screenshots
    all_flows_dir = os.path.join(base, 'all-flows')
    if not os.path.isdir(all_flows_dir):
        all_flows_dir = base  # flat structure

    avail = set(os.listdir(all_flows_dir)) if os.path.isdir(all_flows_dir) else set()
    print(f'  Screenshots dir: {all_flows_dir}')
    print(f'  Available: {len([f for f in avail if f.endswith(".png")])} PNGs')

    # Count what we have
    chains_with_screenshots = sum(
        1 for s in CHAIN_SECTIONS
        if any(os.path.exists(os.path.join(all_flows_dir, f)) for f in s['screenshots'])
    )
    total_pngs = len([f for f in avail if f.endswith('.png')])

    # Feature screenshot counts
    for fs in FEATURE_SECTIONS:
        ss = fs.get('screenshots', {})
        d = os.path.join(base, ss.get('dir', ''))
        if os.path.isdir(d):
            total_pngs += len([f for f in os.listdir(d) if f.endswith('.png')])

    pdf = FirmwareReport(version=args.version)

    # Title page
    pdf.add_title_page(chains_with_screenshots, len(FEATURE_SECTIONS), total_pngs)

    # Feature sections first (what's new / important)
    for section in FEATURE_SECTIONS:
        print(f'  + Feature: {section["title"]}')
        pdf.add_feature_page(section, base)

    # Chain sections
    for section in CHAIN_SECTIONS:
        has_any = any(
            os.path.exists(os.path.join(all_flows_dir, f))
            for f in section['screenshots']
        )
        if has_any:
            print(f'  + Chain: {section["title"]}')
            pdf.add_chain_page(section, all_flows_dir)
        else:
            print(f'  - Chain: {section["title"]} (no screenshots)')

    # Write
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    pdf.output(args.output)
    size_kb = os.path.getsize(args.output) / 1024
    print(f'\n  Report: {args.output} ({size_kb:.0f} KB)')
    print(f'  Done.\n')


if __name__ == '__main__':
    main()
