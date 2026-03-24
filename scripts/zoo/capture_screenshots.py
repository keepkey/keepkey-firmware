#!/usr/bin/env python3
"""
capture_screenshots.py — Orchestrates KeepKey emulator screenshot capture.

Connects to a running emulator via UDP, executes transaction flows,
and captures the OLED display at each confirmation screen.

Usage:
  python3 capture_screenshots.py --output=/output [--flow=btc-send]
  python3 capture_screenshots.py --output=/output --flow=recovery-cipher
  python3 capture_screenshots.py --output=/output --flow=recovery-cipher --mnemonic="zoo zoo ... wrong"

Requires: emulator running on KK_TRANSPORT_MAIN / KK_TRANSPORT_DEBUG
"""
import os
import sys
import argparse
import time
import json

# Add python-keepkey to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'deps', 'python-keepkey'))

from keepkeylib.client import KeepKeyDebuglinkClient
from keepkeylib.transport_udp import UDPTransport
from keepkeylib import messages_pb2 as proto
from keepkeylib import messages_ethereum_pb2 as eth_proto
from keepkeylib import messages_solana_pb2 as sol_proto
from keepkeylib import messages_tron_pb2 as tron_proto
from keepkeylib import messages_ton_pb2 as ton_proto
from keepkeylib import messages_zcash_pb2 as zec_proto
from screenshot import capture_screenshot


def make_client():
    """Create a DebugLink client connected to the emulator."""
    main_host = os.environ.get('KK_TRANSPORT_MAIN', '127.0.0.1:11044')
    debug_host = os.environ.get('KK_TRANSPORT_DEBUG', '127.0.0.1:11045')

    transport = UDPTransport(main_host)
    client = KeepKeyDebuglinkClient(transport)
    debug_transport = UDPTransport(debug_host)
    client.set_debuglink(debug_transport)
    # Disable auto-confirm so we control capture timing
    client.auto_button = False
    return client


def reset_device(client, mnemonic='all ' * 11 + 'all'):
    """Wipe and load a known mnemonic for deterministic screenshots."""
    client.auto_button = True  # auto-confirm for setup
    client.wipe_device()
    client.load_device_by_mnemonic(
        mnemonic=mnemonic.strip(),
        pin='',
        passphrase_protection=False,
        label='KeepKey Zoo',
        language='english',
    )
    client.auto_button = False  # back to manual for captures


def capture(client, output_dir, name):
    """Capture current OLED state to output_dir/name.png."""
    path = os.path.join(output_dir, name)
    ok = capture_screenshot(client.debug, path, scale=3)
    if ok:
        fsize = os.path.getsize(path)
        status = 'OK' if fsize > 400 else 'BLANK?'
        print(f"    [{status}] {name} ({fsize}B)")
    return ok


def capture_with_meta(client, output_dir, name, meta):
    """Capture OLED + save metadata JSON sidecar."""
    ok = capture(client, output_dir, name)
    if ok and meta:
        json_path = os.path.join(output_dir, name.replace('.png', '.json'))
        with open(json_path, 'w') as f:
            json.dump(meta, f, indent=2)
    return ok


def send_and_capture(client, msg, output_dir, screen_name):
    """Send msg, wait for ButtonRequest, capture OLED, then confirm.

    Core pattern: send -> ButtonRequest (screen displayed) -> capture -> press -> advance.
    """
    ret = client.call_raw(msg)
    while isinstance(ret, proto.ButtonRequest):
        time.sleep(0.15)  # animation flush
        capture(client, output_dir, screen_name)
        client.debug.press_yes()
        ret = client.call_raw(proto.ButtonAck())
    return ret


# ═══════════════════════════════════════════════════════════════════════
# Flow: BTC Send
# ═══════════════════════════════════════════════════════════════════════

def flow_btc_send(client, out):
    """Bitcoin send flow — address display."""
    from keepkeylib import tx_api
    client.set_tx_api(tx_api.TxApiBitcoin)
    reset_device(client)

    print("  [btc-send] Get address (show on device)...")
    send_and_capture(client, proto.GetAddress(
        address_n=[44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
        coin_name='Bitcoin',
        show_display=True,
    ), out, '01-btc-get-address.png')


def flow_btc_sign(client, out):
    """Bitcoin sign transaction — confirm output + fee screens."""
    from keepkeylib import tx_api
    client.set_tx_api(tx_api.TxApiBitcoin)
    reset_device(client)

    print("  [btc-sign] Sign transaction...")
    # Use a simple 1-in-1-out tx
    inp1 = proto.TxInputType(
        address_n=[44 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0, 0],
        prev_hash=bytes.fromhex('d5f65ee80147b4bcc70b75e4bbf2d7382021b871bd8867ef8fa525ef50864882'),
        prev_index=0,
        amount=390000,
    )
    out1 = proto.TxOutputType(
        address='1MJ2tj2ThBE62pXbBSwVDT1Gn72SKPkLhD',
        amount=380000,
        script_type=proto.OutputScriptType.Value('PAYTOADDRESS'),
    )

    try:
        (signatures, serialized_tx) = client.sign_tx('Bitcoin', [inp1], [out1])
        # Screenshots captured during the sign flow via DebugLink auto-confirm
    except Exception as e:
        print(f"    sign_tx raised: {e}")

    capture(client, out, '02-btc-confirm-output.png')


# ═══════════════════════════════════════════════════════════════════════
# Flow: ETH Send
# ═══════════════════════════════════════════════════════════════════════

def flow_eth_send(client, out):
    """Ethereum send flow — address display."""
    reset_device(client)

    print("  [eth-send] Get ETH address...")
    send_and_capture(client, eth_proto.EthereumGetAddress(
        address_n=[44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0],
        show_display=True,
    ), out, '01-eth-get-address.png')


# ═══════════════════════════════════════════════════════════════════════
# Flow: Solana
# ═══════════════════════════════════════════════════════════════════════

def flow_solana_address(client, out):
    """Solana get address — full 44-char base58."""
    reset_device(client)

    print("  [solana] Get Solana address...")
    try:
        send_and_capture(client, sol_proto.SolanaGetAddress(
            address_n=[44 | 0x80000000, 501 | 0x80000000, 0 | 0x80000000],
            show_display=True,
        ), out, '01-sol-get-address.png')
    except Exception as e:
        print(f"    solana not available: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Flow: Recovery Cipher (character-by-character seed entry)
# ═══════════════════════════════════════════════════════════════════════

def flow_recovery_cipher(client, out, mnemonic=None, word_count=12, with_pin=False):
    """Recovery cipher flow — captures every screen of character-by-character
    seed phrase entry. This is the major UX bottleneck for users.

    Captures:
      - Initial "reminder" / instructions screen
      - First cipher grid (scrambled alphabet)
      - Character entry progression (each keystroke updates the grid)
      - Auto-complete events (word matched from partial input)
      - Word boundary transitions (space between words)
      - Final confirmation / success screen

    Each screenshot gets a JSON sidecar with metadata:
      - cipher: the 26-char scrambled alphabet mapping
      - word_index: which word (0-based)
      - char_index: which character within the word
      - typed_so_far: characters entered for current word
      - auto_completed: the word if auto-complete triggered
      - phase: 'pin' | 'reminder' | 'cipher_grid' | 'char_entry' | 'auto_complete' | 'word_space' | 'done'
    """

    if mnemonic is None:
        mnemonic = 'all ' * 11 + 'all'
    mnemonic = mnemonic.strip()
    mnemonic_words = mnemonic.split()

    if word_count is None:
        word_count = len(mnemonic_words)

    print(f"  [recovery-cipher] {word_count}-word recovery, {len(mnemonic_words)} words to enter")
    print(f"  [recovery-cipher] First 3 words: {' '.join(mnemonic_words[:3])}...")

    # Step 1: Wipe the device so it's uninitialized
    client.wipe_device()

    step = 1

    # Step 2: Start recovery
    ret = client.call_raw(proto.RecoveryDevice(
        word_count=word_count,
        passphrase_protection=False,
        pin_protection=with_pin,
        label='KeepKey Zoo Recovery',
        language='english',
        enforce_wordlist=True,
        use_character_cipher=True,
    ))

    # Step 3: Handle optional PIN entry
    if with_pin and isinstance(ret, proto.PinMatrixRequest):
        capture_with_meta(client, out, f'{step:02d}-pin-entry-1.png', {
            'phase': 'pin', 'step': 'first_pin_entry',
        })
        step += 1

        pin_encoded = client.debug.encode_pin('135246')
        ret = client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

        if isinstance(ret, proto.PinMatrixRequest):
            capture_with_meta(client, out, f'{step:02d}-pin-entry-2.png', {
                'phase': 'pin', 'step': 'confirm_pin_entry',
            })
            step += 1
            pin_encoded = client.debug.encode_pin('135246')
            ret = client.call_raw(proto.PinMatrixAck(pin=pin_encoded))

    # Step 4: Reminder / instructions screen (ButtonRequest)
    if isinstance(ret, proto.ButtonRequest):
        capture_with_meta(client, out, f'{step:02d}-recovery-reminder.png', {
            'phase': 'reminder',
            'description': 'Instructions screen before cipher entry begins',
        })
        step += 1
        client.debug.press_yes()
        ret = client.call_raw(proto.ButtonAck())

    # Step 5: Character-by-character cipher entry
    total_chars = 0
    total_auto_completes = 0
    recovery_log = []

    for word_idx, word in enumerate(mnemonic_words):
        word_chars_entered = []
        print(f"    Word {word_idx + 1}/{len(mnemonic_words)}: '{word}'")

        for char_idx, character in enumerate(word):
            if not isinstance(ret, proto.CharacterRequest):
                print(f"    WARNING: Expected CharacterRequest, got {ret.__class__.__name__}")
                capture_with_meta(client, out, f'{step:02d}-unexpected-{ret.__class__.__name__}.png', {
                    'phase': 'error',
                    'expected': 'CharacterRequest',
                    'got': ret.__class__.__name__,
                    'word_index': word_idx,
                    'char_index': char_idx,
                })
                step += 1
                break

            # Read cipher + layout in one DebugLink call (avoids 3 round-trips)
            recovery_state = client.debug.read_recovery_state()
            cipher = recovery_state['cipher']

            # Capture the cipher grid screen BEFORE sending character
            is_first_char = (char_idx == 0)
            capture_name = f'{step:02d}-w{word_idx + 1:02d}-c{char_idx + 1:02d}-cipher'
            if is_first_char:
                capture_name += '-initial'
            capture_name += '.png'

            meta = {
                'phase': 'cipher_grid' if is_first_char else 'char_entry',
                'word_index': word_idx,
                'word': word,
                'char_index': char_idx,
                'target_char': character,
                'typed_so_far': ''.join(word_chars_entered),
                'cipher': cipher if isinstance(cipher, str) else cipher.decode('ascii', errors='replace'),
                'cipher_mapping': {chr(97 + i): (cipher[i] if isinstance(cipher[i], str) else chr(cipher[i]))
                                   for i in range(min(26, len(cipher)))},
            }
            capture_with_meta(client, out, capture_name, meta)
            step += 1
            total_chars += 1

            # Encode and send the character through the cipher
            encoded_character = cipher[ord(character) - 97]
            ret = client.call_raw(proto.CharacterAck(character=encoded_character))
            word_chars_entered.append(character)

            # Check for auto-complete (single call)
            auto_completed = client.debug.read_recovery_auto_completed_word()

            if word == auto_completed:
                total_auto_completes += 1
                print(f"      Auto-completed '{word}' after {len(word_chars_entered)} chars")

                # Capture the auto-complete screen
                capture_with_meta(client, out, f'{step:02d}-w{word_idx + 1:02d}-auto-complete.png', {
                    'phase': 'auto_complete',
                    'word_index': word_idx,
                    'word': word,
                    'chars_needed': len(word_chars_entered),
                    'total_chars_in_word': len(word),
                })
                step += 1

                recovery_log.append({
                    'word': word,
                    'chars_typed': len(word_chars_entered),
                    'auto_completed': True,
                })

                # Send space to move to next word (except last)
                if word_idx < len(mnemonic_words) - 1:
                    capture_with_meta(client, out, f'{step:02d}-w{word_idx + 1:02d}-word-space.png', {
                        'phase': 'word_space',
                        'word_index': word_idx,
                        'completed_word': word,
                        'next_word_index': word_idx + 1,
                    })
                    step += 1
                    ret = client.call_raw(proto.CharacterAck(character=' '))
                break
        else:
            # Word was fully typed without auto-complete
            recovery_log.append({
                'word': word,
                'chars_typed': len(word),
                'auto_completed': False,
            })
            # Send space to move to next word (except last)
            if word_idx < len(mnemonic_words) - 1:
                if isinstance(ret, proto.CharacterRequest):
                    ret = client.call_raw(proto.CharacterAck(character=' '))

    # Step 6: Final CharacterAck(done=True)
    if isinstance(ret, proto.CharacterRequest):
        capture_with_meta(client, out, f'{step:02d}-final-before-done.png', {
            'phase': 'done',
            'description': 'Final screen before submitting recovery',
            'total_chars_typed': total_chars,
            'total_auto_completes': total_auto_completes,
        })
        step += 1
        ret = client.call_raw(proto.CharacterAck(done=True))

    # Step 7: Capture the result
    if isinstance(ret, proto.Success):
        print(f"    Recovery SUCCESS: {ret.message}")
        capture_with_meta(client, out, f'{step:02d}-recovery-success.png', {
            'phase': 'success',
            'message': ret.message,
            'total_screenshots': step,
            'total_chars_typed': total_chars,
            'total_auto_completes': total_auto_completes,
        })
    elif isinstance(ret, proto.Failure):
        print(f"    Recovery FAILED: {ret.message}")
        capture_with_meta(client, out, f'{step:02d}-recovery-failure.png', {
            'phase': 'failure',
            'message': ret.message,
        })
    else:
        print(f"    Unexpected response: {ret.__class__.__name__}")
        capture_with_meta(client, out, f'{step:02d}-recovery-unexpected.png', {
            'phase': 'error',
            'response_type': ret.__class__.__name__,
        })

    step += 1

    # Write summary log
    summary = {
        'flow': 'recovery-cipher',
        'word_count': word_count,
        'total_screenshots': step - 1,
        'total_chars_typed': total_chars,
        'total_auto_completes': total_auto_completes,
        'with_pin': with_pin,
        'words': recovery_log,
    }
    summary_path = os.path.join(out, 'summary.json')
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"    -> summary.json ({step - 1} screenshots, {total_chars} chars, {total_auto_completes} auto-completes)")


def flow_recovery_cipher_with_pin(client, out, mnemonic=None):
    """Recovery cipher with PIN — tests the full PIN + cipher flow."""
    flow_recovery_cipher(client, out, mnemonic=mnemonic, with_pin=True)


def flow_recovery_cipher_24(client, out):
    """Recovery cipher with 24-word mnemonic."""
    mnemonic_24 = 'dignity pass list indicate nasty swamp pool script soccer toe leaf photo multiply desk host tomato cradle drill spread actor shine dismiss champion exotic'
    flow_recovery_cipher(client, out, mnemonic=mnemonic_24, word_count=24)


# ═══════════════════════════════════════════════════════════════════════
# Flow: TRON
# ═══════════════════════════════════════════════════════════════════════

def flow_tron_send(client, out):
    """TRON address display."""
    reset_device(client)

    print("  [tron] Get TRON address...")
    try:
        send_and_capture(client, tron_proto.TronGetAddress(
            address_n=[44 | 0x80000000, 195 | 0x80000000, 0 | 0x80000000, 0, 0],
            show_display=True,
        ), out, '01-tron-get-address.png')
    except Exception as e:
        print(f"    tron not available: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Flow: TON
# ═══════════════════════════════════════════════════════════════════════

def flow_ton_send(client, out):
    """TON address display."""
    reset_device(client)

    print("  [ton] Get TON address...")
    try:
        send_and_capture(client, ton_proto.TonGetAddress(
            address_n=[44 | 0x80000000, 607 | 0x80000000, 0 | 0x80000000],
            show_display=True,
        ), out, '01-ton-get-address.png')
    except Exception as e:
        print(f"    ton sign not available: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Flow: Zcash Orchard
# ═══════════════════════════════════════════════════════════════════════

def flow_zcash_fvk(client, out):
    """Zcash Orchard Full Viewing Key derivation."""
    reset_device(client)

    print("  [zcash] Get Orchard FVK...")
    try:
        send_and_capture(client, zec_proto.ZcashGetOrchardFVK(
            address_n=[32 | 0x80000000, 133 | 0x80000000, 0 | 0x80000000],
        ), out, '01-zcash-orchard-fvk.png')
    except Exception as e:
        print(f"    zcash fvk not available: {e}")


# ═══════════════════════════════════════════════════════════════════════
# Flow Registry
# ═══════════════════════════════════════════════════════════════════════

FLOWS = {
    'btc-send': flow_btc_send,
    'btc-sign': flow_btc_sign,
    'eth-send': flow_eth_send,
    'solana-address': flow_solana_address,
    'tron-send': flow_tron_send,
    'ton-send': flow_ton_send,
    'zcash-fvk': flow_zcash_fvk,
    'recovery-cipher': flow_recovery_cipher,
    'recovery-cipher-pin': flow_recovery_cipher_with_pin,
    'recovery-cipher-24': flow_recovery_cipher_24,
}


def main():
    parser = argparse.ArgumentParser(description='KeepKey Zoo Screenshot Capture')
    parser.add_argument('--output', default='zoo-output/screenshots', help='Output directory')
    parser.add_argument('--flow', default=None, help='Run single flow (default: all)')
    parser.add_argument('--mnemonic', default=None, help='Custom mnemonic for recovery flows')
    parser.add_argument('--list-flows', action='store_true', help='List available flows')
    args = parser.parse_args()

    if args.list_flows:
        print("\nAvailable flows:")
        for name, func in FLOWS.items():
            doc = (func.__doc__ or '').split('\n')[0].strip()
            print(f"  {name:25s} {doc}")
        print()
        return

    print("\nKeepKey Zoo — Screenshot Capture\n")

    client = make_client()

    flows_to_run = {args.flow: FLOWS[args.flow]} if args.flow else FLOWS

    for name, func in flows_to_run.items():
        flow_dir = os.path.join(args.output, name)
        os.makedirs(flow_dir, exist_ok=True)
        print(f"  Flow: {name}")
        try:
            # Pass mnemonic to recovery flows that accept it
            if args.mnemonic and name.startswith('recovery-cipher') and name != 'recovery-cipher-24':
                func(client, flow_dir, mnemonic=args.mnemonic)
            else:
                func(client, flow_dir)
        except Exception as e:
            import traceback
            print(f"    ERROR: {e}")
            traceback.print_exc()
        print()

    print(f"  Screenshots: {args.output}/")
    print("  Done.\n")


if __name__ == '__main__':
    main()
