#!/usr/bin/env python3
"""Recompute a KeepKey dice wallet offline, from what you hold.

Both dice modes are designed so that every input to the seed is one you can
write down, so this script needs no secret from the device and no network.

DICE ONLY  -- seed = SHA256(rolls)
    The rolls are the entire derivation. Identical to Coldcard's
    Dice-Rolls-Only, so their published verifier gives the same answer.

        ./verify_dice_seed.py --rolls 5312...  --words 24

MIXED      -- seed = SHA256(SHA256(b"KK\\x01SM" + device + SHA256(b"KK\\x01D" + rolls)))
    The device showed its own 32-byte draw as 24 BIP-39 words BEFORE you
    rolled. Pass those words back in; with them and your rolls the seed is
    fully determined. The host's EntropyAck bytes are consumed by the device
    and discarded, so they do not appear here.

        ./verify_dice_seed.py --rolls 5312... --words 12 \\
            --device-words "abandon ability able ..."

Compare the printed mnemonic with the backup words the device showed. If
they differ, the device did not derive the wallet from your rolls (and, in
MIXED, from the entropy it committed to). Do not fund it.

WARNING: in DICE ONLY the roll string IS the wallet; in MIXED the roll string
plus the device words are. Anyone who obtains them recreates your keys. Run
this on a machine you would trust with the seed, and prefer a throwaway run:
roll, verify the math, then start again with fresh rolls for the wallet you
actually fund.

Neither mode is a default, and DICE ONLY in particular has no device
randomness by design: a biased die, too few rolls, or a photographed roll
sheet is the whole wallet. The device refuses rolls where any face exceeds
30% of the total, as Coldcard does, but that is a floor, not a guarantee.
"""

import argparse
import hashlib
import os
import sys

# 50 rolls for 128-bit, 75 for 192-bit, 99 for 256-bit -- matches
# dice_rolls_for_strength() in lib/firmware/dice_input.c.
ROLLS_FOR_STRENGTH = {128: 50, 192: 75, 256: 99}
STRENGTH_FOR_WORDS = {12: 128, 18: 192, 24: 256}

# Byte tags, matching lib/firmware/dice_input.c. Python's \x takes exactly
# two hex digits, so b"KK\x01D" is the four bytes K, K, 0x01, D.
TAG_USER = b"KK\x01D"
TAG_MIX = b"KK\x01SM"

# The English wordlist the firmware itself is built from, as shipped in the
# trezor-crypto submodule. It is a C source file (the .h only declares the
# array), not a .txt; either form is read.
WORDLIST_CANDIDATES = (
    "deps/crypto/trezor-firmware/crypto/bip39_english.c",
    "deps/crypto/trezor-firmware/crypto/bip39_english.h",
)


def parse_wordlist(path):
    """One word per line, or a C source with the words as quoted literals.
    Returns the list, or None if the file does not hold exactly the 2048
    English words -- a wrong or partial file must not yield a plausible but
    different sentence."""
    with open(path) as handle:
        text = handle.read()
    if path.endswith((".h", ".c")):
        # The C source quotes other things too (its license text, for one),
        # so take the run from the first word to the last rather than every
        # quoted literal in the file.
        import re
        tokens = re.findall(r'"([a-z]+)"', text)
        try:
            first = tokens.index("abandon")
            last = tokens.index("zoo", first)
        except ValueError:
            return None
        words = tokens[first:last + 1]
    else:
        words = [line.strip() for line in text.splitlines() if line.strip()]
    if len(words) != 2048 or words[0] != "abandon" or words[-1] != "zoo":
        return None
    return words


def load_wordlist(explicit):
    """The wordlist from --wordlist, else the first repo candidate that
    parses. None if nothing usable was found."""
    if explicit:
        words = parse_wordlist(explicit)
        if words is None:
            raise SystemExit("%s does not contain the 2048 BIP-39 English "
                             "words" % explicit)
        return words
    here = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    for rel in WORDLIST_CANDIDATES:
        path = os.path.join(here, rel)
        if os.path.isfile(path):
            words = parse_wordlist(path)
            if words is not None:
                return words
    return None


def mnemonic_from_entropy(entropy, words):
    """BIP39: entropy + SHA256 checksum, split into 11-bit indices."""
    checksum_bits = len(entropy) * 8 // 32
    digest = hashlib.sha256(entropy).digest()
    bits = "".join("{:08b}".format(b) for b in entropy)
    bits += "".join("{:08b}".format(b) for b in digest)[:checksum_bits]
    return " ".join(words[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


def entropy_from_mnemonic(sentence, words):
    """Inverse of the above for the 24-word device sentence, checksum
    verified: a typo in a copied word is caught here, not blamed on the
    device."""
    parts = sentence.split()
    if len(parts) != 24:
        raise SystemExit("--device-words must be the 24 words the device "
                         "showed; got %d" % len(parts))
    try:
        bits = "".join("{:011b}".format(words.index(w)) for w in parts)
    except ValueError as exc:
        raise SystemExit("not a BIP-39 word: %s" % exc)
    entropy = bytes(int(bits[i:i + 8], 2) for i in range(0, 256, 8))
    if bits[256:] != "{:08b}".format(hashlib.sha256(entropy).digest()[0]):
        raise SystemExit("device words fail their BIP-39 checksum; re-check "
                         "the transcription before suspecting the device")
    return entropy


def seed_dice_only(rolls):
    return hashlib.sha256(rolls.encode("ascii")).digest()


def seed_mixed(device_entropy, rolls):
    user = hashlib.sha256(TAG_USER + rolls.encode("ascii")).digest()
    inner = hashlib.sha256(TAG_MIX + device_entropy + user).digest()
    return hashlib.sha256(inner).digest()


def main():
    ap = argparse.ArgumentParser(
        description="Recompute a KeepKey dice wallet from what you hold.")
    ap.add_argument("--rolls", help="roll string, digits 1-6 (default: stdin)")
    ap.add_argument("--words", type=int, choices=sorted(STRENGTH_FOR_WORDS),
                    required=True, help="word count the device produced")
    ap.add_argument("--device-words",
                    help="the 24 device-entropy words shown before rolling "
                         "(MIXED mode); omit for DICE ONLY")
    ap.add_argument("--mode", choices=("mixed", "only"),
                    help="the mode the device ran. Inferred from "
                         "--device-words when omitted; pass it to be told off "
                         "rather than handed the wrong wallet")
    ap.add_argument("--wordlist", help="path to bip39_english.txt")
    args = ap.parse_args()

    rolls = args.rolls if args.rolls is not None else sys.stdin.read()
    rolls = "".join(rolls.split())

    bad = sorted(set(rolls) - set("123456"))
    if bad:
        raise SystemExit("rolls contain non-d6 characters: %s" % ", ".join(bad))

    strength = STRENGTH_FOR_WORDS[args.words]
    expected = ROLLS_FOR_STRENGTH[strength]
    if len(rolls) != expected:
        raise SystemExit(
            "got %d rolls, but a %d-word dice seed uses exactly %d.\n"
            "A different count derives a different wallet, so this is a "
            "transcription error, not a warning." % (len(rolls), args.words,
                                                     expected))

    words = load_wordlist(args.wordlist)

    digest = hashlib.sha256(rolls.encode("ascii")).digest()

    # The mode decides the derivation, so getting it wrong produces a perfectly
    # valid mnemonic for the OTHER ceremony -- which then does not match what
    # the device showed. Inferring it from the presence of --device-words alone
    # meant a forgotten flag ended in "the device did not derive the wallet
    # from your rolls", i.e. this tool accused the device of cheating because
    # the user left an argument off.
    mode_arg = args.mode or ("mixed" if args.device_words else "only")
    if mode_arg == "mixed" and not args.device_words:
        raise SystemExit(
            "MIXED needs --device-words: the 24 words the device showed "
            "BEFORE you rolled. Without them this cannot reproduce the seed.")
    if mode_arg == "only" and args.device_words:
        raise SystemExit(
            "DICE ONLY derives from the rolls alone, so --device-words cannot "
            "be part of it. Drop the flag, or pass --mode mixed if that is "
            "the ceremony you ran.")

    if mode_arg == "mixed":
        if words is None:
            raise SystemExit("MIXED mode needs the BIP-39 wordlist to decode "
                             "--device-words; pass --wordlist")
        device_entropy = entropy_from_mnemonic(args.device_words, words)
        seed = seed_mixed(device_entropy, rolls)
        mode = "MIXED   seed = SHA256d(tag || device || SHA256(tag || rolls))"
    else:
        seed = seed_dice_only(rolls)
        mode = "DICE ONLY   seed = SHA256(rolls)"

    print("mode        : %s" % mode)
    print("rolls       : %d" % len(rolls))
    print("roll digest : %s" % digest.hex())
    print("            : the device showed this in full on the Dice Rolls "
          "screen")
    if args.device_words:
        print("device draw : %s" % device_entropy.hex())
    print("entropy     : %s" % seed[:strength // 8].hex())

    if words is None:
        raise SystemExit(
            "\nno BIP39 wordlist found (looked for the trezor-crypto "
            "submodule's bip39_english.c under deps/); pass --wordlist with "
            "that file or any one-word-per-line English list to print the "
            "mnemonic. The entropy above is the value the backup words encode.")

    mnemonic = mnemonic_from_entropy(seed[:strength // 8], words)
    print()
    print("mnemonic    :")
    parts = mnemonic.split()
    for i in range(0, len(parts), 4):
        print("  %2d. %s" % (i + 1, "  ".join(parts[i:i + 4])))
    print()
    other = ("--mode mixed --device-words '<the 24 words the device showed>'"
             if mode_arg == "only" else "--mode only")
    print("These are the words for %s."
          % ("DICE ONLY" if mode_arg == "only" else "MIXED"))
    print()
    print("If they are not what the device showed, check the MODE first. The "
          "other")
    print("ceremony derives a different, equally valid-looking wallet from the "
          "same")
    print("rolls, so a wrong --mode looks exactly like a dishonest device.")
    print("Re-run with:  %s" % other)
    print()
    print("If BOTH modes disagree with the device, the device did not derive "
          "the")
    print("wallet from your rolls. Do not fund it.")


if __name__ == "__main__":
    main()
