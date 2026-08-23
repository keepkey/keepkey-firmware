#!/usr/bin/env python3
"""Enforce the RC18 split between public and secret Pallas operations."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", text, re.S)
    if not match:
        raise AssertionError("function not found: " + name)
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start + 1:index]
    raise AssertionError("unterminated function: " + name)


def code_only(text):
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def require(body, token, where):
    if token not in body:
        raise AssertionError("{} must call {}".format(where, token))


def forbid(body, token, where):
    if token in body:
        raise AssertionError("{} must not call {}".format(where, token))


def main():
    pallas = source("deps/crypto/trezor-firmware/crypto/pallas.c")
    sinsemilla = source("deps/crypto/trezor-firmware/crypto/pallas_sinsemilla.c")
    redpallas = source("deps/crypto/trezor-firmware/crypto/redpallas.c")
    zcash = source("lib/firmware/zcash.c")
    zcash_fsm = source("lib/firmware/fsm_msg_zcash.h")
    storage = source("lib/firmware/storage.c")

    # Public transaction data needs the fast compatibility implementation.
    forbid(pallas, '"pallas_ct.h"', "pallas.c public compatibility path")
    hash_to_point = code_only(function_body(
        sinsemilla, "pallas_sinsemilla_hash_to_point_progress"))
    require(hash_to_point, "sinsemilla_incomplete_add",
            "Sinsemilla public hash path")
    forbid(hash_to_point, "pallas_ct_", "Sinsemilla public hash path")
    require(hash_to_point, "progress(", "Sinsemilla public hash progress")
    incomplete_add = code_only(function_body(sinsemilla,
                                             "sinsemilla_incomplete_add"))
    require(incomplete_add, "pallas_point_add", "Sinsemilla public hash add")
    forbid(incomplete_add, "pallas_ct_", "Sinsemilla public hash add")

    # Transaction note rcm is host-known; use the fast public path.  The IVK's
    # device-secret rivk has a separate helper that remains fixed-schedule.
    commit = code_only(function_body(
        sinsemilla, "pallas_sinsemilla_commit_progress"))
    require(commit, "pallas_point_mult", "public Sinsemilla blinding")
    require(commit, "pallas_point_add", "public Sinsemilla blinding")
    forbid(commit, "pallas_ct_", "public Sinsemilla blinding")
    require(commit, "pallas_sinsemilla_commit_prepare",
            "public Sinsemilla progress propagation")
    secret_commit = code_only(function_body(
        sinsemilla, "pallas_sinsemilla_commit_secret_blind"))
    require(secret_commit, "pallas_ct_point_mult", "secret IVK blinding")
    require(secret_commit, "pallas_ct_point_add", "secret IVK blinding")
    forbid(secret_commit, "pallas_point_mult(", "secret IVK blinding")
    forbid(secret_commit, "pallas_point_add(", "secret IVK blinding")
    commit_ivk = code_only(function_body(sinsemilla,
                                         "pallas_sinsemilla_commit_ivk"))
    require(commit_ivk, "pallas_sinsemilla_commit_secret_blind",
            "IVK commitment")
    forbid(commit_ivk, "pallas_sinsemilla_short_commit", "IVK commitment")

    # Authorization scalars, nonces, and randomized keys must never fall back
    # to the variable-time public-data API.
    spendauth = code_only(function_body(redpallas, "pallas_scalar_mult_spendauth"))
    require(spendauth, "pallas_ct_point_mult", "RedPallas scalar multiplication")
    forbid(spendauth, "pallas_point_mult(", "RedPallas scalar multiplication")
    spendauth_progress = code_only(function_body(
        redpallas, "redpallas_scalar_mult_spendauth_G_progress"))
    require(spendauth_progress, "pallas_ct_point_mult_progress",
            "progress-reporting RedPallas scalar multiplication")
    forbid(spendauth_progress, "pallas_point_mult(",
           "progress-reporting RedPallas scalar multiplication")
    public_spendauth = code_only(function_body(
        redpallas, "pallas_scalar_mult_spendauth_public"))
    require(public_spendauth, "pallas_point_mult",
            "public alpha scalar multiplication")
    forbid(public_spendauth, "pallas_ct_",
           "public alpha scalar multiplication")

    sign = code_only(function_body(redpallas, "redpallas_sign_digest"))
    require(sign, "pallas_ct_add_mod_q", "redpallas_sign_digest")
    for token in ("pallas_add_mod_q(", "pallas_mod_q(", "pallas_mul_mod_q("):
        forbid(sign, token, "redpallas_sign_digest")

    sign_core = code_only(function_body(redpallas,
                                        "redpallas_sign_with_rsk"))
    for token in ("pallas_ct_add_mod_q", "pallas_ct_mod_q",
                  "pallas_ct_mul_mod_q", "pallas_ct_scalar_replace_zero_with_one"):
        require(sign_core, token, "RedPallas signing core")
    for token in ("pallas_add_mod_q(", "pallas_mod_q(", "pallas_mul_mod_q("):
        forbid(sign_core, token, "RedPallas signing core")

    optimized_sign = code_only(function_body(
        redpallas, "redpallas_sign_digest_with_ak"))
    require(optimized_sign, "redpallas_derive_rk_from_ak",
            "optimized RedPallas signing")
    require(optimized_sign, "pallas_ct_add_mod_q",
            "optimized RedPallas signing")
    forbid(optimized_sign, "pallas_scalar_mult_spendauth_public",
           "optimized RedPallas signing")

    pczt_sign = code_only(function_body(
        redpallas, "redpallas_sign_digest_for_rk"))
    require(pczt_sign, "pallas_ct_add_mod_q", "PCZT RedPallas signing")
    require(pczt_sign, "redpallas_sign_with_rsk", "PCZT RedPallas signing")
    forbid(pczt_sign, "pallas_point_mult(", "PCZT RedPallas signing")
    forbid(pczt_sign, "pallas_scalar_mult_spendauth_public",
           "PCZT RedPallas signing")
    action_handler = code_only(function_body(zcash_fsm,
                                             "fsm_msgZcashPCZTAction"))
    require(action_handler, "msg->has_is_spend", "PCZT action handler")
    require(action_handler, "if (msg->is_spend)", "PCZT action handler")
    require(action_handler, "redpallas_sign_digest_for_rk",
            "PCZT action handler")
    require(action_handler, "signatures[zcash_signing.signature_count]",
            "compact PCZT signature collection")
    require(action_handler, "zcash_signing.signature_count++",
            "compact PCZT signature collection")
    require(action_handler,
            "resp_signed->signatures_count = zcash_signing.signature_count",
            "compact PCZT signature response")
    forbid(action_handler, "redpallas_sign_digest_with_ak",
           "PCZT action handler")
    output_verification = code_only(function_body(
        zcash_fsm, "zcash_verify_and_confirm_orchard_output"))
    require(output_verification, "zcash_orchard_compute_cmx_with_progress",
            "interactive Orchard note verification")
    forbid(output_verification, "zcash_orchard_compute_cmx(",
           "interactive Orchard note verification")
    # Orchard V2 and Ironwood V3 share the public Sinsemilla commitment path;
    # only their rcm derivation differs. Keep the expensive implementation in
    # one helper, and ensure both interactive wrappers route through it.
    note_commitment = code_only(function_body(
        zcash, "zcash_orchard_family_compute_cmx_with_progress"))
    require(note_commitment, "pallas_sinsemilla_short_commit_progress",
            "Orchard-family note verification progress")
    for name in ("zcash_orchard_compute_cmx_with_progress",
                 "zcash_ironwood_compute_cmx_with_progress"):
        wrapper = code_only(function_body(zcash, name))
        require(wrapper, "zcash_orchard_family_compute_cmx_with_progress",
                name)

    derive_rk = code_only(function_body(redpallas, "redpallas_derive_rk"))
    require(derive_rk, "pallas_ct_add_mod_q", "redpallas_derive_rk")

    # ZIP-32 key reduction and transmission-key derivation also process
    # device-secret viewing/spending material.
    for name in ("to_scalar", "to_base"):
        body = code_only(function_body(zcash, name))
        require(body, "pallas_ct_", name)
    key_derivation = code_only(function_body(
        zcash, "zcash_derive_orchard_keys_with_progress"))
    require(key_derivation, "redpallas_scalar_mult_spendauth_G_progress",
            "Orchard key derivation")
    forbid(key_derivation, "redpallas_scalar_mult_spendauth_G(",
           "Orchard key derivation")
    stored_key_derivation = code_only(function_body(
        storage, "storage_zcashOrchardKeys"))
    require(stored_key_derivation, "zcash_derive_orchard_keys_with_progress",
            "interactive Orchard key derivation")
    forbid(stored_key_derivation, "zcash_derive_orchard_keys(",
           "interactive Orchard key derivation")
    transmission = code_only(function_body(zcash, "zcash_orchard_derive_transmission_key"))
    require(transmission, "pallas_ct_point_mult", "Orchard transmission-key derivation")
    forbid(transmission, "pallas_point_mult(", "Orchard transmission-key derivation")

    print("Pallas API boundary: public Sinsemilla fast path and secret CT path verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as error:
        print("Pallas API boundary violation: {}".format(error), file=sys.stderr)
        sys.exit(1)
