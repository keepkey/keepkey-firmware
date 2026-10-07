#!/usr/bin/env python3
"""Enforce the RC18 split between public and secret Pallas operations."""

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


# The gate reads source text, not the compiled translation unit, so it cannot
# tell which branch of a preprocessor conditional is built. It therefore only
# accepts checked function bodies that contain none: every token it requires or
# forbids is then compiled whenever the function is.
CONDITIONAL = re.compile(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef|elif|else|endif)\b",
                         re.M)


# A macro defined or undefined inside a checked body could alias a required
# token to a forbidden one, so bodies may hold none.
MACRO = re.compile(r"^[ \t]*#[ \t]*(?:define|undef)\b", re.M)

# Identifiers named by require()/forbid(); none may be #defined anywhere the
# gate reads, or `#define pallas_ct_x pallas_x` would satisfy require().
GUARDED = set()

PALLAS_CT_INCLUDE = re.compile(
    r'^[ \t]*#[ \t]*include[ \t]*[<"](?:[^>"\n]*/)?pallas_ct\.h[>"]', re.M)


def guard(token):
    match = re.match(r"[A-Za-z_]\w*", token)
    if match:
        GUARDED.add(match.group(0))


# Conditionals a checked definition may sit under: on in every production
# image that contains the checked code. Anything else (#if 0, a debug-only
# guard, an #else branch) is refused rather than evaluated.
PRODUCTION_CONDITIONALS = {"#if ZCASH_PRIVACY"}


def enclosing_conditionals(text):
    """(directive, branch) for each conditional open at the end of text."""
    stack = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        words = stripped[1:].split()
        if not words:
            continue
        keyword = words[0]
        if keyword in ("if", "ifdef", "ifndef"):
            stack.append(["#" + " ".join(words), "if"])
        elif keyword in ("elif", "else") and stack:
            stack[-1][1] = "else"
        elif keyword == "endif" and stack:
            stack.pop()
    return [tuple(entry) for entry in stack]


def splice(text):
    """Join backslash-newline continuations first, as the compiler does, so a
    directive split as '#i\\' + newline + 'f 0' is still seen."""
    return re.sub(r"\\\r?\n", "", text)


def function_body(text, name):
    text = code_only(splice(text))
    # A definition: the name starts a line or follows its return type there,
    # and the parameter list holds no ';' or brace. An indented caller such
    # as `if (name(x)) {` can therefore never stand in for the definition.
    match = re.search(r"^(?:[A-Za-z_][\w \t*]*[ \t*])?" + re.escape(name) +
                      r"\s*\([^;{}]*\)\s*\{", text, re.M)
    if not match:
        raise AssertionError("function not found: " + name)
    for directive, branch in enclosing_conditionals(text[:match.start()]):
        if directive not in PRODUCTION_CONDITIONALS or branch != "if":
            raise AssertionError(
                "{} is defined under '{}' ({} branch); this gate cannot tell "
                "whether that is compiled".format(name, directive, branch))
    start = match.end() - 1
    depth = 0
    for index in range(start, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                body = text[start + 1:index]
                if CONDITIONAL.search(body):
                    raise AssertionError(
                        name + " has preprocessor conditionals; this gate "
                        "checks unconditional code only")
                if MACRO.search(body):
                    raise AssertionError(
                        name + " defines or undefines a macro; one could "
                        "alias a checked token")
                return body
    raise AssertionError("unterminated function: " + name)


def code_only(text):
    """Blank comments and string/char literals so neither can satisfy a token
    check or unbalance the brace count. Literals keep their quotes."""
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            out.append(" ")
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
        elif text[i] in "\"'":
            quote = text[i]
            i += 1
            while i < n and text[i] != quote and text[i] != "\n":
                i += 2 if text[i] == "\\" else 1
            i += 1
            out.append(quote + quote)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def token_pattern(token):
    """A token as a regex: identifier edges must be word boundaries, so
    'pallas_ct_add_mod_q' is not satisfied by 'pallas_ct_add_mod_q_result',
    and '(' may follow any whitespace. A trailing '_' marks a prefix."""
    pattern = re.escape(token).replace(r"\(", r"\s*\(")
    if re.match(r"\w", token):
        pattern = r"\b" + pattern
    # A token ending in '_' (e.g. 'pallas_ct_') is a deliberate prefix.
    if re.search(r"[A-Za-z0-9]$", token):
        pattern += r"\b"
    return re.compile(pattern)


def require(body, token, where):
    guard(token)
    if not token_pattern(token).search(body):
        raise AssertionError("{} must call {}".format(where, token))


def forbid(body, token, where):
    guard(token)
    if token.endswith("("):
        # A call: any whitespace may sit between the name and its "(".
        found = re.search(r"\b" + re.escape(token[:-1]) + r"\s*\(", body)
    else:
        found = token in body
    if found:
        raise AssertionError("{} must not call {}".format(where, token))


def main():
    pallas = source("deps/crypto/trezor-firmware/crypto/pallas.c")
    sinsemilla = source("deps/crypto/trezor-firmware/crypto/pallas_sinsemilla.c")
    redpallas = source("deps/crypto/trezor-firmware/crypto/redpallas.c")
    zcash = source("lib/firmware/zcash.c")
    zcash_fsm = source("lib/firmware/fsm_msg_zcash.h")
    storage = source("lib/firmware/storage.c")

    # Public transaction data needs the fast compatibility implementation.
    if PALLAS_CT_INCLUDE.search(pallas):
        raise AssertionError(
            "pallas.c public compatibility path must not include pallas_ct.h")
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
    for token in ("pallas_ct_add_mod_q", "pallas_ct_mul_mod_q"):
        require(sign_core, token, "RedPallas signing core")

    # The nonce must come from the spec construction, not from a raw reduction.
    require(sign_core, "redpallas_hash_nonce", "RedPallas signing core")

    # NEVER normalise a signing nonce. This gate used to REQUIRE
    # pallas_ct_scalar_replace_zero_with_one() here, which institutionalised the
    # defect as an invariant: a dead entropy source became the constant nonce 1
    # on every signature, and a nonce that is reused AND publicly known
    # discloses the key from a single signature. A zero scalar must fail the
    # signature instead. Requiring a helper by name checked the shape of the
    # code; this checks the security property.
    forbid(sign_core, "pallas_ct_scalar_replace_zero_with_one",
           "RedPallas signing core")
    forbid(sign_core, "random_buffer", "RedPallas signing core")

    # The nonce hash must wipe its BLAKE2b context, not just the digest buffer.
    # blake2b_Final() clears its own scratch but leaves the finished state in
    # ctx: h[0..7] IS the digest it serialized, and buf still holds the last
    # input block, which contains T. Either one recovers the nonce r, and r plus
    # the emitted signature gives up the randomized signing key via
    # rsk = (s - r) / c. Found in review after the fix landed, so it is pinned
    # here rather than left to the next reader to notice.
    nonce_hash = code_only(function_body(redpallas, "redpallas_hash_nonce"))
    require(nonce_hash, "memzero(&ctx", "RedPallas nonce hash")
    require(nonce_hash, "memzero(hash_out", "RedPallas nonce hash")
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
    # The action handler must sign through the rk-VALIDATING entry point. This
    # gate previously required redpallas_sign_digest_for_rk() here, which pinned
    # the weaker path as an invariant: _for_rk feeds the host's rk straight into
    # the nonce and challenge hashes without ever checking it describes this
    # device's key, so the device would authorize under a verification key that
    # is not its own. _with_ak derives rk from the device's ak and alpha,
    # refuses on mismatch, and signs with the derived value.
    #
    # This is the second time this file has been found requiring the weaker of
    # two available implementations by name (see the normaliser note above).
    # Requiring a function by name pins whichever one happened to be in use;
    # forbid the unsafe one as well, so the gate states the property.
    require(action_handler, "redpallas_sign_digest_with_ak",
            "PCZT action handler")
    forbid(action_handler, "redpallas_sign_digest_for_rk(",
           "PCZT action handler")
    require(action_handler, "signatures[zcash_signing.signature_count]",
            "compact PCZT signature collection")
    require(action_handler, "zcash_signing.signature_count++",
            "compact PCZT signature collection")
    require(action_handler,
            "resp_signed->signatures_count = zcash_signing.signature_count",
            "compact PCZT signature response")
    output_verification = code_only(function_body(
        zcash_fsm, "zcash_verify_and_confirm_orchard_output"))
    require(output_verification, "zcash_orchard_compute_cmx_with_progress",
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
    address_derivation = code_only(function_body(
        zcash, "zcash_orchard_derive_unified_address"))
    require(address_derivation, "redpallas_scalar_mult_spendauth_G_progress",
            "Orchard unified-address derivation")
    forbid(address_derivation, "redpallas_scalar_mult_spendauth_G(",
           "Orchard unified-address derivation")
    stored_key_derivation = code_only(function_body(
        storage, "storage_zcashOrchardKeys"))
    require(stored_key_derivation, "zcash_derive_orchard_keys_with_progress",
            "interactive Orchard key derivation")
    forbid(stored_key_derivation, "zcash_derive_orchard_keys(",
           "interactive Orchard key derivation")
    transmission = code_only(function_body(zcash, "zcash_orchard_derive_transmission_key"))
    require(transmission, "pallas_ct_point_mult", "Orchard transmission-key derivation")
    forbid(transmission, "pallas_point_mult(", "Orchard transmission-key derivation")

    # No file the gate reads, nor the Pallas headers, may #define a checked
    # identifier: an alias would satisfy require() while compiling to another
    # call.
    # Every header these sources can reach inside the tree: the crypto
    # library's and the firmware's own.
    header_roots = [ROOT / "deps/crypto/trezor-firmware/crypto",
                    ROOT / "include", ROOT / "lib"]
    headers = {str(h.relative_to(ROOT)): h.read_text(encoding="utf-8",
                                                     errors="replace")
               for base in header_roots for h in sorted(base.rglob("*.h"))}
    checked = dict(headers, **{
        "pallas.c": pallas, "pallas_sinsemilla.c": sinsemilla,
        "redpallas.c": redpallas, "zcash.c": zcash,
        "fsm_msg_zcash.h": zcash_fsm, "storage.c": storage})
    for where, text in sorted(checked.items()):
        for match in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)",
                                 code_only(splice(text)), re.M):
            if match.group(1) in GUARDED:
                raise AssertionError("{} #defines checked identifier {}".format(
                    where, match.group(1)))

    print("Pallas API boundary: public Sinsemilla fast path and secret CT path verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as error:
        print("Pallas API boundary violation: {}".format(error), file=sys.stderr)
        sys.exit(1)
