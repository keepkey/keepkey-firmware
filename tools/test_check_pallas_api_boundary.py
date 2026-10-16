"""Regression checks for the Pallas public/secret API boundary gate."""

import unittest

from check_pallas_api_boundary import (FORBIDDEN, GUARDED, alias_scan_texts,
                                       check_address_derivation, check_aliases,
                                       check_nonce_reduction,
                                       check_signing_sites,
                                       check_wide_reductions, forbid,
                                       function_body, includes_pallas_ct,
                                       require, source)


class NonceReduction(unittest.TestCase):
    def setUp(self):
        self.redpallas = source("deps/crypto/trezor-firmware/crypto/redpallas.c")

    def test_actual_nonce_reduction_passes(self):
        check_nonce_reduction(self.redpallas)

    def test_variable_time_nonce_operations_are_rejected(self):
        for constant, variable in (("pallas_ct_mod_q", "pallas_mod_q"),
                                   ("pallas_ct_mul_mod_q", "pallas_mul_mod_q"),
                                   ("pallas_ct_add_mod_q", "pallas_add_mod_q")):
            with self.subTest(operation=variable):
                with self.assertRaises(AssertionError):
                    check_nonce_reduction(self.redpallas.replace(constant, variable))

    def test_one_variable_time_half_cannot_hide_behind_the_other(self):
        bad = self.redpallas.replace("pallas_ct_mod_q(&hi)", "pallas_mod_q(&hi)")
        with self.assertRaisesRegex(AssertionError, "pallas_mod_q"):
            check_nonce_reduction(bad)

    def test_nonce_hash_cannot_bypass_the_checked_reduction(self):
        bad = self.redpallas.replace("pallas_from_uniform_bytes(hash_out", "unchecked_reduce(hash_out")
        with self.assertRaises(AssertionError):
            check_nonce_reduction(bad)


class ConditionalCompilation(unittest.TestCase):
    def test_unconditional_body_is_checked(self):
        body = function_body("void sign(void) {\n  pallas_ct_add_mod_q();\n}\n",
                             "sign")
        require(body, "pallas_ct_add_mod_q", "sign")

    def test_required_token_in_dead_branch_cannot_pass(self):
        source = ("void sign(void) {\n#if 0\n  pallas_ct_add_mod_q();\n"
                  "#endif\n  pallas_add_mod_q();\n}\n")
        with self.assertRaisesRegex(AssertionError, "preprocessor conditionals"):
            function_body(source, "sign")

    def test_every_conditional_directive_is_refused(self):
        for directive in ("#if X", "# if X", "#ifdef X", "#ifndef X",
                          "#elif X", "#else", "  #endif"):
            with self.subTest(directive=directive):
                source = "void f(void) {\n" + directive + "\n}\n"
                with self.assertRaises(AssertionError):
                    function_body(source, "f")

    def test_non_conditional_directive_is_allowed(self):
        body = function_body("void f(void) {\n#pragma once\n  g(2);\n}\n", "f")
        require(body, "g(", "f")

    def test_macro_definition_in_a_body_is_refused(self):
        # An alias could satisfy require() while compiling to another call.
        for directive in ("#define pallas_ct_add pallas_add",
                          "#undef pallas_ct_add"):
            with self.assertRaises(AssertionError):
                function_body("void f(void) {\n%s\n  pallas_ct_add(x);\n}\n"
                              % directive, "f")

    def test_line_continuation_cannot_hide_a_guard(self):
        source = ("#i\\\nf 0\nvoid f(void) {\n  pallas_ct_add(x);\n}\n"
                  "#endif\n")
        with self.assertRaises(AssertionError):
            function_body(source, "f")

    def test_require_needs_the_whole_identifier(self):
        with self.assertRaises(AssertionError):
            require("pallas_ct_add_mod_q_result = 0;", "pallas_ct_add_mod_q", "f")
        with self.assertRaises(AssertionError):
            require("my_pallas_ct_add_mod_q(x);", "pallas_ct_add_mod_q", "f")
        require("pallas_ct_add_mod_q (x);", "pallas_ct_add_mod_q", "f")
        require("memzero (&ctx, 1);", "memzero(&ctx", "f")
        require("pallas_ct_point_mult(x);", "pallas_ct_", "f")  # prefix

    def test_spaced_call_cannot_evade_forbid(self):
        for call in ("pallas_add_mod_q(x)", "pallas_add_mod_q (x)",
                     "pallas_add_mod_q\n  (x)"):
            with self.assertRaises(AssertionError):
                forbid(call, "pallas_add_mod_q(", "f")
        forbid("pallas_ct_add_mod_q(x)", "pallas_add_mod_q(", "f")

    def test_function_reference_cannot_satisfy_required_call(self):
        for body in ("(void)pallas_ct_add_mod_q;",
                     "operation = pallas_ct_add_mod_q; operation(x);",
                     "operation = &pallas_ct_add_mod_q;"):
            with self.subTest(body=body):
                with self.assertRaises(AssertionError):
                    require(body, "pallas_ct_add_mod_q", "f")
        for body in ("pallas_ct_add_mod_q(x);",
                     "pallas_ct_add_mod_q \n (x);"):
            require(body, "pallas_ct_add_mod_q", "f")

    def test_include_of_the_ct_header_is_found_in_every_spelling(self):
        for line in ('#include "pallas_ct.h"', "#include <pallas_ct.h>",
                     '#include "trezor/crypto/pallas_ct.h"',
                     "  #  include <crypto/pallas_ct.h>"):
            self.assertTrue(includes_pallas_ct(line + "\n"), line)
        self.assertFalse(includes_pallas_ct('#include "pallas.h"\n'))

    def test_include_split_by_a_continuation_is_found(self):
        for line in ('#inc\\\nlude "pallas_ct.h"',
                     '#include \\\n  "pallas_ct.h"',
                     "#include <pallas_\\\r\nct.h>"):
            self.assertTrue(includes_pallas_ct(line + "\n"), line)

    def test_include_after_a_comment_is_found(self):
        for line in ('/*x*/#include "pallas_ct.h"',
                     "/* a */ /* b */ # /* c */ include <pallas_ct.h>",
                     '/* spans\nlines */ #include "crypto/pallas_ct.h"'):
            self.assertTrue(includes_pallas_ct(line + "\n"), line)
        for line in ('// #include "pallas_ct.h"',
                     '/* #include "pallas_ct.h" */',
                     'const char *s = "\\n#include <pallas_ct.h>";'):
            self.assertFalse(includes_pallas_ct(line + "\n"), line)

    def test_caller_cannot_stand_in_for_the_definition(self):
        source = ("void caller(void) {\n  if (sign(x)) {\n    pallas_ct_add_mod_q();\n"
                  "  }\n}\n\nstatic bool sign(int x) {\n  pallas_add_mod_q();\n}\n")
        body = function_body(source, "sign")
        self.assertIn("pallas_add_mod_q", body)
        self.assertNotIn("pallas_ct_add_mod_q", body)

    def test_return_type_on_its_own_line(self):
        body = function_body("static bool\nsign(int x,\n     int y) {\n  g();\n}\n",
                             "sign")
        require(body, "g()", "sign")

    def test_call_only_is_not_a_definition(self):
        with self.assertRaisesRegex(AssertionError, "function not found"):
            function_body("void f(void) {\n  if (sign(x)) {\n  }\n}\n", "sign")


class EnclosingConditionals(unittest.TestCase):
    def test_definition_inside_if_0_is_refused(self):
        source = ("#if 0\nvoid sign(void) {\n  pallas_ct_add_mod_q();\n}\n"
                  "#endif\n")
        with self.assertRaisesRegex(AssertionError, "cannot tell"):
            function_body(source, "sign")

    def test_else_branch_of_a_production_guard_is_refused(self):
        source = ("#if ZCASH_PRIVACY\n#else\nvoid sign(void) {\n  g();\n}\n"
                  "#endif\n")
        with self.assertRaisesRegex(AssertionError, "else branch"):
            function_body(source, "sign")

    def test_second_definition_is_refused(self):
        checked = "void sign(void) {\n  pallas_ct_add_mod_q(x);\n}\n"
        other = "void sign(void) {\n  pallas_add_mod_q(x);\n}\n"
        for source in (
                "#if ZCASH_PRIVACY\n" + checked + "#else\n" + other +
                "#endif\n",
                "#if ZCASH_PRIVACY\n" + checked + "#endif\n"
                "#if !ZCASH_PRIVACY\n" + other + "#endif\n",
                "#if ZCASH_PRIVACY\n" + checked + "#endif\n" + other):
            with self.subTest(source=source):
                with self.assertRaisesRegex(AssertionError, "more than once"):
                    function_body(source, "sign")

    def test_production_guard_and_closed_blocks_are_accepted(self):
        source = ("#if 0\nvoid old(void) {}\n#endif\n#if ZCASH_PRIVACY\n"
                  "void sign(void) {\n  g();\n}\n#endif\n")
        require(function_body(source, "sign"), "g()", "sign")


class WideReductions(unittest.TestCase):
    """Substitutions in the real zcash.c that the old prefix check passed."""

    ZCASH = source("lib/firmware/zcash.c")

    def substituted(self, function, old, new):
        start = self.ZCASH.index("static void {}(".format(function))
        end = self.ZCASH.index("\n}\n", start)
        body = self.ZCASH[start:end]
        self.assertIn(old, body)
        return self.ZCASH[:start] + body.replace(old, new) + self.ZCASH[end:]

    def test_shipped_reductions_pass(self):
        check_wide_reductions(self.ZCASH)

    def test_variable_time_reduction_is_refused(self):
        for function, field in (("to_scalar", "q"), ("to_base", "p")):
            for operation in ("mod_", "mul_mod_", "add_mod_"):
                ct = "pallas_ct_{}{}(".format(operation, field)
                with self.subTest(function=function, operation=ct):
                    with self.assertRaises(AssertionError):
                        check_wide_reductions(self.substituted(
                            function, ct, ct.replace("pallas_ct_", "pallas_")))

    def test_added_variable_time_reduction_is_refused(self):
        # Every constant-time call stays, so only the ban on its
        # variable-time twin can refuse these.
        for function, field in (("to_scalar", "q"), ("to_base", "p")):
            for operation in ("mod_", "mul_mod_", "add_mod_"):
                ct = "pallas_ct_{}{}(".format(operation, field)
                twin = ct.replace("pallas_ct_", "pallas_")
                with self.subTest(function=function, operation=twin):
                    with self.assertRaisesRegex(AssertionError,
                                                "must not call"):
                        check_wide_reductions(self.substituted(
                            function, ct, twin + "x);\n  " + ct))

    def test_full_names_are_guarded_against_aliases(self):
        check_wide_reductions(self.ZCASH)
        for name in ("pallas_ct_mod_q", "pallas_mod_q", "pallas_ct_mod_p",
                     "pallas_mod_p"):
            self.assertIn(name, GUARDED)


class MacroAliases(unittest.TestCase):
    """A #define of a checked identifier is refused wherever it can reach the
    checked code."""

    ALIAS = "#define redpallas_sign_digest_with_ak redpallas_sign_digest_for_rk\n"

    def setUp(self):
        # Only what this test names is checked, whatever ran before it. The
        # gate's own require() and forbid() are what mark an identifier.
        self.saved = set(GUARDED), set(FORBIDDEN)
        GUARDED.clear()
        FORBIDDEN.clear()
        require("redpallas_sign_digest_with_ak(x);",
                "redpallas_sign_digest_with_ak", "f")
        forbid("", "pallas_mod_q(", "f")
        forbid("", "pallas_ct_", "f")

    def tearDown(self):
        for names, saved in zip((GUARDED, FORBIDDEN), self.saved):
            names.clear()
            names.update(saved)

    def test_macro_expanding_to_a_forbidden_call_is_refused(self):
        for text in ("#define ALT pallas_mod_q\n",
                     "#define ALT(x) pallas_mod_q(x)\n",
                     "#define ALT(x) \\\n  (pallas_mod_q (x))\n",
                     "#define FAST pallas_ct_point_mult\n"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(AssertionError, "to forbidden"):
                    check_aliases({"x.c": text})
        check_aliases({"x.c": "#define ALT pallas_mod_q_table\n"
                              "#define OTHER 1 /* pallas_mod_q */\n"
                              "#define NAME \"pallas_mod_q\"\n"})

    def test_spaced_member_access_in_macro_is_refused(self):
        forbid("", "->ask", "address derivation")
        for access in ("->ask", "-> ask", "->\task", "->/* hidden */ask"):
            with self.subTest(access=access):
                with self.assertRaisesRegex(AssertionError, "to forbidden"):
                    check_aliases({"x.h": "#define GET_ASK(k) ((k)" + access + ")\n"})
        check_aliases({"x.h": "#define OTHER(k) ((k)-> ask_count)\n"})

    def test_forbidden_call_through_a_macro_in_the_real_source(self):
        # The body still makes every constant-time call, so the body check
        # passes; only the macro scan sees the variable-time one.
        texts = alias_scan_texts()
        check_aliases(texts)
        path = "lib/firmware/zcash.c"
        start = texts[path].index("static void to_scalar(")
        brace = texts[path].index("{", start) + 1
        mutated = dict(texts)
        mutated[path] = (texts[path][:start] + "#define ALT pallas_mod_q\n" +
                         texts[path][start:brace] + "\n  ALT(x);" +
                         texts[path][brace:])
        check_wide_reductions(mutated[path])
        with self.assertRaisesRegex(AssertionError, path + " #defines ALT"):
            check_aliases(mutated)

    def test_alias_of_a_checked_identifier_is_refused(self):
        for text in (self.ALIAS, "  #  define redpallas_sign_digest_with_ak(a) x\n",
                     "#def\\\nine redpallas_sign_digest_with_ak x\n"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(AssertionError, "#defines checked"):
                    check_aliases({"x.c": text})
        check_aliases({"x.c": "#define redpallas_sign_digest_with_ak_count 1\n"
                              "// #define redpallas_sign_digest_with_ak x\n"})

    def test_alias_in_the_handlers_translation_unit_is_refused(self):
        # fsm_msg_zcash.h is compiled inside fsm.c, so a macro defined there
        # before the #include renames the calls the handlers make.
        texts = alias_scan_texts()
        check_aliases(texts)
        for path in ("lib/firmware/fsm.c", "lib/firmware/fsm_msg_zcash.h",
                     "lib/firmware/zcash.c", "include/keepkey/firmware/zcash.h"):
            with self.subTest(path=path):
                self.assertIn(path, texts)
                mutated = dict(texts)
                mutated[path] = self.ALIAS + texts[path]
                with self.assertRaisesRegex(AssertionError, path):
                    check_aliases(mutated)


class SigningSites(unittest.TestCase):
    """The handlers sign only where the handler tests count it."""

    FSM = source("lib/firmware/fsm_msg_zcash.h")

    def in_function(self, signature, statement):
        start = self.FSM.index(signature)
        brace = self.FSM.index("{", start) + 1
        return self.FSM[:brace] + "\n  " + statement + self.FSM[brace:]

    def test_shipped_handlers_pass(self):
        check_signing_sites(self.FSM)

    def test_signing_while_streaming_is_refused(self):
        for signature in ("void fsm_msgZcashPCZTAction(",
                          "void fsm_msgZcashTransparentInput(",
                          "static void zcash_final_gate("):
            for statement in (
                    "redpallas_sign_digest_with_ak(a, b, c, d, e, f, g, h, i);",
                    "redpallas_sign_digest(a, b, c, d, e);",
                    "hdnode_sign_digest(node, digest, sig, NULL, NULL);",
                    "ecdsa_sign_digest(curve, key, digest, sig, NULL, NULL);",
                    "sign = hdnode_sign_digest;"):
                with self.subTest(signature=signature, statement=statement):
                    with self.assertRaisesRegex(AssertionError,
                                                "outside the final-gate"):
                        check_signing_sites(
                            self.in_function(signature, statement))

    def test_uncounted_signing_call_is_refused(self):
        for signature in ("static bool zcash_sign_transparent_inputs(",
                          "static bool zcash_sign_orchard_spends("):
            with self.subTest(signature=signature):
                with self.assertRaisesRegex(AssertionError, "must count"):
                    check_signing_sites(self.in_function(
                        signature, "hdnode_sign_digest(n, d, s, NULL, NULL);"))
        uncounted = self.FSM.replace("ZCASH_TEST_COUNT_SIGN();", ";")
        self.assertNotEqual(uncounted, self.FSM)
        with self.assertRaisesRegex(AssertionError, "must count"):
            check_signing_sites(uncounted)


class AddressDerivation(unittest.TestCase):
    """The unified address comes from the cached ak, never from ask."""

    ZCASH = source("lib/firmware/zcash.c")

    def with_statement(self, statement):
        start = self.ZCASH.index("bool zcash_orchard_derive_unified_address(")
        brace = self.ZCASH.index("{", start) + 1
        return self.ZCASH[:brace] + "\n  " + statement + self.ZCASH[brace:]

    def test_shipped_derivation_passes(self):
        check_address_derivation(self.ZCASH)
        check_address_derivation(self.with_statement("(void)keys->ak;"))

    def test_spaced_member_access_is_refused(self):
        for access in ("->ask", "-> ask", "->\task", "->\nask", "->/* hidden */ask"):
            with self.subTest(access=access):
                with self.assertRaisesRegex(AssertionError, "must not call"):
                    check_address_derivation(self.with_statement("(void)keys" + access + ";"))
        check_address_derivation(self.with_statement("(void)keys->ask_count;"))

    def test_reading_or_multiplying_by_ask_is_refused(self):
        for statement in (
                "bn_read_le(keys->ask, &ask_scalar);",
                "redpallas_scalar_mult_spendauth_G(&ask_scalar, &ak_point);",
                "redpallas_scalar_mult_spendauth_G_progress(&ask_scalar, "
                "&ak_point, NULL, NULL);"):
            with self.subTest(statement=statement):
                with self.assertRaisesRegex(AssertionError, "must not call"):
                    check_address_derivation(self.with_statement(statement))


if __name__ == "__main__":
    unittest.main()
