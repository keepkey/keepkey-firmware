"""Regression checks for the Pallas public/secret API boundary gate."""

import unittest

from check_pallas_api_boundary import PALLAS_CT_INCLUDE, forbid, function_body, require


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

    def test_include_of_the_ct_header_is_found_in_every_spelling(self):
        for line in ('#include "pallas_ct.h"', "#include <pallas_ct.h>",
                     '#include "trezor/crypto/pallas_ct.h"',
                     "  #  include <crypto/pallas_ct.h>"):
            self.assertTrue(PALLAS_CT_INCLUDE.search(line + "\n"), line)
        self.assertFalse(PALLAS_CT_INCLUDE.search('#include "pallas.h"\n'))

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

    def test_production_guard_and_closed_blocks_are_accepted(self):
        source = ("#if 0\nvoid old(void) {}\n#endif\n#if ZCASH_PRIVACY\n"
                  "void sign(void) {\n  g();\n}\n#endif\n")
        require(function_body(source, "sign"), "g()", "sign")


if __name__ == "__main__":
    unittest.main()
