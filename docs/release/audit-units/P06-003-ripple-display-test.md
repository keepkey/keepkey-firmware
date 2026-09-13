# P06-003: permanent displayed-address regression

Pin host 81b950da16209c492a956bb4969db93963e01c4f, fork PR
https://github.com/BitHighlander/python-keepkey/pull/77, above firmware
885609fbe (the response lifetime fix).

The existing screenshot-selected Ripple address test now asserts the returned
known address for 7.15. Earlier versions retain display execution pending their
separate fix. The assertion exposed an empty response before P06-002 and passes
afterward. All three address host tests pass with screenshot capture on the
fixed full emulator. No firmware source changes in this unit.

The exact host commit is fetchable through the configured submodule URL.
Combined CI remains pending. This test does not prove physical OLED behavior
or close other-release and full Ripple audit obligations.
