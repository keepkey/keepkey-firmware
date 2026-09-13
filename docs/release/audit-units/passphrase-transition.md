# Passphrase setting changes invalidate wallet selection

Carry the accepted foundation's storage_setPassphraseProtected implementation
and five PassphraseTransition regressions into this product. Changing the setting
clears cached seed/passphrase material and authenticator state; an unchanged setting
retains the confirmed wallet. Preserve PIN authorization and staged setup state.

The source is release/715-00-foundation at 843a01ff2, where H03 recorded this fix.
The product still had the original assignment-only setter. Scope is the setter
and its regression suite; no flash-format or authorization-policy redesign.

Local result: all five transition tests pass on this product's emulator build,
including enable/disable wallet selection, unchanged settings, PIN preservation
and staged setup. Full assembled product checks remain required.
