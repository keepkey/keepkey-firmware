# Complete storage cipher scratch cleanup

Replay the existing foundation's four missing wipes: clear the IV after encryption
and the AES key schedule after decryption in migration and authenticator block
helpers. Preserve encryption, decryption and persisted bytes.

The unit-only observer compiles the real storage implementation and observes
AES/memzero boundaries while the objects are alive. It is never included in the
production firmware. All four cleanup regressions pass on this product's native
build, covering encryption/decryption for both helpers. Full assembly validation
remains required. This closes the known H02 applicability gap, not a new broad audit.
