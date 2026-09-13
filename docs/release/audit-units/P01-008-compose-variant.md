# P01-008: Keep Bitcoin-only unit images separate

Status: resolved Compose configuration checked; phase integration pending.

The Bitcoin-only override selected Bitcoin-only compiler flags for firmware-unit
but inherited its regular `kktech/kkemu:latest` image tag. The emulator service
used `kktech/kkemu-bitcoin-only:latest`. Thus builds could overwrite the regular
image with Bitcoin-only code, while unforced local runs could reuse the regular
image for supposedly Bitcoin-only unit tests.

Set the unit service to the same Bitcoin-only image identity as its emulator.
`docker compose config --format json` confirms full and Bitcoin-only configurations
now bind both firmware services to the matching image and compiler flags.
Whitespace validation passes. Configuration resolution needs no daemon and did
not build/run containers; actual runtime suite validation remains an integration
gate. The obsolete Compose version-key warning is unrelated to this binding.
