Release Process
===============

1. Run the emulator unittests: `make all test`.
1. Run the integration tests in the `python-keepkey` testsuite against the emulator.
1. Build a debug build of the firmware, and run the `python-keepkey` tests against it.
1. Increment the version in the top-level CMakeLists.txt
1. Tag the release on github.
    * Source must be published with every firmware release so that:
        1. Users can "don't trust; verify" it.
        1. We stay in compliance with the GPL license.
1. Build a release build of the firmware on multiple different machines, and compare firmware hashes.
1. Sign it on the airgapped machine with 3/5 signers.
1. Double check that storage upgrade preserves keys on a production device.
1. Upload the signed firmware to github.
1. Publish release notes on github.
