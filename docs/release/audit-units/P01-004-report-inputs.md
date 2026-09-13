# P01-004: Require native report evidence (7.15)

Status: bounded fix validated locally; phase integration and complete release audit pending.

The report discovered native XMLs with a glob, which silently omitted missing
suites. Require each product's emitted native suite by name, nonempty content,
parseable XML and at least one test case before merging report evidence.

Validation: actual native XML artifacts from CI run 34283763680 are accepted;
16 missing, empty, malformed and no-case mutations are rejected.
The repeatable rehearsal is `docs/release/rehearsals/native_report_inputs.py`
on the phase-scope branch (PR #668). Python syntax and whitespace checks pass.

Also require the downloaded screenshot directory and screenshot-selection JUnit;
refuse malformed merged inputs, and audit against the screenshot-selection JUnit.
Main-entry rehearsal accepts a valid fixture and rejects missing screenshots,
missing selection and malformed Python XML before invoking the renderer. It mocks
ARM provenance, Git revision lookup and the external renderer only to isolate
these input gates; it does not establish PDF, ARM or screenshot-content validity.

The 72 Zcash cases already exist in firmware.xml. No duplicate standalone native
suite or new CMake registration is required by this change.
