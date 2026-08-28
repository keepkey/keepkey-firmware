# The Test Atlas — what it is, how to read it, what it cannot tell you

The atlas is `SECTIONS` in
`deps/python-keepkey/scripts/generate-test-report.py`. It produces the PDF test
report, and it drives the screenshot filter. Those two facts together are the
single most important thing to understand about it:

> **A test that is not in SECTIONS is captured by nothing and appears nowhere.**
> Adding a test does not put it in the report. Cataloguing it does.

---

## 1. How to read a report

The header line is the verdict:

```
Firmware 7.15.0 | 2026-08-21 20:12 | 376 tests: 372 passed, 4 skipped, 0 pending
Candidate: alpha@d3bb0055f...
```

**The four counts add up to the total, and the report asserts it** before
printing. They once did not: the scope paragraph rebound `skipped` to the
run-wide census, so the catalog's breakdown quoted a skip count from a
different population and nothing reconciled. The total counts DISTINCT tests,
not catalog rows — a few tests are deliberately catalogued twice because they
carry two different arguments (J9 and VG2 are the same refusal), and summing
rows made the header claim more tests than the run contains.

Read the **candidate** first. A report is evidence about one commit. A green
report for a tree that is not the one you are shipping proves nothing about the
one you are.

Then read the three counts, which mean different things:

| word | meaning | is it evidence? |
|---|---|---|
| **passed** | ran, asserted, succeeded | yes |
| **skipped** | did not execute | **no** |
| **pending** | catalogued, no result at all | **no** |
| **withheld** | every test in the section skipped | **no** |

A skip is never evidence a feature works. The report says so on page 1, and it
says so because an RC audit once grepped the PDF for feature keywords, found
none, and reported four features as untested when their tests had run green in
the same CI run.

## 2. Section states

- **Tested** — at least one test produced a real result.
- **Withheld on this build** — every test skipped *by design*, e.g. the
  bitcoin-only section on a full-feature emulator. Legitimate, but it means this
  report carries no evidence for that section. Get it from the other product's
  report.
- **Pending (no firmware support yet)** — nothing ran. Usually the feature is
  absent. **Sometimes it is a wiring bug**: the Storage Upgrade Preservation
  section rendered "pending" while all eight of its tests were passing, because
  `parse_junit()` only recognised three module-name families. A pending section
  whose tests you believe exist is a bug in the report, not in the firmware.

## 3. Version gating

Each section carries a `min_fw`. A section is active only when
`ver_ge(fw_version, min_fw)`. This is what makes a release cut mechanical:

| FW_VERSION | active sections |
|---|---|
| 7.14.2 | 18 |
| 7.15.0 | 26 |

`FW_VERSION` comes from `CMakeLists.txt`, and getting it wrong silently narrows
what is checked. It has happened: CI read `7.14.0` for an entire release, which
excluded every 7.14.1+ section from screenshot capture — the release's own
screens were never looked at by anything. The runner now FAILS rather than
defaulting.

## 4. What a section must contain

```python
('F', 'Clear-Sign Provider Context - Additive Invariant', '7.15.0',
 'Background: what this proves and why it matters.',
 [ 'the rules, as bullet lines' ],
 [ ('F1', 'test_module', 'test_method',
    'short title',
    'what the device must do, and why',
    ['screen 1', 'screen 2']) ])
```

The screenshot list drives capture. **An empty list is legitimate and
deliberate** for a refusal path that draws nothing — its evidence is the Failure
on the wire plus the *absence* of a ButtonRequest. Because empty means
something here, an entry that is empty for a *different* reason must say so on
the line: seven entries once declared screens their test cannot draw at all
(the `getaddress` tests answer on the wire; the drawing is the `show_address`
sibling), and the audit that catches this failed on every run until someone
read it.

Every entry needs a **context** — the sentence saying what it proves. An entry
without one renders as a bare test name, which is exactly the row an auditor
cannot evaluate. `_audit_catalog()` asserts it on every render, along with
unique section letters and unique test ids.

A module listed in `MUST_RUN_MODULES` turns a skip into a failure from the
named firmware version onward. Use it for a capability the build CLAIMS to
have: taproot tests open with `requires_taproot()`, so a regressed capability
would skip all six and the report would still read green — certifying coverage
it never obtained.

For a claim about ORDER, add the test to `FULL_SEQUENCE_TESTS`, or the report
shows a best-of-3 frame sample and hides the very thing being proved.

## 5. Measuring screens without being lied to

The confirm driver preloads accept/reject pairs; each screen consumes two
packets.

- `drain() == 0` → exactly N screens shown
- `drain() > 0` → **fewer** screens than budgeted
- `drain() < 0` → **more** than expected (the sentinel was eaten)
- preload one too few → the test **hangs** rather than failing

Screen counts are value-dependent: `confirm()` paginates a body over
`BODY_ROWS = 3`, and bytes outside `0x21..0x7e` render as 4-glyph `\xNN`
escapes — **space included**. Measure with an over-large preload
(`screens = N - drain/2`); never model it.

## 6. The traps that have actually cost releases

1. **A skip that hides a defect.** Three Uniswap liquidity tests were skipped
   whenever the variant started with `"Emulator"`. The emulator is the only
   thing CI runs, so they had never executed on any branch — and they were
   hiding a defect that made Uniswap liquidity unsignable to a third party.
2. **A capability that is implemented but not advertised.** Taproot signing
   worked; the firmware never set `supports_taproot`, so six catalogued tests
   skipped and the report showed a shipped feature as untested.
3. **A stage-1 CI gate failing and skipping the whole build graph.** Six jobs
   reported "skipped" and the run looked like one red job instead of a release
   with no evidence behind it.
4. **Lifting a skip incorrectly.** Replacing `self.skipTest(...)` with `pass`
   leaves the following `return`, so the body never runs and the test "passes"
   vacuously in ~0.1 s. Delete the whole guard. A suspiciously fast pass is the
   tell.
5. **Testing the wrong product.** `requires_fullFeature()` skips on
   `KeepKeyBTC`/`EmulatorBTC`. Until the firmware reported the variant honestly
   it never skipped anything, and multi-chain tests ran against a device with
   those chains compiled out.

## 7. What the atlas still cannot tell you

- **Whether the screen says the right words.** Frames are compared as bytes.
  Tests prove a screen is the SAME screen as a baseline; they do not read it.
  Text-level judgement is human review of the captured PNGs — that is what
  gate 3 is for.
- **Anything about real hardware.** Every number here is the emulator.
- **Whether a section is complete.** The atlas is a curated catalog: 374 of 879
  collected tests. Absence from the report is not evidence of absence of
  coverage — check the JUnit artifacts.
