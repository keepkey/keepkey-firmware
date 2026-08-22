# #488 pager — hardware validation

Device: 7.14.2, fw_hash `f19ad98f235aecd1` (= sha256 of the flashed
`firmware.keepkey.v7.14.2-b294e19-firmware.keepkey.bin`), uninitialised.
Vehicle: `Ping` with `button_protection`, 255-character digit-ramp body.

## VERDICT: PASS (5/5)

| # | check | result |
|---|---|---|
| Q1 | pages render on glass | PASS — `PING 1/3`, `2/3`, `3/3` |
| Q2 | a short click advances an intermediate page | PASS |
| Q3 | **a tap does NOT approve the final page** | **PASS** — 15s silence |
| — | a hold DOES approve the final page | PASS — `Success` at **1.650s** |
| Q4 | digit ramp continuous across seams | PASS |

The Q3/hold pair is the security property, and it is measured rather than
reported: the same finger, the same page, a tap yields silence and a hold yields
`Success` at 1.650s — consistent with `CONFIRM_TIMEOUT_MS` (1200) plus the
confirm animation.

Click to page, hold to approve. Reading what you are shown costs a click;
consenting to it still costs a hold.

## CI complements this, and neither is sufficient alone

CI captured the *rendering* (`PING 2/3`, `3/3`, and the short-body control
staying unnumbered) once the screenshot pipeline was fixed. It cannot capture
press durations — there is no physical button in the emulator. Hardware measured
the durations. Neither half proves the feature on its own.

`PING 1/3` came out blank in the CI capture. That is a capture race, not a
rendering defect: `confirm()` writes the first `ButtonRequest` before
`confirm_helper()` runs, and the pager counts pages before drawing page 1, so a
host that screenshots on receipt catches the canvas mid-work. It renders
correctly on glass. Cosmetic; worth fixing so CI shows all three pages.

## Process note — a false FAIL, caught by asking

The first Q3 run reported **FAIL: a CLICK approved the final page** and
recommended reverting #488. It was wrong. The test only observed "`Success`
arrived" and inferred the press type; the tester had held.

That is the identical error as fw #484 earlier the same day: inferring an
unobservable (how long a button was pressed) from an observable (a timing),
with no control able to separate them. It did not become a second retracted PR
only because the tester was asked what they did rather than the result being
taken at face value.

The instrumented re-run timestamps from the moment the final page is displayed,
so a sub-600ms approval and a >1.2s approval are distinguishable, and a tap that
approves nothing produces silence — a positive, checkable outcome instead of an
inference.

**Rule, restated:** never let a pass/fail criterion rest on how a human pressed a
button unless the two outcomes are separable in the data.

## Reproduce

    cd deps/python-keepkey/tests
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 pager_q3.py    # tap -> silence
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 pager_hold.py  # hold -> Success

Replug between runs; `hwpreflight.idle_or_die()` refuses to start on a dirty
device — it caught exactly that between these two runs.
