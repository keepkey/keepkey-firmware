# T5 — Cut Off pre-screen (#428/#481/#482), hardware round

Device: 7.14.2, variant KeepKey, device_id 39353036114736342A004600, AdvancedMode=False.
Vehicle: `Ping` with `button_protection` — `fsm_msgPing` -> `confirm(..., "Ping", "%s", msg->message)`.

## VERDICT: PASS

| body | ButtonRequests | result |
|---|---|---|
| 100 ch | 1 | one screen, no warning |
| 117 ch | 1 | three full rows, no warning |
| 118 ch | 2 | CUT OFF — boundary is 118 |
| 119 ch | 2 | CUT OFF |
| 255 ch | 2 | CUT OFF |

- **#481 confirmed on hardware.** Boundary is 118, not the 119 the plan predicted.
  A clipped final glyph no longer reports as fitting (`draw.c:213-219`).
- **#482 confirmed on hardware.** The Cut Off screen emits its own ButtonRequest
  (`code=1`, ButtonRequest_Other), so an auto-approving host cannot deadlock.
- No false positives at 100 or 117.
- Host `Cancel` aborts correctly.

The plan's stated expectation that "only one ButtonRequest goes on the wire either
way" is stale — it predates #482. The count is now 1 for a fitting body and 2 for
a truncated one, and that count IS the #482 evidence.

## FINDING — "Hold to view it anyway" discloses nothing (#485)

`confirm_sm.c:441` re-draws the SAME truncated body after the warning:

    return confirm_screen(request_title, request_body, ...);

`request_body` is unchanged and the generic `confirm()` path has no pager. The
byte-exact pager (`confirm_bytes()`, n/m counters) covers only the three
SignMessage handlers. The hidden remainder stays hidden; the second hold shows
the user nothing new.

This is a source-level fact, independent of any hardware measurement.

## RETRACTED — the "release bounce" defect (#484, PR #486, both closed)

An earlier version of this document reported that a confirm screen accepted the
release bounce of the previous hold as consent, based on screens completing at
~1.6s with the tester "not touching the button". The tester was pressing it. No
such defect exists.

**The control that refutes it:** a SINGLE confirm screen (117 chars, one
ButtonRequest), acked and left alone, completed at 5.076s. With no preceding
screen there is no transition and no bounce to inherit.

**Method rules adopted for the remaining tests, T1-T4 and T6-T12:**

1. **Never infer "no press" from a timing.** Absence of physical input is not
   observable from the host. Do not design a pass criterion that depends on it.
2. **Prefer wire-level counts.** The ButtonRequest count is exact, host-visible,
   and independent of the tester. Everything T5 genuinely proved came from it.
3. **Use host `Cancel` for abort tests**, never "the tester declines to press" —
   Cancel is deterministic and the device honours it.
4. **A fix that does not move its target metric is refuted, not inconclusive.**
   The #484 fix moved 1.602s to 1.662s and I read that as noise.
5. **Check the mechanism against the numbers.** CONFIRM_TIMEOUT_MS is 1200ms, so
   confirming needs a press held over a second; a contact bounce is microseconds.
   That contradiction was visible in the first measurement.

## Trap (real, keep)

An aborted run leaves a ButtonRequest queued that survives into the next session,
and the next run answers it silently — observed as BR1 returning code=4 instead of
the Ping's own code=23. `hwpreflight.idle_or_die()` now guards every script, and
the first-code assertion catches the rest.

## Reproduce

    cd deps/python-keepkey/tests
    PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python python3 cutoff_428.py
