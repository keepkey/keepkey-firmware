# Release Rehearsal SOP

Lessons learned from the 7.14.0 release rehearsal. One-page checklist for every PR and merge cycle.

---

## Preflight Checklist (before opening or updating any PR)

| # | Check | How |
|---|-------|-----|
| 1 | Branch target correct | `develop` for features, `master` for releases only |
| 2 | No merge commits from unrelated features | `git log --merges` shows only your own merges |
| 3 | Submodule URLs point upstream | All remotes are `keepkey/*`, not `BitHighlander/*` |
| 4 | Submodule SHAs are intentional and documented | Pin table in PR description (see below) |
| 5 | Changed Python files compile | `python3 -m py_compile` on every changed `.py` file |
| 6 | Shared dispatch files reviewed as a set | `fsm.h`, `fsm.c`, `messagemap.def`, `CMakeLists.txt` |
| 7 | PR scope matches title | No superset branches; diff is exactly what the title says |

---

## Hard Gates

- **No Python push** without `py_compile` on changed files.
- **No branch push** without submodule audit.
- **No PR from branches** containing merge commits from other features.
- **No upstream push/PR** without explicit approval.
- **No direct pushes to develop** — all changes through PRs. Rehearsal means PRs.
- **PRs >50 files** require explicit justification in the PR body.
- **PRs >1000 LOC** must be either infra/release or an isolated chain feature.
- **Master PRs with multiple feature areas**: reject unless intentional release PR.

---

## Submodule Pin Strategy

At session start, audit ALL active branches and build a pin table:

| branch | device-protocol SHA / URL | python-keepkey SHA / URL | trezor-firmware SHA / URL |
|--------|---------------------------|--------------------------|---------------------------|
| develop | `<sha>` keepkey/device-protocol | `<sha>` keepkey/python-keepkey | `<sha>` keepkey/trezor-firmware |
| feature/xyz | ... | ... | ... |

Normalize all submodule URLs to upstream (`keepkey/*`) before making any code changes.

---

## Batch Conflict Strategy

These four files form a **conflict set** across all chain PRs:

- `include/keepkey/firmware/fsm.h`
- `lib/firmware/fsm.c`
- `lib/firmware/messagemap.def`
- `lib/firmware/CMakeLists.txt`

Resolve all chain PRs against them in **one local pass**. Never push-wait-fail-retry through GitHub.

---

## Rehearsal Merge Order

1. **Zoo infra PR first** — must merge before all other PRs so the zoo workflow and artifact pipeline exist on develop. Without this, all subsequent PRs fail the zoo-report check.
2. **Feature PRs via PR, not git merge** — open PR → CI triggers → verify green + artifacts → merge → next PR. Never merge directly.
3. **Pre-zoo branches** — feature branches created before zoo infra will not have `scripts/zoo/`. The zoo workflow gracefully skips (checks for `package.json`). Artifact verification starts after zoo infra merges.

## Per-Phase Validation

After each merge to `develop`:

| Phase | Scope | Validation |
|-------|-------|------------|
| 0 | Zoo infra | Zoo workflow succeeds, 4 artifacts downloadable, PDF has 7 critical |
| 0 | Fixes | CI green, existing tests pass, zoo skips gracefully |
| 1-2 | Features | Feature-specific smoke test + zoo artifacts |
| 3-6 | Chain additions | Per-chain address/sign + zoo artifacts with chain pages |
| 7 | Release | Full emulator sweep + real device + final zoo report |

---

## CI Artifact Verification

Every PR to `develop` or `master` must produce downloadable artifacts:

| Artifact | Contents | Required For |
|----------|----------|-------------|
| `zoo-report-{pr}` | Master zoo PDF (49 screens, 20 flows) | Every PR |
| `zoo-pages-{pr}` | Individual OLED screen PNGs | Every PR |
| `zoo-feature-reports-{pr}` | Per-chain markdown reports | UI-changing PRs |
| `zoo-testing-guides-{pr}` | Layer 2/3/4 test plans | Every PR |

**After each PR merge**, verify:
1. Artifacts are downloadable from the Actions run
2. Zoo PDF renders all flows (no blank pages)
3. Per-feature report covers the chain being added
4. Page count matches expected (currently 49)

Release branch (`release/**`) also triggers artifact generation on push.

---

## Final Merged-State Checklist

Before upstreaming to `keepkey/keepkey-firmware`:

- [ ] Fork `develop` is CI-green end-to-end
- [ ] Final device testing completed on the merged state
- [ ] Security sign-off recorded for sensitive PRs
- [ ] Upstream submodule repinning checklist prepared
- [ ] Zoo report artifact generated and downloaded
- [ ] All per-feature reports present in artifacts
- [ ] Testing guides present in artifacts
- [ ] Artifact content reviewed (not just existence verified)
