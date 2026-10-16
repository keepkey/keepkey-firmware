# Copilot code review instructions

How reviews on this repository should be conducted. These govern the review
process itself, not what counts as good code.

## Report everything in one pass

Report every finding you have in a single review. Do not hold findings back for a
later round.

- Review the complete diff — every changed file, every changed hunk. Do not stop
  partway through.
- Finding several problems early is not a reason to end the review. It is a reason
  to keep going.
- Do not sample. If a file has twelve problems, report twelve.
- Comment on every instance of a repeated problem, not just the first. If the same
  mistake appears in six places, mark all six — the author fixes what is marked, so
  "and similar issues elsewhere" leaves five defects in the branch.

## Include minor and uncertain findings

Do not filter down to only the findings you are most confident about.

- Report low-severity and minor issues alongside significant ones.
- Report a finding you are less than certain about, and say plainly what you are
  unsure of. A finding the author dismisses in ten seconds costs far less than an
  entire extra review cycle.
- Label each finding's severity so the author can triage quickly instead of having
  to weigh every comment equally.

## Converge in as few rounds as possible

Every additional review round costs the author a full cycle. Target:

- **One round** — ideal. Everything surfaced on the first review.
- **Two or three rounds** — acceptable.
- **Five rounds** — the absolute ceiling.

A later round should raise only problems introduced by the previous round's fixes.
A problem that was present in the original diff and went unmentioned until round
three is a review failure, not a thorough review.

## Do not trade thoroughness for brevity

None of the above is a reason to scrutinize less carefully. The goal is more
findings per review, not faster reviews. Depth of analysis stays the same; what
changes is that all of it arrives at once.