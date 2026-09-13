# P01-006: Reject absent Bitcoin-only disassembly evidence

Status: fixed and checked against existing ARM artifacts; phase integration pending.

An empty `--disassembly` file exited zero and reported privacy code absent.
Require decoded instructions and a symbol heading before the Bitcoin-only
absence check. Full mode already requires its named multiplier symbols.

Validation: saved full and Bitcoin-only ARM ELFs from CI 34283763680 still pass
with arm-none-eabi-objdump output. Empty, garbage and symbol-only inputs fail;
the full image fails the Bitcoin-only exclusion check; deleting the full
multiplier symbol fails full mode. Python syntax and whitespace checks pass.

This validates the input gate. The disassembly shape check is not a proof of
constant-time arithmetic: backward branches still need fixed-bound source
review, and memory access patterns and secret/public data classification need
independent P08/dependency review. No cryptographic implementation changed.
