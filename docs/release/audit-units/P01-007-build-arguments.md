# P01-007: Preserve local release build arguments

Status: invocation contract rehearsed; actual phase ARM rebuild pending.

The added extra-CMake-argument interface flattened $* into a shell command.
A single argument such as `-DCMAKE_C_FLAGS=-O2 -g` consequently became two
arguments in the container. Pass original arguments as positional parameters
and expand quoted "$@" inside the container instead. Quote the checkout path
and bind mount at the same invocation boundary.

Validation: bash syntax, shellcheck and whitespace checks pass. A disposable
checkout with spaces ran the actual wrapper against fake Docker/compiler tools.
The captured container command then ran under /bin/sh with only its fixed /root
filesystem prefix redirected to a temporary directory. Zero extra arguments,
Bitcoin-only selection, a spaced CMake value and literal shell-expression text
arrived unchanged at the fake compiler. No Docker build, signing or publication
was performed. Repeatable fixture is release_arguments.py on scope PR #668.

This corrects the 7.15 argument interface. Older products do not advertise that
interface; no extra-argument feature was backported to them.
