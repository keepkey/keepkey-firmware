# Coin Integration Guide for KeepKey Firmware

This guide explains the submodule-first workflow required when adding new coin
support to the firmware. If you skip or reorder these steps, CI will fail
because the firmware's submodule commits won't resolve.

## Repository Map

The firmware repo has 7 submodules. Three matter for coin integration:

| Submodule | Path | Upstream URL | Fork URL | Purpose |
|-----------|------|-------------|----------|---------|
| device-protocol | `deps/device-protocol` | `keepkey/device-protocol` | `BitHighlander/device-protocol` | Protobuf message definitions |
| python-keepkey | `deps/python-keepkey` | `keepkey/python-keepkey` | `BitHighlander/python-keepkey` | Python client + integration tests |
| trezor-firmware | `deps/crypto/trezor-firmware` | `keepkey/trezor-firmware` | (keepkey org) | Crypto primitives (curves, hashing) |

**Critical**: `.gitmodules` points to upstream `keepkey/*` URLs. For development
branches with commits that don't exist upstream yet, you must temporarily change
the URLs to point to your fork.

## The Submodule-First Workflow

### Why Order Matters

When CI clones the firmware, it runs `git submodule update --init`. The submodule
commits referenced in the firmware tree must exist in the repos that `.gitmodules`
URLs point to. If you add a new proto file to device-protocol and update the
firmware's submodule pointer, but that commit only exists on your fork and
`.gitmodules` still points to upstream — CI fails.

### Dependency Order

```
1. device-protocol fork  →  proto messages
2. trezor-firmware fork  →  crypto primitives (if new curve/algo needed)
3. python-keepkey fork   →  client methods + wire ID registration + tests
4. firmware              →  FSM handlers, derivation, signing + unit tests
```

Each step must be pushed to the correct fork and the commit hash noted before
the next step can reference it.

### Step-by-Step

#### Phase 0: Verify Fork Remotes

For each submodule that needs changes, ensure the fork remote exists:

```bash
cd modules/keepkey-firmware

# device-protocol: check if your fork remote exists
cd deps/device-protocol
git remote -v
# If only 'origin' pointing to keepkey/, add your fork:
git remote add fork https://github.com/BitHighlander/device-protocol.git
git fetch fork
cd ../..

# python-keepkey: same pattern
cd deps/python-keepkey
git remote add fork https://github.com/BitHighlander/python-keepkey.git
git fetch fork
cd ../..

# trezor-firmware (crypto): usually keepkey org has push access
cd deps/crypto/trezor-firmware
git remote -v
cd ../../..
```

#### Phase 1: Device Protocol (Proto Messages)

```bash
cd deps/device-protocol

# Create branch from upstream master
git fetch origin
git checkout -b feature/<coin>-proto origin/master

# Add your proto file
# Example: messages-zcash.proto, messages-solana.proto, etc.
# Also update messages.proto with new MessageType enum values

git add messages-<coin>.proto
git commit -m "feat: add <Coin> protocol messages (IDs XXXX-XXXX)"

# Push to YOUR FORK (not upstream!)
git push fork feature/<coin>-proto

# Note the commit hash — you'll need it for firmware
git rev-parse HEAD
# → abc1234...
```

**Wire ID conventions**: Check existing ranges in `messages.proto` to avoid collisions.
Current allocations:
- Zcash: 1300-1307
- Tron: 1400-1403
- TON: 1500-1503
- Solana: 1200-1205

#### Phase 2: Crypto Primitives (If Needed)

Only needed if the coin requires a new elliptic curve or hash function not
already in trezor-firmware/crypto.

```bash
cd deps/crypto/trezor-firmware

# Check current state
git status

# Create branch from current HEAD
git checkout -b feature/<coin>-crypto

# Add new crypto files
git add crypto/<new_curve>.c crypto/<new_curve>.h
git commit -m "feat: add <curve> primitives for <Coin>"

# Push (usually to keepkey/trezor-firmware directly)
git push origin feature/<coin>-crypto
```

**Examples of coin-specific crypto**:
- Zcash: `pallas.c/h`, `redpallas.c/h` (Pallas curve + RedPallas signatures)
- Solana: `ed25519` (already in repo)

#### Phase 3: Python-KeepKey (Client + Tests)

```bash
cd deps/python-keepkey

git fetch origin
git checkout -b feature/<coin>-tests origin/master

# Add/update:
# 1. keepkeylib/messages_<coin>_pb2.py  — protobuf bindings (or generate from proto)
# 2. keepkeylib/client.py              — add client method(s)
# 3. keepkeylib/mapping.py             — register wire IDs
# 4. tests/test_msg_<coin>.py          — integration tests

git add -A
git commit -m "feat: add <Coin> client methods and tests"

# Push to YOUR FORK
git push fork feature/<coin>-tests
```

**Important**: python-keepkey uses hand-written `_pb2.py` files for protobuf 3.x
compatibility. Do NOT regenerate all proto bindings — only add the new coin's
`_pb2.py` and register wire IDs in `mapping.py`.

#### Phase 4: Firmware (Core Implementation)

Now create the firmware branch with updated submodule pointers:

```bash
cd modules/keepkey-firmware

# Branch from develop
git checkout -b feature/<coin> origin/develop

# UPDATE .gitmodules TO POINT TO YOUR FORKS
# This is the critical step most people miss!
git config -f .gitmodules submodule.deps/device-protocol.url \
  https://github.com/BitHighlander/device-protocol.git
git config -f .gitmodules submodule.deps/python-keepkey.url \
  https://github.com/BitHighlander/python-keepkey.git

# Update submodule pointers to your fork branch commits
cd deps/device-protocol
git fetch fork
git checkout <commit-hash-from-phase-1>
cd ../..

cd deps/python-keepkey
git fetch fork
git checkout <commit-hash-from-phase-3>
cd ../..

# If crypto was changed:
cd deps/crypto/trezor-firmware
git checkout <commit-hash-from-phase-2>
cd ../../..

# Stage submodule pointer updates + .gitmodules
git add .gitmodules deps/device-protocol deps/python-keepkey deps/crypto/trezor-firmware

# Now add firmware code:
# - include/keepkey/firmware/<coin>.h
# - lib/firmware/<coin>.c
# - lib/firmware/fsm_msg_<coin>.h
# - include/keepkey/transport/messages-<coin>.options
# - lib/firmware/messagemap.def  (add message registrations)
# - lib/firmware/fsm.c           (add #include and declarations)
# - lib/firmware/CMakeLists.txt   (add source files)
# - lib/transport/CMakeLists.txt  (add proto build steps)
# - unittests/firmware/<coin>.cpp (add unit tests)
# - unittests/firmware/CMakeLists.txt (register test file)

git add -A
git commit -m "feat: add <Coin> support"
git push origin feature/<coin>
```

#### Phase 5: Before Merging Upstream

When your firmware PR is ready to merge into the main `keepkey/keepkey-firmware`:

1. First merge device-protocol changes into upstream `keepkey/device-protocol`
2. First merge python-keepkey changes into upstream `keepkey/python-keepkey`
3. First merge crypto changes into upstream `keepkey/trezor-firmware`
4. **Then** update `.gitmodules` URLs back to `keepkey/*` upstream
5. Update submodule pointers to the upstream merge commits
6. Push the firmware PR

## CI Pipeline

The firmware uses CircleCI with docker-compose:

- **emulator-build-test**: Builds emulator, runs `firmware-unit` and `python-keepkey` tests
- Tests must produce a status file with "0" to pass
- Both unit tests (GoogleTest C++) and integration tests (Python) run

### Making CI Pass

For each PR, ensure:
1. All submodule URLs in `.gitmodules` resolve (fork URLs during development)
2. All submodule commits exist in the repos the URLs point to
3. Firmware builds clean with `cmake` + `make`
4. `firmware-unit` tests pass (GoogleTest, `unittests/firmware/`)
5. `python-keepkey` tests pass (pytest, `deps/python-keepkey/tests/`)

## Common Mistakes

### 1. Forgetting to update .gitmodules URLs
**Symptom**: CI fails with "Could not find remote branch" or "reference is not a tree"
**Fix**: Change `.gitmodules` URLs to point to your fork before pushing

### 2. Pushing submodule changes to upstream instead of fork
**Symptom**: Unauthorized push failure, or accidentally landing unreviewed proto changes
**Fix**: Always add your fork as a separate remote named `fork`, push there

### 3. Not initializing the device-protocol submodule
**Symptom**: `deps/device-protocol` shows as `-` prefix in `git submodule status`
**Fix**: `git submodule init deps/device-protocol && git submodule update deps/device-protocol`

### 4. Regenerating all python-keepkey proto bindings
**Symptom**: Massive diff touching files you didn't mean to change
**Fix**: Only add the new coin's `_pb2.py` file and register wire IDs in `mapping.py`

### 5. Working in detached HEAD without realizing it
**Symptom**: Commits exist locally but can't be pushed, "branch not found"
**Fix**: Always create a named branch before committing in submodules

## File Layout for New Coin

```
keepkey-firmware/
├── deps/
│   ├── device-protocol/
│   │   └── messages-<coin>.proto          ← Proto messages
│   ├── crypto/trezor-firmware/
│   │   └── crypto/<curve>.{c,h}          ← Crypto primitives (if needed)
│   └── python-keepkey/
│       ├── keepkeylib/messages_<coin>_pb2.py
│       ├── keepkeylib/client.py           ← Add client method(s)
│       ├── keepkeylib/mapping.py          ← Register wire IDs
│       └── tests/test_msg_<coin>.py       ← Integration tests
├── include/keepkey/
│   ├── firmware/<coin>.h                  ← Public API
│   └── transport/messages-<coin>.options  ← Nanopb options
├── lib/firmware/
│   ├── <coin>.c                           ← Core implementation
│   ├── fsm_msg_<coin>.h                   ← FSM message handlers
│   ├── fsm.c                              ← #include + declarations
│   ├── messagemap.def                     ← Message registrations
│   └── CMakeLists.txt                     ← Add source file
├── lib/transport/
│   └── CMakeLists.txt                     ← Add proto build steps
└── unittests/firmware/
    ├── <coin>.cpp                         ← Unit tests (GoogleTest)
    └── CMakeLists.txt                     ← Register test file
```

## Existing Coin References

When implementing a new coin, study these existing implementations:

| Coin | Proto | Firmware | Tests | Complexity |
|------|-------|----------|-------|------------|
| Mayachain | messages-mayachain.proto | mayachain.c | mayachain.cpp | Simple (address + sign) |
| Cosmos | messages-cosmos.proto | cosmos.c | cosmos.cpp | Moderate (amino encoding) |
| Ethereum | messages-ethereum.proto | ethereum.c | ethereum.cpp | Complex (EIP-155, tokens) |
| Zcash | messages-zcash.proto | zcash.c | (in progress) | Complex (ZIP-32, Orchard, RedPallas) |

## Branch Naming Conventions

| Repo | Branch Pattern | Example |
|------|---------------|---------|
| device-protocol | `feature/<coin>-proto` | `feature/zcash-proto` |
| trezor-firmware | `feature/<coin>-crypto` | `feature/zcash-crypto` |
| python-keepkey | `feature/<coin>-tests` | `feature/zcash-orchard-tests` |
| keepkey-firmware | `feature/<coin>` | `feature/zcash` |
