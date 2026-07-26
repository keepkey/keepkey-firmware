FROM kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2

# Extra Python deps needed by tests that aren't in the shared base image.
# - rlp + eth-keys + eth-utils: build the canonical EIP-1559 type-2 pre-image
#   and ECDSA-recover the signer in test_msg_ethereum_signtx_chunked_data_eip1559.
# - pycryptodome: backend for eth-utils.keccak (else import-time ImportError).
# Base image is Alpine 3.8 (Python 3.6.9). cytoolz (transitive eth-utils dep)
# compiles a C extension at install time and needs Python.h + a C toolchain
# linked against musl. Verified locally against the pinned image.
RUN apk add --no-cache python3-dev gcc musl-dev
RUN python3 -m pip install --no-cache-dir rlp eth-keys eth-utils pycryptodome

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
