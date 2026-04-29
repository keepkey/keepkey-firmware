FROM kktech/firmware:v15

# Extra Python deps needed by tests that aren't in the shared base image.
# - rlp + eth-keys + eth-utils: build the canonical EIP-1559 type-2 pre-image
#   and ECDSA-recover the signer in test_msg_ethereum_signtx_chunked_data_eip1559.
# - pycryptodome: backend for eth-utils.keccak (else import-time ImportError).
#
# Base image is Alpine Linux 3.8 (apk, not apt-get). cytoolz (transitive
# dep of eth-utils) compiles a C extension, which needs python3-dev for
# Python.h plus musl-dev for Alpine's libc headers and gcc for the toolchain.
RUN apk add --no-cache python3-dev musl-dev gcc
RUN python3 -m pip install --no-cache-dir rlp eth-keys eth-utils pycryptodome

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]