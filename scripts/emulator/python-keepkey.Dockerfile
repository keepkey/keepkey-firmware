# Split into a `deps` stage on purpose. The dependency layers below are
# stable across commits and worth caching; the COPY layer beneath them ships
# the whole build context and is invalidated by every commit, so exporting it
# to a layer cache is pure cost with no possible hit. CI caches `deps` only.
# Parameterised because buildx's docker-container driver resolves FROM
# against a registry rather than the local daemon, so CI must be able to
# point it at the GHCR mirror explicitly. The default keeps plain
# `docker build` and local use working unchanged.
ARG BASE_IMAGE=kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2
FROM ${BASE_IMAGE} AS deps

# Extra Python deps needed by tests that aren't in the shared base image.
# - rlp + eth-keys + eth-utils: build the canonical EIP-1559 type-2 pre-image
#   and ECDSA-recover the signer in test_msg_ethereum_signtx_chunked_data_eip1559.
# - pycryptodome: backend for eth-utils.keccak (else import-time ImportError).
# Base image is Alpine 3.8 (Python 3.6.9). cytoolz (transitive eth-utils dep)
# compiles a C extension at install time and needs Python.h + a C toolchain
# linked against musl. Verified locally against the pinned image.
RUN apk add --no-cache python3-dev gcc musl-dev
RUN python3 -m pip install --no-cache-dir rlp eth-keys eth-utils pycryptodome

FROM deps

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
