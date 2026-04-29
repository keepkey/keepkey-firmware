FROM kktech/firmware:v15

# Extra Python deps needed by tests that aren't in the shared base image.
# - rlp + eth-keys + eth-utils: build the canonical EIP-1559 type-2 pre-image
#   and ECDSA-recover the signer in test_msg_ethereum_signtx_chunked_data_eip1559.
# - pycryptodome: backend for eth-utils.keccak (else import-time ImportError).
RUN apt-get update && apt-get install -y python3-dev gcc && rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --no-cache-dir rlp eth-keys eth-utils pycryptodome

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]