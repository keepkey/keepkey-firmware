FROM kktech/firmware:v12

WORKDIR /kkemu
COPY ./ /kkemu

RUN python -m ensurepip
RUN pip install \
    "ecdsa>=0.9" \
    "protobuf>=3.0.0" \
    "mnemonic>=0.8" \
    requests \
    pytest \
    semver

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
