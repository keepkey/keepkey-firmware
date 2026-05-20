FROM kktech/firmware:v15

WORKDIR /kkemu
COPY ./ /kkemu
RUN python3 -m pip install --no-cache-dir "protobuf==3.20.3"

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
