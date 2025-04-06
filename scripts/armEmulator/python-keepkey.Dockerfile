FROM kkfirmware:v16

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/armEmulator/python-keepkey-tests.sh"]
