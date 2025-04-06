FROM kktech/firmware:v16

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
