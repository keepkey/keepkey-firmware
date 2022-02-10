FROM kktech/firmware:v15

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
