FROM kktech/firmware:v13

WORKDIR /kkemu
COPY ./ /kkemu

ENTRYPOINT ["/bin/sh", "./scripts/emulator/python-keepkey-tests.sh"]
