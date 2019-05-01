FROM kktech/firmware:v8

WORKDIR /kkemu
COPY ./ /kkemu

RUN python -m ensurepip
RUN pip install \
    "ecdsa>=0.9" \
    "protobuf>=3.0.0" \
    "mnemonic>=0.8" \
    requests \
    flask \
    pytest

RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_COLOR_MAKEFILE=ON

RUN make -j

EXPOSE 21324/udp 21325/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]

