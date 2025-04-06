FROM kkfirmware:v16

WORKDIR /kkemu
COPY ./ /kkemu

ARG coinsupport=""
RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=Debug \
    ${coinsupport} \
    -DCMAKE_COLOR_MAKEFILE=ON

RUN make -j

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/armEmulator/run.sh"]

