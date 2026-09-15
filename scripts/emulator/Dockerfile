# Parameterised for the same reason as python-keepkey.Dockerfile: CI resolves
# the base through a GHCR mirror and must be able to point FROM at it, while a
# plain `docker build` keeps working unchanged.
#
# The DEFAULT is a digest, not the :v15 tag develop carries. A release build
# has to name an immutable base. A moving release tag may resolve to this
# digest today, but a signed release should not depend on that. CI overrides
# it with the mirror it resolved, which is the same image either way.
ARG BASE_IMAGE=kktech/firmware@sha256:7438e53933d47d53157ed6d96d864cb208597e62dce26235ace09d1063427fa2
FROM ${BASE_IMAGE}

WORKDIR /kkemu
COPY ./ /kkemu

ARG coinsupport=""
RUN cmake -C ./cmake/caches/emulator.cmake . \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    ${coinsupport} \
    -DCMAKE_COLOR_MAKEFILE=ON

RUN make -j

EXPOSE 11044/udp 11045/udp
EXPOSE 5000
CMD ["/kkemu/scripts/emulator/run.sh"]
