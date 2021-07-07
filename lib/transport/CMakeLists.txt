set(sources
    pb_common.c
    pb_encode.c
    pb_decode.c)

set(protoc_pb_sources
    ${DEVICE_PROTOCOL}/types.proto
    ${DEVICE_PROTOCOL}/exchange.proto
    ${DEVICE_PROTOCOL}/messages-eos.proto
    ${DEVICE_PROTOCOL}/messages-nano.proto
    ${DEVICE_PROTOCOL}/messages-binance.proto
    ${DEVICE_PROTOCOL}/messages-cosmos.proto
    ${DEVICE_PROTOCOL}/messages-ripple.proto
    ${DEVICE_PROTOCOL}/messages-tendermint.proto
    ${DEVICE_PROTOCOL}/messages-thorchain.proto
    ${DEVICE_PROTOCOL}/messages.proto)

set(protoc_pb_options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/types.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/exchange.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-eos.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-nano.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-binance.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-cosmos.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-ripple.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-tendermint.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-thorchain.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages.options)

set(protoc_c_sources
    ${CMAKE_BINARY_DIR}/lib/transport/types.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/exchange.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-eos.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-nano.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-binance.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-cosmos.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-ripple.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-tendermint.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-thorchain.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages.pb.c)

set(protoc_c_headers
    ${CMAKE_BINARY_DIR}/include/types.pb.h
    ${CMAKE_BINARY_DIR}/include/exchange.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-eos.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-nano.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-binance.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-cosmos.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-ripple.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-tendermint.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-thorchain.pb.h
    ${CMAKE_BINARY_DIR}/include/messages.pb.h)

set(protoc_pb_sources_moved
    ${CMAKE_BINARY_DIR}/lib/transport/types.proto
    ${CMAKE_BINARY_DIR}/lib/transport/exchange.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-eos.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-nano.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-binance.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-cosmos.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-ripple.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-tendermint.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-thorchain.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages.proto)

add_custom_command(
  OUTPUT
    ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp
    ${protoc_c_sources}
    ${protoc_c_headers}
  WORKING_DIRECTORY
    ${CMAKE_BINARY_DIR}/lib/transport
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/include/keepkey/transport
  COMMAND
    ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/lib/transport
  COMMAND
    ${CMAKE_COMMAND} -E copy ${protoc_pb_options} ${CMAKE_BINARY_DIR}/lib/transport
  COMMAND
    ${CMAKE_COMMAND} -E copy ${protoc_pb_sources} ${CMAKE_BINARY_DIR}/lib/transport
  COMMAND
    ${CMAKE_COMMAND} -E copy
      ${DEVICE_PROTOCOL}/google/protobuf/descriptor.proto
      ${CMAKE_BINARY_DIR}/lib/transport/google/protobuf/descriptor.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f types.options:." types.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f exchange.options:." exchange.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-eos.options:." messages-eos.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-nano.options:." messages-nano.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-binance.options:." messages-binance.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-cosmos.options:." messages-cosmos.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-ripple.options:." messages-ripple.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-tendermint.options:." messages-tendermint.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages-thorchain.options:." messages-thorchain.proto
  COMMAND
    ${PROTOC_BINARY} -I. -I/usr/include
      --plugin=nanopb=${NANOPB_DIR}/generator/protoc-gen-nanopb
      "--nanopb_out=-f messages.options:." messages.proto
  COMMAND
    ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/lib/transport/*.pb.h
       ${CMAKE_BINARY_DIR}/include
  COMMAND
    sh -c "! grep -r pb_callback_t ${CMAKE_BINARY_DIR}/include/*.pb.h" || (echo "pb_callback_t forbidden. missing .options entry?" && false)
  COMMAND
    ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp
  DEPENDS
    ${protoc_pb_sources} ${protoc_pb_options})

add_custom_target(kktransport.pb ALL DEPENDS ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp)

add_library(kktransport ${sources} ${protoc_c_sources})
add_dependencies(kktransport kktransport.pb)
