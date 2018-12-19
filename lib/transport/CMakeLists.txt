set(sources
    pb_encode.c
    pb_decode.c)

set(protoc_pb_sources
    ${DEVICE_PROTOCOL}/types.proto
    ${DEVICE_PROTOCOL}/exchange.proto
    ${DEVICE_PROTOCOL}/messages-eos.proto
    ${DEVICE_PROTOCOL}/messages.proto)

set(protoc_pb_options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/types.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/exchange.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages-eos.options
    ${CMAKE_SOURCE_DIR}/include/keepkey/transport/messages.options)

set(protoc_c_sources
    ${CMAKE_BINARY_DIR}/lib/transport/types.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/exchange.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages-eos.pb.c
    ${CMAKE_BINARY_DIR}/lib/transport/messages.pb.c)

set(protoc_c_headers
    ${CMAKE_BINARY_DIR}/include/types.pb.h
    ${CMAKE_BINARY_DIR}/include/exchange.pb.h
    ${CMAKE_BINARY_DIR}/include/messages-eos.pb.h
    ${CMAKE_BINARY_DIR}/include/messages.pb.h)

set(protoc_pb_sources_moved
    ${CMAKE_BINARY_DIR}/lib/transport/types.proto
    ${CMAKE_BINARY_DIR}/lib/transport/exchange.proto
    ${CMAKE_BINARY_DIR}/lib/transport/messages-eos.proto
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
      "--nanopb_out=-f messages.options:." messages.proto
  COMMAND
    ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/lib/transport/*.pb.h
       ${CMAKE_BINARY_DIR}/include
  COMMAND
    ${CMAKE_COMMAND} -E touch ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp
  DEPENDS
    ${protoc_pb_sources} ${protoc_pb_options})

add_custom_target(kktransport.pb ALL DEPENDS ${CMAKE_BINARY_DIR}/lib/transport/kktransport.pb.stamp)

add_library(kktransport ${sources} ${protoc_c_sources})
add_dependencies(kktransport kktransport.pb)
