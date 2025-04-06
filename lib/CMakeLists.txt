add_subdirectory(board)
add_subdirectory(emulator)
add_subdirectory(firmware)
add_subdirectory(rand)
add_subdirectory(transport)
add_subdirectory(variant)

# The nanopb generator is pre-built in the docker container. The kk build has dependencies on these
# files and were originally just copy pasted to these directories from the nanopb repo. That has
# caused an unfortunate nanopb version dependency, i.e., these files need to be copied from the same
# version of nanopb that is in the container.
#
# The cmake code here is copying the files out of the nanopb directory in the container for the kk build.
# These files must then be deleted at the end of the build because they are owned by root and will
# cause problems with the keepkey-firmware repo.
#
# A better way to implement this is to vendorize the nanopb dependency. However, this will force an 
# update to a bunch of kk source files. Future project. 
set(nanopb_sources
  ${NANOPB_DIR}/pb_common.c
  ${NANOPB_DIR}/pb_decode.c
  ${NANOPB_DIR}/pb_encode.c
)

set(nanopb_inc
  ${NANOPB_DIR}/pb_common.h
  ${NANOPB_DIR}/pb_decode.h
  ${NANOPB_DIR}/pb_encode.h
  ${NANOPB_DIR}/pb.h
)

file(COPY ${nanopb_sources} DESTINATION ${CMAKE_SOURCE_DIR}/lib/transport)
file(COPY ${nanopb_inc} DESTINATION ${CMAKE_SOURCE_DIR}/include/)
