set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(board)
add_subdirectory(crypto)
add_subdirectory(firmware)

if(KK_EMULATOR)
  add_subdirectory(emulator)
endif()
