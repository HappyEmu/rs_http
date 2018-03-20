cmake_minimum_required(VERSION 3.9)
project(rs_http C)

set(CMAKE_C_STANDARD 99)

link_directories(${CMAKE_SOURCE_DIR}/lib)
include_directories(include)

add_executable(rs_http main.c symmetric.c symmetric.h cwt.c cwt.h utils.c utils.h edhoc.c edhoc.h rs_types.h cose.c cose.h)
target_link_libraries(rs_http mongoose wolfssl tinycbor)