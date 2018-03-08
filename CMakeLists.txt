cmake_minimum_required(VERSION 3.9)
project(rs_http C)

set(CMAKE_C_STANDARD 99)

add_executable(rs_http main.c symmetric.c symmetric.h cwt.c cwt.h utils.c utils.h)
target_link_libraries(rs_http mongoose cbor wolfssl)