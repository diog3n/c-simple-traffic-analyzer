cmake_minimum_required(VERSION 3.10)

project(traffan C)

set(CMAKE_C_STANDARD 17)

file(GLOB SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)

add_executable(traffan ${SRC_FILES})

target_include_directories(traffan PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(traffan pcap)