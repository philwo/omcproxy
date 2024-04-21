cmake_minimum_required(VERSION 3.21)

project(omcproxy CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(omcproxy src/client.cc src/mrib.cc src/querier.cc src/groups.cc src/igmp.cc src/mld.cc src/proxy.cc src/omcproxy.cc libubox/avl.cc libubox/list.cc libubox/uloop.cc libubox/utils.cc)

target_compile_features(omcproxy PRIVATE cxx_std_23)
target_compile_definitions(omcproxy PRIVATE _GNU_SOURCE _TIME_BITS=64 _FILE_OFFSET_BITS=64)
target_compile_options(omcproxy PRIVATE -Wall -g)
target_include_directories(omcproxy BEFORE PRIVATE .)

install(TARGETS omcproxy DESTINATION sbin/)
