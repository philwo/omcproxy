cmake_minimum_required(VERSION 3.21)

project(omcproxy C)

add_executable(omcproxy)

target_compile_features(omcproxy PRIVATE c_std_99)
target_compile_definitions(omcproxy PRIVATE _GNU_SOURCE _TIME_BITS=64 _FILE_OFFSET_BITS=64)
target_compile_options(omcproxy PRIVATE -Wall)

target_include_directories(omcproxy BEFORE PRIVATE .)
target_sources(omcproxy PRIVATE libubox/avl.c libubox/blob.c libubox/blobmsg.c libubox/list.c libubox/uloop.c libubox/utils.c)

target_sources(omcproxy PRIVATE src/client.c src/mrib.c src/querier.c src/groups.c src/igmp.c src/mld.c src/proxy.c src/omcproxy.c)

install(TARGETS omcproxy DESTINATION sbin/)
