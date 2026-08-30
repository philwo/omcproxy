add_test(NAME config_error COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/unit/config_error_test.sh $<TARGET_FILE:omcproxy>)
set_tests_properties(config_error PROPERTIES SKIP_RETURN_CODE 77)

add_executable(test_config
  unit/test_config.c
  ${CMAKE_SOURCE_DIR}/src/config.c
)
target_include_directories(test_config PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_config PRIVATE omcproxy_build omcproxy_warnings)
add_test(NAME config COMMAND test_config)

add_executable(test_addr
  unit/test_addr.c
  ${CMAKE_SOURCE_DIR}/src/addr.c
)
target_include_directories(test_addr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_addr PRIVATE omcproxy_build omcproxy_warnings)
add_test(NAME addr COMMAND test_addr)

add_executable(test_ev
  unit/test_ev.c
  ${CMAKE_SOURCE_DIR}/src/ev.c
)
target_include_directories(test_ev PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_ev PRIVATE omcproxy_build omcproxy_warnings)
add_test(NAME ev COMMAND test_ev)

add_executable(test_groups
  unit/test_groups.c
  unit/ev_stub.c
  ${CMAKE_SOURCE_DIR}/src/addr.c
  ${CMAKE_SOURCE_DIR}/src/groups.c
)
target_include_directories(test_groups PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_groups PRIVATE omcproxy_build omcproxy_warnings)
add_test(NAME groups COMMAND test_groups)

add_executable(test_client
  unit/test_client.c
  unit/ev_stub.c
  ${CMAKE_SOURCE_DIR}/src/client.c
)
target_include_directories(test_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_client PRIVATE omcproxy_build omcproxy_warnings)
target_link_options(test_client PRIVATE -Wl,--wrap=socket -Wl,--wrap=setsockopt -Wl,--wrap=close)
add_test(NAME client COMMAND test_client)

add_executable(test_proxy
  unit/test_proxy.c
  ${CMAKE_SOURCE_DIR}/src/proxy.c
)
target_include_directories(test_proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_proxy PRIVATE omcproxy_build omcproxy_warnings)
add_test(NAME proxy COMMAND test_proxy)

add_executable(test_mrib
  unit/test_mrib.c
  unit/ev_stub.c
  ${CMAKE_SOURCE_DIR}/src/addr.c
  ${CMAKE_SOURCE_DIR}/src/gmp.c
  ${CMAKE_SOURCE_DIR}/src/groups.c
  ${CMAKE_SOURCE_DIR}/src/mrib.c
  ${CMAKE_SOURCE_DIR}/src/querier.c
)
target_include_directories(test_mrib PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_mrib PRIVATE omcproxy_build omcproxy_warnings)
target_link_options(test_mrib PRIVATE
  -Wl,--wrap=socket
  -Wl,--wrap=setsockopt
  -Wl,--wrap=close
  -Wl,--wrap=recvmsg
)
add_test(NAME mrib COMMAND test_mrib)

add_executable(test_gmp
  unit/test_gmp.c
  unit/ev_stub.c
  unit/mrib_stub.c
  ${CMAKE_SOURCE_DIR}/src/addr.c
  ${CMAKE_SOURCE_DIR}/src/gmp.c
  ${CMAKE_SOURCE_DIR}/src/groups.c
  ${CMAKE_SOURCE_DIR}/src/querier.c
)
target_include_directories(test_gmp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_gmp PRIVATE omcproxy_build omcproxy_warnings)
target_link_options(test_gmp PRIVATE -Wl,--wrap=calloc)
add_test(NAME gmp COMMAND test_gmp)

if(OMCPROXY_FUZZ)
  add_executable(fuzz_gmp
    fuzz/fuzz_gmp.c
    unit/ev_stub.c
    unit/mrib_stub.c
    ${CMAKE_SOURCE_DIR}/src/addr.c
    ${CMAKE_SOURCE_DIR}/src/gmp.c
    ${CMAKE_SOURCE_DIR}/src/groups.c
    ${CMAKE_SOURCE_DIR}/src/querier.c
  )
  target_include_directories(fuzz_gmp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
  target_link_libraries(fuzz_gmp PRIVATE omcproxy_build omcproxy_warnings)
  target_compile_options(fuzz_gmp PRIVATE -fsanitize=fuzzer)
  target_link_options(fuzz_gmp PRIVATE -fsanitize=fuzzer)
endif()

add_test(NAME netns_mld COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/netns/leave_keeps_upstream_join_test.sh)
add_test(NAME netns_igmp COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/netns/igmp_leave_keeps_upstream_join_test.sh)
add_test(NAME netns_payload COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/netns/payload_forwarding_test.sh)
set_tests_properties(netns_mld netns_igmp netns_payload PROPERTIES
  LABELS netns
  ENVIRONMENT "OMCPROXY=$<TARGET_FILE:omcproxy>"
  TIMEOUT 180
)
