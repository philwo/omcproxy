add_executable(test_groups
  unit/test_groups.c
  unit/ev_stub.c
  ${CMAKE_SOURCE_DIR}/src/groups.c
)
target_include_directories(test_groups PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_groups PRIVATE omcproxy_build omcproxy_warnings ${libubox})
add_test(NAME groups COMMAND test_groups)

add_executable(test_gmp
  unit/test_gmp.c
  unit/ev_stub.c
  unit/mrib_stub.c
  ${CMAKE_SOURCE_DIR}/src/groups.c
  ${CMAKE_SOURCE_DIR}/src/igmp.c
  ${CMAKE_SOURCE_DIR}/src/mld.c
  ${CMAKE_SOURCE_DIR}/src/querier.c
)
target_include_directories(test_gmp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/unit)
target_link_libraries(test_gmp PRIVATE omcproxy_build omcproxy_warnings ${libubox})
add_test(NAME gmp COMMAND test_gmp)

add_test(NAME netns_mld COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/netns/leave_keeps_upstream_join_test.sh)
set_tests_properties(netns_mld PROPERTIES
  LABELS netns
  ENVIRONMENT "OMCPROXY=$<TARGET_FILE:omcproxy>"
  TIMEOUT 180
)
