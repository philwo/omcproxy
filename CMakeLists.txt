cmake_minimum_required(VERSION 3.21)

project(omcproxy C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds are not supported, use cmake -B build")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(OMCPROXY_WERROR "Treat compiler warnings as errors" OFF)
option(OMCPROXY_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(OMCPROXY_FUZZ "Build the libFuzzer target" OFF)

add_library(omcproxy_build INTERFACE)
target_compile_features(omcproxy_build INTERFACE c_std_23)
target_compile_definitions(omcproxy_build INTERFACE _GNU_SOURCE _TIME_BITS=64 _FILE_OFFSET_BITS=64)
target_include_directories(omcproxy_build INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
if(DEFINED L_LEVEL)
  target_compile_definitions(omcproxy_build INTERFACE L_LEVEL=${L_LEVEL})
endif()
if(OMCPROXY_SANITIZE)
  target_compile_options(omcproxy_build INTERFACE -fsanitize=address,undefined -fno-sanitize-recover=all)
  target_link_options(omcproxy_build INTERFACE -fsanitize=address,undefined)
endif()

add_library(omcproxy_warnings INTERFACE)
target_compile_options(omcproxy_warnings INTERFACE -Wall -Wextra)
if(OMCPROXY_WERROR)
  target_compile_options(omcproxy_warnings INTERFACE -Werror)
endif()

find_library(libubox ubox REQUIRED)

add_library(omcproxy_core OBJECT
  src/client.c
  src/config.c
  src/ev.c
  src/groups.c
  src/igmp.c
  src/mld.c
  src/mrib.c
  src/proxy.c
  src/querier.c
)
target_link_libraries(omcproxy_core PRIVATE omcproxy_build omcproxy_warnings)

add_executable(omcproxy src/omcproxy.c)
target_link_libraries(omcproxy PRIVATE omcproxy_build omcproxy_warnings omcproxy_core ${libubox})

install(TARGETS omcproxy DESTINATION sbin)

enable_testing()
add_subdirectory(test)
