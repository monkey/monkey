set(src
  test.c)

add_executable(api_test ${src})

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  target_link_libraries(api_test monkey-core-static mk_core ws2_32)

  include_directories(../mk_core/deps/libevent/include)
  include_directories("${PROJECT_BINARY_DIR}/mk_core/deps/libevent/include/")
else()
  target_link_libraries(api_test monkey-core-static)
endif()

set(src
  errors.c
  )

add_executable(api_error ${src})
target_link_libraries(api_error monkey-core-static)
