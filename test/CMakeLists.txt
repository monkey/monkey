# if(MK_LIB_TEST)
#     add_executable(lib_test lib_test.c)
#     add_dependencies(lib_test monkey-core-static)
#     target_include_directories(lib_test PUBLIC BEFORE lib/acutest)
#     target_link_libraries(lib_test monkey-core-static)
#     add_test(NAME lib_test
#              COMMAND lib_test
#              WORKING_DIRECTORY ${CMAKE_HOME_DIRECTORY}/build)
# endif()
set(UNIT_TESTS_FILES
  lib_server.c
  event_timeout.c
  http_framing.c
  )

if (CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(UNIT_TESTS_FILES
    ${UNIT_TESTS_FILES}
    win32_socketpair.c
    )
endif()

# Prepare list of unit tests
foreach(source_file ${UNIT_TESTS_FILES})
  get_filename_component(source_file_we ${source_file} NAME_WE)
  set(source_file_we mk-test-${source_file_we})

  add_executable(
    ${source_file_we}
    ${source_file}
    )

  if(source_file STREQUAL "http_framing.c")
    # Compile the production parser with the test's error-response stub.
    target_sources(${source_file_we} PRIVATE ../mk_server/mk_http_parser.c)
    target_link_libraries(${source_file_we} mk_core)
  else()
    target_link_libraries(${source_file_we} monkey-core-static)
  endif()

  add_test(NAME ${source_file_we}
    COMMAND $<TARGET_FILE:${source_file_we}>
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endforeach()
