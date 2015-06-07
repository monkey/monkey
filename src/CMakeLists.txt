set(src
  mk_mimetype.c
  mk_vhost.c
  mk_header.c
  mk_config.c
  mk_signals.c
  mk_user.c
  mk_utils.c
  mk_stream.c
  mk_scheduler.c
  mk_http.c
  mk_http_parser.c
  mk_file.c
  mk_socket.c
  mk_clock.c
  mk_cache.c
  mk_server.c
  mk_kernel.c
  mk_plugin.c
  )


add_subdirectory(mk_core)

include_directories(./)

# Always build a static library, thats our core :)
add_library(monkey-core-static STATIC ${src})
target_link_libraries(monkey-core-static dl mk_core ${CMAKE_THREAD_LIBS_INIT} ${STATIC_PLUGINS_LIBS})

if(NOT WITH_SYSTEM_MALLOC)
  target_link_libraries(monkey-core-static libjemalloc ${CMAKE_THREAD_LIBS_INIT})
endif()

# Linux Kqueue emulation
if(WITH_LINUX_KQUEUE)
  target_link_libraries(monkey-core-static kqueue)
endif()

# Build the binary
if(NOT WITHOUT_BIN)
  add_executable(monkey-bin monkey.c)
  target_link_libraries(monkey-bin monkey-core-static)
  set_target_properties(monkey-bin PROPERTIES OUTPUT_NAME monkey)
endif()


if(BUILD_LOCAL)
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/")
else()
  install(TARGETS monkey-bin RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_SBINDIR})
endif()
