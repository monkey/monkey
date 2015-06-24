set(conf_dir "${MK_PATH_CONF}/plugins/cgi/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY cgi.conf DESTINATION ${conf_dir})
else()
  install(FILES cgi.conf DESTINATION ${conf_dir})
endif()
