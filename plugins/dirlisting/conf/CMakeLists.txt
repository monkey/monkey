set(conf_dir "${MK_PATH_CONF}/dirlisting/")

install(DIRECTORY DESTINATION ${conf_dir})

if(BUILD_LOCAL)
  file(COPY dirhtml.conf DESTINATION ${conf_dir})
  file(COPY themes DESTINATION ${conf_dir})
else()
  install(FILES dirhtml.conf DESTINATION ${conf_dir})
  install(DIRECTORY themes DESTINATION ${conf_dir})
endif()