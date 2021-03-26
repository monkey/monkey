if(NOT DEFINED MK_HAVE_REGEX)
set(src
  regex.c
  )

add_definitions(-DREGEX_STATIC)

add_library(regex STATIC ${src})
endif()
