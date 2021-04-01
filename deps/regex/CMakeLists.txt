if(NOT DEFINED MK_HAVE_REGEX)
set(src
    re.c
  )

add_library(regex STATIC ${src})
endif()
