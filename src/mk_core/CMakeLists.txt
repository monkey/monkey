set(src
  mk_iov.c
  mk_rconf.c
  mk_string.c
  mk_memory.c
  mk_event.c
  mk_rbtree.c
  )

include_directories(include)
add_library(mk_core STATIC ${src})
