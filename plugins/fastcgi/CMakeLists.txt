set(src
  fastcgi.c
  protocol.c
  chunk.c
  request.c
  fcgi_fd.c
  fcgi_config.c
  fcgi_context.c
  fcgi_env.c
  )

MONKEY_PLUGIN(fastcgi "${src}")
add_subdirectory(conf)
