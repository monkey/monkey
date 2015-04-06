set(src
  auth.c
  base64.c
  conf.c
  sha1.c
  )

MONKEY_PLUGIN(auth "${src}")

add_subdirectory(tools)
