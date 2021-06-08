set(src
  libco.c
  )

include(CheckSymbolExists)

# Check for posix_memalign so that Apple Silicon can be supported
check_symbol_exists(posix_memalign "stdlib.h" HAVE_POSIX_MEMALIGN)

# Check for posix_memalign so that FreeBSD can be supported
check_symbol_exists(posix_memalign "malloc_np.h" HAVE_POSIX_MEMALIGN)

IF(HAVE_POSIX_MEMALIGN)
  add_definitions(-DHAVE_POSIX_MEMALIGN)
  MESSAGE("Found posix_memalign setting -DHAVE_POSIX_MEMALIGN")
ENDIF(HAVE_POSIX_MEMALIGN)

add_definitions(-DLIBCO_MP)
add_library(co STATIC ${src})
