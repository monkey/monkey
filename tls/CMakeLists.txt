set(MK_TLS_PROVIDER "none")
set(MK_TLS_SOURCES "${PROJECT_SOURCE_DIR}/tls/tls_stub.c")
set(MK_TLS_LIBS "")
set(MK_TLS_INCLUDE_DIRS "")

if(MK_TLS AND (MK_TLS_BACKEND STREQUAL "auto" OR MK_TLS_BACKEND STREQUAL "openssl"))
  find_package(OpenSSL QUIET)
  if(OPENSSL_FOUND)
    set(MK_TLS_PROVIDER "openssl")
    set(MK_TLS_SOURCES "${PROJECT_SOURCE_DIR}/tls/tls_openssl.c")
    set(MK_TLS_LIBS ${OPENSSL_LIBRARIES})
    if(OPENSSL_INCLUDE_DIR)
      set(MK_TLS_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
    endif()
  elseif(MK_TLS_BACKEND STREQUAL "openssl")
    message(FATAL_ERROR "MK_TLS_BACKEND=openssl was requested but OpenSSL was not found")
  endif()
endif()

if(MK_TLS AND MK_TLS_PROVIDER STREQUAL "none")
  set(MK_TLS_PROVIDER "mbedtls")
  set(MK_TLS_SOURCES "${PROJECT_SOURCE_DIR}/tls/tls_mbedtls.c")
  set(MK_TLS_LIBS mbedtls mbedx509 mbedcrypto)

  if(NOT MK_MBEDTLS_SHARED)
    option(ENABLE_TESTING OFF)
    option(ENABLE_PROGRAMS OFF)
    option(INSTALL_MBEDTLS_HEADERS OFF)
    set(MK_MBEDTLS_SRC ../deps/mbedtls-2.4.2)
    add_subdirectory(${MK_MBEDTLS_SRC} ${CMAKE_BINARY_DIR}/mbedtls-2.4.2)
    set(MK_TLS_INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/deps/mbedtls-2.4.2/include)
  else()
    find_path(MBEDTLS_INCLUDE_DIR NAMES mbedtls/version.h)
    find_library(MBEDTLS_LIBRARY NAMES mbedtls)
    find_library(MBEDX509_LIBRARY NAMES mbedx509)
    find_library(MBEDCRYPTO_LIBRARY NAMES mbedcrypto)

    if(NOT MBEDTLS_INCLUDE_DIR OR NOT MBEDTLS_LIBRARY OR
       NOT MBEDX509_LIBRARY OR NOT MBEDCRYPTO_LIBRARY)
      message(FATAL_ERROR "MK_TLS_BACKEND=mbedtls was selected but the mbedTLS headers or libraries were not found")
    endif()

    set(MK_TLS_INCLUDE_DIRS ${MBEDTLS_INCLUDE_DIR})
    set(MK_TLS_LIBS ${MBEDTLS_LIBRARY} ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY})
  endif()
endif()

message(STATUS "TLS backend selected: ${MK_TLS_PROVIDER}")

configure_file(
  "${PROJECT_SOURCE_DIR}/tls/tls.conf"
  "${PROJECT_BINARY_DIR}/conf/tls.conf"
  COPYONLY
  )

if(NOT MK_WITHOUT_CONF AND DEFINED MK_PATH_CONF)
  install(FILES "${PROJECT_SOURCE_DIR}/tls/tls.conf"
    DESTINATION ${MK_PATH_CONF})
endif()

set(MK_TLS_PROVIDER "${MK_TLS_PROVIDER}" PARENT_SCOPE)
set(MK_TLS_SOURCES "${MK_TLS_SOURCES}" PARENT_SCOPE)
set(MK_TLS_LIBS "${MK_TLS_LIBS}" PARENT_SCOPE)
set(MK_TLS_INCLUDE_DIRS "${MK_TLS_INCLUDE_DIRS}" PARENT_SCOPE)
