# Let's have fun!
cmake_minimum_required(VERSION 2.8)
project(monkey C)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

# CMake includes
include(CheckSymbolExists)
include(CheckLibraryExists)
include(CheckIncludeFile)

# Set default compiler options
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wextra")

# Monkey Version
set(MK_VERSION_MAJOR  1)
set(MK_VERSION_MINOR  6)
set(MK_VERSION_PATCH  0)
set(MK_VERSION_STR "${MK_VERSION_MAJOR}.${MK_VERSION_MINOR}.${MK_VERSION_PATCH}")

configure_file(
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_env.h.in"
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_env.h"
  )

# ============================================
# ============= BUILD OPTIONS ================
# ============================================

# Monkey Core
option(WITH_ACCEPT         "Use accept(2) system call"   No)
option(WITH_ACCEPT4        "Use accept4(2) system call" Yes)
option(WITH_LINUX_KQUEUE   "Use Linux kqueue emulator"   No)
option(WITH_TRACE          "Enable Trace mode"           No)
option(WITH_UCLIB          "Enable uClib libc support"   No)
option(WITH_MUSL           "Enable Musl libc support"    No)
option(WITH_BACKTRACE      "Enable Backtrace feature"   Yes)
option(WITH_LINUX_TRACE    "Enable Lttng support"        No)
option(WITH_PTHREAD_TLS    "Use old Pthread TLS mode"    No)
option(WITH_SYSTEM_MALLOC  "Use system memory allocator" No)

# Plugins: what should be build ?, these options
# will be processed later on the plugins/CMakeLists.txt file
option(WITH_PLUGIN_AUTH          "Basic authentication"     Yes)
option(WITH_PLUGIN_CGI           "CGI support"               No)
option(WITH_PLUGIN_CHEETAH       "Cheetah Shell Interface"   No)
option(WITH_PLUGIN_DIRLISTING    "Directory Listing"         No)
option(WITH_PLUGIN_FASTCGI       "FastCGI"                   No)
option(WITH_PLUGIN_LIANA         "Basic network layer"      Yes)
option(WITH_PLUGIN_LOGGER        "Log Writer"                No)
option(WITH_PLUGIN_MANDRIL       "Security"                  No)
option(WITH_PLUGIN_MBEDTLS       "TLS/SSL support"           No)
option(WITH_PLUGIN_PROXY_REVERSE "Proxy reverse"             No)

# ===========================================
# ============== DEPENDENCIES ===============
# ===========================================

# Find pthreads
find_package(Threads)

# Check for accept(2) v/s accept(4)
if(WITH_ACCEPT)
  set(WITH_ACCEPT4 No)
elseif(WITH_ACCEPT4)
  # accept(4) requires _GNU_SOURCE defined
  list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)
  check_symbol_exists(accept4 sys/socket.h HAVE_ACCEPT4)
  list(REMOVE_ITEM CMAKE_REQUIRED_DEFINITIONS -D_GNU_SOURCE)

  # check the results
  if(NOT HAVE_ACCEPT4)
    # switch back to accept(2)
    set(WITH_ACCEPT Yes)
  endif()
endif()

# Check for LTTng-UST
if(WITH_LINUX_TRACE)
  check_include_file("lttng/tracepoint.h" HAVE_LTTNG)
  if (NOT HAVE_LTTNG)
    message(FATAL_ERROR "LTTng-UST is not installed in your system." )
  endif()
endif()

# Check for Linux Kqueue library emulator
if(WITH_LINUX_KQUEUE)
  find_package(Libkqueue REQUIRED)
  if(NOT LIBKQUEUE_FOUND)
    message(FATAL_ERROR "Linux libkqueue was not found." )
  endif()
endif()

# Check Backtrace support
if(WITH_BACKTRACE)
  check_include_file("execinfo.h" HAVE_BACKTRACE)
  if (NOT HAVE_BACKTRACE)
    set(WITH_BACKTRACE No)
  endif()
endif()

# ============================================
# =========== CONFIGURATION FILES=============
# ============================================

# Default values for conf/monkey.conf
set(MK_CONF_LISTEN       "2001")
set(MK_CONF_WORKERS      "0")
set(MK_CONF_TIMEOUT      "15")
set(MK_CONF_PIDFILE      "monkey.pid")
set(MK_CONF_USERDIR      "public_html")
set(MK_CONF_INDEXFILE    "index.html index.htm index.php")
set(MK_CONF_HIDEVERSION  "Off")
set(MK_CONF_RESUME       "On")
set(MK_CONF_USER         "www-data")
set(MK_CONF_KA           "On")
set(MK_CONF_KA_TIMEOUT   "5")
set(MK_CONF_KA_MAXREQ    "1000")
set(MK_CONF_REQ_SIZE     "32")
set(MK_CONF_SYMLINK      "Off")
set(MK_CONF_TRANSPORT    "liana")
set(MK_CONF_DEFAULT_MIME "text/plain")
set(MK_CONF_FDT          "On")
set(MK_CONF_OVERCAPACITY "Resist")

# Default values for conf/sites/default
set(MK_VH_SERVERNAME     "127.0.0.1")
set(MK_VH_DOCUMENT_ROOT  MK_DATADIR)
set(MK_VH_LOG_ACCESS     MK_LOGDIR)
set(MK_VH_LOG_ERROR      MK_LOGDIR)

# Generate conf/monkey.conf
configure_file(
  "${PROJECT_SOURCE_DIR}/lang/en/mconf"
  "${PROJECT_SOURCE_DIR}/conf/monkey.conf"
  )

# Generate conf/sites/default
configure_file(
  "${PROJECT_SOURCE_DIR}/lang/en/sites/default"
  "${PROJECT_SOURCE_DIR}/conf/sites/default"
  )

# General Headers
include_directories(include/)


add_subdirectory(plugins/)

# Instruct CMake to build the Monkey Core
add_subdirectory(src/)
