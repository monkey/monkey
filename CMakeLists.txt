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
set(MK_VER_MAJOR  1)
set(MK_VER_MINOR  6)
set(MK_VER_PATCH  0)

# ============================================
# ============= BUILD OPTIONS ================
# ============================================

option(WITH_ACCEPT         "Use accept(2) system call"   No)
option(WITH_ACCEPT4        "Use accept4(2) system call" Yes)
option(WITH_LINUX_KQUEUE   "Use Linux kqueue emulator"   No)
option(WITH_TRACE          "Enable Trace mode"           No)
option(WITH_UCLIB          "Enable uClib libc support"   No)
option(WITH_MUSL           "Enable Musl libc support"    No)
option(WITH_BACKTRACE      "Disable Backtrace feature"  Yes)
option(WITH_LINUX_TRACE    "Enable Lttng support"        No)
option(WITH_PTHREAD_TLS    "Use old Pthread TLS mode"    No)
option(WITH_SYSTEM_MALLOC  "Use system memory allocator" No)

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

# General Headers
include_directories(include/)

# Instruct CMake to build the Fluent Bit Core
add_subdirectory(src/)
