# Check if a plugin will be linked statically
macro(CHECK_STATIC_PLUGIN name)
  string(REPLACE "," ";" plugins ${STATIC_PLUGINS})
  list(FIND plugins ${name} found)
  if(NOT found EQUAL -1)
    set(IS_STATIC TRUE)
    message(STATUS "      [^static]")
  else()
    set(IS_STATIC FALSE)
  endif()
endmacro()

# Used by plugins to create the targets
macro(MONKEY_PLUGIN name src)
  CHECK_STATIC_PLUGIN(${name})
  if(IS_STATIC)
    add_library(monkey-${name}-static STATIC ${src})
    set_target_properties(monkey-${name}-static PROPERTIES OUTPUT_NAME monkey-${name})
    set_target_properties(monkey-${name}-static PROPERTIES PREFIX "")
  else()
    add_library(monkey-${name}-shared SHARED ${src})
    set_target_properties(monkey-${name}-shared PROPERTIES OUTPUT_NAME monkey-${name})
    set_target_properties(monkey-${name}-shared PROPERTIES PREFIX "")
  endif()
endmacro()

# This macro determinate if the plugin is enabled through the
# option WITH_PLUGIN_NAME defined on the root CMakeLists.txt
macro(MK_BUILD_PLUGIN name)
  CHECK_STATIC_PLUGIN(${name})
  if(IS_STATIC)
    set(STATIC_PLUGINS_LIBS "${STATIC_PLUGINS_LIBS} monkey-${name}-static")
    set(STATIC_PLUGINS_INIT "${STATIC_PLUGINS_INIT}\n    p = &mk_plugin_${name};\n    mk_list_add(&p->_head, mk_config->plugins);\n")
    set(STATIC_PLUGINS_DECL "${STATIC_PLUGINS_DECL}struct mk_plugin mk_plugin_${name};\n")
  endif()

  string(TOUPPER ${name} NAME)
  set(option WITH_PLUGIN_${NAME})
  if(${option})
    message(STATUS "Plugin ${name} enabled")
    add_subdirectory(${name})
  endif()

endmacro()

# Try to configure/build all plugins
MK_BUILD_PLUGIN("auth")
MK_BUILD_PLUGIN("cgi")
MK_BUILD_PLUGIN("cheetah")
MK_BUILD_PLUGIN("dirlisting")
MK_BUILD_PLUGIN("fastcgi")
MK_BUILD_PLUGIN("liana")
MK_BUILD_PLUGIN("logger")
MK_BUILD_PLUGIN("mandril")
MK_BUILD_PLUGIN("mbedtls")

configure_file(
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_static_plugins.h.in"
  "${PROJECT_SOURCE_DIR}/include/monkey/mk_static_plugins.h"
  )
