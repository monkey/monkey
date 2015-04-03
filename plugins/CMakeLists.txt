# Used by plugins to create the targets
macro(MONKEY_PLUGIN name src)
  add_library(monkey-${name}-shared SHARED ${src})
  set_target_properties(monkey-${name}-shared PROPERTIES OUTPUT_NAME monkey-${name})
  set_target_properties(monkey-${name}-shared PROPERTIES PREFIX "")
endmacro()

# This macro determinate if the plugin is enabled through the
# option WITH_PLUGIN_NAME defined on the root CMakeLists.txt
macro(MK_BUILD_PLUGIN name)
  string(TOUPPER ${name} NAME)
  set(option WITH_PLUGIN_${NAME})
  if(${option})
    message(STATUS "Plugin ${name} enabled")
    add_subdirectory(${name})
  endif()
endmacro()

# Try to configure all plugins
MK_BUILD_PLUGIN("auth")
MK_BUILD_PLUGIN("cgi")
MK_BUILD_PLUGIN("cheetah")
MK_BUILD_PLUGIN("dirlisting")
MK_BUILD_PLUGIN("fastcgi")
MK_BUILD_PLUGIN("liana")
MK_BUILD_PLUGIN("logger")
MK_BUILD_PLUGIN("mandril")
MK_BUILD_PLUGIN("mbedtls")
MK_BUILD_PLUGIN("proxy_reverse")
