set(htdocs
  js/cbpAnimatedHeader.js
  js/classie.js
  js/jquery.js
  js/freelancer.js
  js/bootstrap.min.js
  js/cbpAnimatedHeader.min.js
  js/jqBootstrapValidation.js
  font-awesome/css/font-awesome.min.css
  font-awesome/fonts/fontawesome-webfont.woff
  font-awesome/fonts/FontAwesome.otf
  font-awesome/fonts/fontawesome-webfont.svg
  font-awesome/fonts/fontawesome-webfont.eot
  font-awesome/fonts/fontawesome-webfont.ttf
  favicon.ico
  css/monkey.css
  css/bootstrap.min.css
  css/freelancer.css
  fonts/glyphicons-halflings-regular.woff2
  fonts/glyphicons-halflings-regular.ttf
  fonts/glyphicons-halflings-regular.svg
  fonts/glyphicons-halflings-regular.woff
  fonts/glyphicons-halflings-regular.eot
  img/mk_signature.png
  img/mk_logo.png
  img/mk_banner.png
  index.html
  )

if(NOT BUILD_LOCAL)
  foreach (file ${htdocs})
    get_filename_component(dir ${file} PATH)
    install(FILES ${file} DESTINATION ${MK_PATH_WWW}/${dir})
  endforeach()
endif()
