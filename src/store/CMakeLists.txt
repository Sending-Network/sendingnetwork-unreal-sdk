
add_library(kazvstore INTERFACE)
add_library(libkazv::kazvstore ALIAS kazvstore)

target_link_libraries(kazvstore INTERFACE kazvbase)

target_include_directories(kazvstore
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
  $<INSTALL_INTERFACE:include/kazv/store>
  )

install(TARGETS kazvstore EXPORT libkazvTargets)
