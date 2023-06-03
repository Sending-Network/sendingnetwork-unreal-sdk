
include(linklibsys)

configure_file(libkazv-defs.hpp.in libkazv-defs.hpp)

set(kazvbase_SRCS
  debug.cpp
  event.cpp
  basejob.cpp
  file-desc.cpp
  )

add_library(kazvbase ${kazvbase_SRCS})
add_library(libkazv::kazvbase ALIAS kazvbase)
set_target_properties(kazvbase PROPERTIES VERSION ${libkazv_VERSION_STRING} SOVERSION ${libkazv_SOVERSION})

target_link_libraries_system(kazvbase
  PUBLIC nlohmann_json::nlohmann_json
  immer
  zug
  lager
  Boost::serialization)
target_include_directories(kazvbase
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  $<INSTALL_INTERFACE:include/kazv/base>
  )

target_include_directories(kazvbase
  PRIVATE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
  )

install(TARGETS kazvbase EXPORT libkazvTargets LIBRARY)

if(libkazv_INSTALL_HEADERS)
  # Install headers not under src/
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libkazv-defs.hpp DESTINATION ${libkazv_HEADER_INSTALL_DIR}/base)
endif()
