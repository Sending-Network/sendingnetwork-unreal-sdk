
include(linklibsys)

set(FULL_CSAPI_DIR csapi)
file(GLOB_RECURSE kazvapi_SRCS ${FULL_CSAPI_DIR}/*.cpp)

add_library(kazvapi ${kazvapi_SRCS})
add_library(libkazv::kazvapi ALIAS kazvapi)
set_target_properties(kazvapi PROPERTIES VERSION ${libkazv_VERSION_STRING} SOVERSION ${libkazv_SOVERSION})

target_link_libraries(kazvapi PUBLIC kazvbase)

target_include_directories(kazvapi PRIVATE .)

target_include_directories(kazvapi
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/kazv/api>
  )

install(TARGETS kazvapi EXPORT libkazvTargets LIBRARY)
