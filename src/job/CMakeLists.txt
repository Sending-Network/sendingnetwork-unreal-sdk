
include(linklibsys)

set(libkazvjob_SRCS
  cprjobhandler.cpp
  )

add_library(kazvjob ${libkazvjob_SRCS})
add_library(libkazv::kazvjob ALIAS kazvjob)
set_target_properties(kazvjob PROPERTIES VERSION ${libkazv_VERSION_STRING} SOVERSION ${libkazv_SOVERSION})

target_link_libraries(kazvjob PUBLIC Threads::Threads kazvbase)
target_link_libraries_system(kazvjob PUBLIC
  cpr::cpr
  )
target_include_directories(kazvjob
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/kazv/job>
  )

install( TARGETS kazvjob EXPORT libkazv-jobTargets LIBRARY)
install(EXPORT libkazv-jobTargets
  NAMESPACE
    libkazv::
  DESTINATION
    ${ConfigPackageLocation}
)
install(
  FILES ${libkazvSourceRoot}/cmake/libkazv-jobConfig.cmake
  DESTINATION ${ConfigPackageLocation})
