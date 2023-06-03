
include(linklibsys)

set(libkazv_HEADER_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR}/kazv)

add_subdirectory(base)
add_subdirectory(store)
add_subdirectory(api)
add_subdirectory(crypto)
add_subdirectory(client)
add_subdirectory(eventemitter)

if(libkazv_BUILD_KAZVJOB)
  add_subdirectory(job)
endif()

add_library(kazvall INTERFACE)
add_library(libkazv::kazvall ALIAS kazvall)
add_library(kazv ALIAS kazvall)
add_library(libkazv::kazv ALIAS kazvall)


target_link_libraries(kazvall INTERFACE kazvbase kazvstore kazvapi kazvcrypto kazvclient kazveventemitter)

target_include_directories(kazvall
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/kazv>
  )

install(TARGETS kazvall EXPORT libkazvTargets)

if(libkazv_INSTALL_HEADERS)
  install(
    DIRECTORY
    ${CMAKE_CURRENT_SOURCE_DIR}/

    DESTINATION ${libkazv_HEADER_INSTALL_DIR}

    FILES_MATCHING PATTERN "*.hpp"

    PATTERN "tests" EXCLUDE
    )
endif()

# export(TARGETS kazv)

if(libkazv_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(libkazv_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
