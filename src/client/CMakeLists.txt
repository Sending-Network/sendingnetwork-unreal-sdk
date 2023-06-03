set(kazvclient_SRCS
  sdk-model.cpp
  client-model.cpp
  client.cpp
  actions/auth.cpp
  actions/sync.cpp
  actions/paginate.cpp
  actions/membership.cpp
  actions/states.cpp
  actions/send.cpp
  actions/ephemeral.cpp
  actions/content.cpp
  actions/encryption.cpp
  actions/profile.cpp
  device-list-tracker.cpp
  encrypted-file.cpp

  room/room-model.cpp
  room/room.cpp
  did.cpp
  sdn.cpp
  )

add_library(kazvclient ${kazvclient_SRCS})
add_library(libkazv::kazvclient ALIAS kazvclient)
set_target_properties(kazvclient PROPERTIES VERSION ${libkazv_VERSION_STRING} SOVERSION ${libkazv_SOVERSION})

target_link_libraries(kazvclient PUBLIC kazvbase kazvapi kazvcrypto kazvstore)

target_include_directories(kazvclient PRIVATE .)

target_include_directories(kazvclient
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/kazv/client>
  )

install(TARGETS kazvclient EXPORT libkazvTargets LIBRARY)
