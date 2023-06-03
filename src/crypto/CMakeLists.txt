set(kazvcrypto_SRCS
  crypto.cpp
  session.cpp
  inbound-group-session.cpp
  outbound-group-session.cpp

  aes-256-ctr.cpp
  base64.cpp
  sha256.cpp
  )

add_library(kazvcrypto ${kazvcrypto_SRCS})
add_library(libkazv::kazvcrypto ALIAS kazvcrypto)
set_target_properties(kazvcrypto PROPERTIES VERSION ${libkazv_VERSION_STRING} SOVERSION ${libkazv_SOVERSION})

target_link_libraries(kazvcrypto PUBLIC kazvbase Olm::Olm cryptopp)

target_include_directories(kazvcrypto PRIVATE .)

target_include_directories(kazvcrypto
  INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  $<INSTALL_INTERFACE:include/kazv/crypto>
  )

install(TARGETS kazvcrypto EXPORT libkazvTargets LIBRARY)
