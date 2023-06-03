find_package(PkgConfig)

if(PkgConfig_FOUND)
  pkg_search_module(cryptopp libcryptopp libcrypto++ IMPORTED_TARGET GLOBAL)
else()
  set(cryptopp_FOUND OFF)
endif()
