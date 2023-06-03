

include(CTest)

set(KAZVTEST_RESPATH ${CMAKE_CURRENT_SOURCE_DIR}/resources)
configure_file(kazvtest-respath.hpp.in kazvtest-respath.hpp)

add_executable(kazvtest
  testmain.cpp
  basejobtest.cpp
  event-test.cpp
  cursorutiltest.cpp
  base/serialization-test.cpp
  base/types-test.cpp

  client/client-test-util.cpp
  client/discovery-test.cpp
  client/sync-test.cpp
  client/content-test.cpp
  client/paginate-test.cpp
  client/util-test.cpp
  client/serialization-test.cpp
  client/encrypted-file-test.cpp
  client/sdk-test.cpp
  client/thread-safety-test.cpp
  client/room-test.cpp
  client/random-generator-test.cpp
  client/profile-test.cpp
  client/kick-test.cpp
  client/ban-test.cpp
  client/keys-test.cpp
  client/room/room-actions-test.cpp

  kazvjobtest.cpp
  event-emitter-test.cpp
  crypto-test.cpp
  crypto/deterministic-test.cpp
  promise-test.cpp
  store-test.cpp
  file-desc-test.cpp
  )

target_include_directories(
  kazvtest
  PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(kazvtest
  PRIVATE Catch2::Catch2WithMain
  PRIVATE kazv
  PRIVATE kazveventemitter
  PRIVATE kazvjob
  PRIVATE nlohmann_json::nlohmann_json
  PRIVATE immer
  PRIVATE lager
  PRIVATE zug)
