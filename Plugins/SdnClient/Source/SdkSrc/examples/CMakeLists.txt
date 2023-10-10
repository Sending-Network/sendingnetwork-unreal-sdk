include_directories(../tests)

add_executable(room_feed room_feed.cpp)
target_link_libraries(room_feed SDNClient::SDNClient)

include(CheckIncludeFileCXX)
CHECK_INCLUDE_FILE_CXX("filesystem" HAVE_STD_FILESYSTEM)

if (HAVE_STD_FILESYSTEM)
  add_executable(media_downloader media_downloader.cpp)
  target_link_libraries(media_downloader SDNClient::SDNClient)
  if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_libraries(media_downloader stdc++fs)
  endif()
endif()

add_executable(memberstats memberstats.cpp)
target_link_libraries(memberstats SDNClient::SDNClient)

add_executable(simple_bot simple_bot.cpp)
target_link_libraries(simple_bot SDNClient::SDNClient)

add_executable(crypto_bot crypto_bot.cpp)
target_link_libraries(crypto_bot
                      spdlog::spdlog
                      SDNClient::SDNClient
                      Olm::Olm)

  add_executable(online_backup_exporter online_backup_exporter.cpp)
  target_link_libraries(online_backup_exporter SDNClient::SDNClient)
