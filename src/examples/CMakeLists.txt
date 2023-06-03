
add_executable(basicexample
  basic/main.cpp
  basic/web3Sign.cpp
  basic/commands.cpp)

target_link_libraries(basicexample
  PRIVATE kazvjob
  PRIVATE kazv
  PRIVATE immer
  PRIVATE zug
  PRIVATE lager
  PRIVATE ${LIBHTTPSERVER_LINK_LIBRARIES})
target_include_directories(basicexample
  PRIVATE ${LIBHTTPSERVER_INCLUDE_DIRS})
