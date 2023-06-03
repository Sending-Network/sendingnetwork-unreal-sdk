# Do not let the option()s override variables here
cmake_minimum_required(VERSION 3.13)

if(NOT DEFINED PROJECT_NAME)
  if(NOT DEFINED libkazv_INSTALL_HEADERS)
    set(libkazv_INSTALL_HEADERS ON)
  endif()
endif()

project(libkazv)

set(libkazvSourceRoot ${CMAKE_CURRENT_SOURCE_DIR})

set(libkazv_VERSION_MAJOR 0)
set(libkazv_VERSION_MINOR 2)
set(libkazv_VERSION_PATCH 1)
set(libkazv_VERSION_STRING ${libkazv_VERSION_MAJOR}.${libkazv_VERSION_MINOR}.${libkazv_VERSION_PATCH})
set(libkazv_SOVERSION 2)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

option(libkazv_BUILD_TESTS "Build tests" ON)
option(libkazv_BUILD_EXAMPLES "Build examples" ON)
option(libkazv_BUILD_KAZVJOB "Build libkazvjob the async and networking library" ON)
option(libkazv_OUTPUT_LEVEL "Output level: Debug>=90, Info>=70, Quiet>=20, no output=1" 0)
option(libkazv_ENABLE_COVERAGE "Enable code coverage information" OFF)

if(libkazv_ENABLE_COVERAGE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fprofile-arcs -ftest-coverage -fPIC -O0")
endif()

if((libkazv_BUILD_TESTS OR libkazv_BUILD_EXAMPLES) AND NOT libkazv_BUILD_KAZVJOB)
  message(FATAL_ERROR
    "You asked kazvjob not to be built, but asked to build tests or examples. Tests and examples both depend on kazvjob. This is not possible.")
endif()

# Build shared libraries by default
if(NOT DEFINED BUILD_SHARED_LIBS)
  set(BUILD_SHARED_LIBS ON)
endif()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(LIBKAZV_BUILT_WITH_DEBUG 1)
else()
  set(LIBKAZV_BUILT_WITH_DEBUG 0)
endif()


find_package(Boost REQUIRED COMPONENTS serialization)


include(FetchContent)
if(libkazv_BUILD_KAZVJOB)
  find_package(cpr)
  if (NOT cpr_FOUND)
    message( STATUS "Using cpr from FetchContent")
    set(USE_SYSTEM_CURL ON)
    set(BUILD_CPR_TESTS OFF)
    FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/whoshuu/cpr.git GIT_TAG c34ddb9b3de2a22fdbd5d318d8b7d1997e6ca0bf)
    FetchContent_MakeAvailable(cpr)
  endif()

  set(THREADS_PREFER_PTHREAD_FLAG ON)
  find_package(Threads REQUIRED)
endif()

if(libkazv_BUILD_TESTS)
  find_package(Catch2)
  if (NOT Catch2_FOUND)
    message(STATUS "Using Catch2 from FetchContent")
    FetchContent_Declare(Catch2 GIT_REPOSITORY https://github.com/catchorg/Catch2 GIT_TAG v2.13.0)
    FetchContent_MakeAvailable(Catch2)
  endif()
endif()

find_package(nlohmann_json)
if (NOT nlohmann_json_FOUND)
  message(STATUS "Using nlohmann_json from FetchContent")
  set(JSON_BuildTests OFF)
  FetchContent_Declare(nlohmann_json GIT_REPOSITORY https://github.com/nlohmann/json GIT_TAG v3.9.1)
  FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(Immer)
if(NOT Immer_FOUND)
  message(STATUS "Using Immer from FetchContent")
  set(immer_BUILD_TESTS OFF)
  set(immer_BUILD_EXAMPLES OFF)
  set(immer_BUILD_DOCS OFF)
  set(immer_BUILD_EXTRAS OFF)
  FetchContent_Declare(immer GIT_REPOSITORY https://github.com/arximboldi/immer GIT_TAG
    800ddb04e528a3e83e69e8021d7e872e7c34cbcd)
  FetchContent_MakeAvailable(immer)
endif()

find_package(Zug)
if(NOT Zug_FOUND)
  message(STATUS "Using zug from FetchContent")
  set(zug_BUILD_TESTS OFF)
  set(zug_BUILD_EXAMPLES OFF)
  set(zug_BUILD_DOCS OFF)
  FetchContent_Declare(zug GIT_REPOSITORY https://github.com/arximboldi/zug GIT_TAG
    266cc7fcc01f546c4fd0dabf3a26c71ddc7f3e7d)
  FetchContent_MakeAvailable(zug)
endif()

find_package(Lager)
if(NOT Lager_FOUND)
  message(STATUS "Using lager from FetchContent")
  set(lager_BUILD_TESTS OFF)
  set(lager_BUILD_EXAMPLES OFF)
  set(lager_BUILD_DOCS OFF)
  set(lager_EMBED_RESOURCES_PATH OFF)
  FetchContent_Declare(lager GIT_REPOSITORY https://github.com/arximboldi/lager GIT_TAG
    71eca6b0ebbccf3e0e54324b6967f047e49ba92d)
  FetchContent_MakeAvailable(lager)
endif()

find_package(cryptopp REQUIRED)

find_package(Olm REQUIRED)

if(libkazv_BUILD_EXAMPLES)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(LIBHTTPSERVER REQUIRED libhttpserver)
endif()

if(libkazv_OUTPUT_LEVEL)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DLIBKAZV_OUTPUT_LEVEL=${libkazv_OUTPUT_LEVEL}")
endif()

include(GNUInstallDirs)

set(ConfigPackageLocation ${CMAKE_INSTALL_LIBDIR}/cmake/libkazv)

add_subdirectory(src)

install(EXPORT libkazvTargets
  NAMESPACE
    libkazv::
  DESTINATION
    ${ConfigPackageLocation}
)

install(
  FILES cmake/libkazvConfig.cmake
  DESTINATION ${ConfigPackageLocation})

# cpr does not install a good config file.
# We use the find module instead.
install(
  FILES cmake/Findcpr.cmake
  cmake/Findcryptopp.cmake
  DESTINATION ${ConfigPackageLocation})
