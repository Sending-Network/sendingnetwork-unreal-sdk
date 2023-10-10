cmake_minimum_required(VERSION 3.11...3.13)


set(
	CMAKE_TOOLCHAIN_FILE
	"${CMAKE_CURRENT_LIST_DIR}/toolchain.cmake"
	CACHE
	FILEPATH
	"Default toolchain"
	)
set(CMAKE_CXX_STANDARD 20 CACHE STRING "C++ standard")
set(CMAKE_CXX_STANDARD_REQUIRED ON CACHE BOOL "Require C++ standard to be supported")
set(CMAKE_POSITION_INDEPENDENT_CODE ON CACHE BOOL "compile as PIC by default")

option(HUNTER_ENABLED "Enable Hunter package manager" OFF)
include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.8.tar.gz"
    SHA1 "ca7838dded9a1811b04ffd56175f629e0af82d3d"
    LOCAL
)

option(USE_BUNDLED_SPDLOG "Use the bundled version of spdlog."
	${HUNTER_ENABLED})
option(USE_BUNDLED_OLM "Use the bundled version of libolm." ${HUNTER_ENABLED})
option(USE_BUNDLED_GTEST "Use the bundled version of Google Test."
	${HUNTER_ENABLED})
option(USE_BUNDLED_JSON "Use the bundled version of nlohmann json."
	${HUNTER_ENABLED})
option(USE_BUNDLED_OPENSSL "Use the bundled version of OpenSSL."
	${HUNTER_ENABLED})
option(USE_BUNDLED_COEURL "Use a bundled version of the Curl wrapper"
	${HUNTER_ENABLED})
option(USE_BUNDLED_LIBEVENT "Use the bundled version of libevent." ${HUNTER_ENABLED})
option(USE_BUNDLED_LIBCURL "Use the bundled version of libcurl." ${HUNTER_ENABLED})
option(USE_BUNDLED_RE2 "Use the bundled version of re2." ${HUNTER_ENABLED})
option(USE_BUNDLED_SECP256K1 "Use the bundled version of libsecp256k1." ${HUNTER_ENABLED})

project(sdn_client
	VERSION 0.9.2
	DESCRIPTION "Client API library for SendingNetwork.")

option(ASAN "Compile with address sanitizers" OFF)
option(BUILD_LIB_TESTS "Build tests" OFF)
option(BUILD_LIB_EXAMPLES "Build examples" OFF)
option(COVERAGE "Calculate test coverage" OFF)
option(IWYU "Check headers with include-what-you-use" OFF)
option(BUILD_SHARED_LIBS "Specifies whether to build mtxclient as a shared library lib or not" ON)
option(JSON_ImplicitConversions "Disable implicit conversions in nlohmann/json" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(NOT MSVC AND NOT CLANG_TIDY_WORKAROUND)
	set(
		CMAKE_CXX_FLAGS
		"${CMAKE_CXX_FLAGS} \
		-Wall \
		-Wextra \
		-Wconversion \
		-pipe \
		-pedantic \
		-fsized-deallocation \
		-fdiagnostics-color=always \
		-Wno-attributes \
		-Wunreachable-code"
		)
endif()

if(MSVC)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /bigobj -bigobj")
endif()

if(ASAN)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined")
endif()

add_library(sdn_client)

if(NOT MSVC AND NOT APPLE)
	set(THREADS_PREFER_PTHREAD_FLAG ON)
	find_package(Threads REQUIRED)
endif()

include(FeatureSummary)

if(USE_BUNDLED_OPENSSL)
	hunter_add_package(OpenSSL)
endif()
find_package(OpenSSL 1.1.0 REQUIRED)
set_package_properties(OpenSSL PROPERTIES
	DESCRIPTION "Open source SSL and TLS implementation and cryptographic library"
	URL "https://www.openssl.org/"
	TYPE REQUIRED
	)

if(USE_BUNDLED_OLM)
	include(FetchContent)
	FetchContent_Declare(
		Olm
		GIT_REPOSITORY https://gitlab.matrix.org/matrix-org/olm.git
		GIT_TAG        3.2.14
		)
	FetchContent_MakeAvailable(Olm)
else()
	find_package(Olm 3.2.7 REQUIRED)
	set_package_properties(Olm PROPERTIES
		DESCRIPTION "An implementation of the Double Ratchet cryptographic ratchet"
		URL "https://git.matrix.org/git/olm/about/"
		TYPE REQUIRED
		)
endif()

if(USE_BUNDLED_JSON)
	hunter_add_package(nlohmann_json)
endif()
find_package(nlohmann_json 3.2.0 CONFIG REQUIRED)
set_package_properties(nlohmann_json PROPERTIES
	DESCRIPTION "JSON for Modern C++, a C++11 header-only JSON class"
	URL "https://nlohmann.github.io/json/"
	TYPE REQUIRED
	)

if(USE_BUNDLED_RE2)
	hunter_add_package(re2)
	find_package(re2 CONFIG REQUIRED)
	target_link_libraries(sdn_client PRIVATE re2::re2)
else()
	find_package(PkgConfig REQUIRED) 
	pkg_check_modules(re2 REQUIRED IMPORTED_TARGET re2)
	target_link_libraries(sdn_client PRIVATE PkgConfig::re2)
endif()

## Need to repeat all libevent deps?!?
# libevent
if (USE_BUNDLED_LIBEVENT)
	hunter_add_package(Libevent)
	find_package(Libevent CONFIG REQUIRED)
else()
	find_package(PkgConfig REQUIRED) 
	pkg_check_modules(libevent_core REQUIRED IMPORTED_TARGET libevent_core)
	if (WIN32)
		pkg_check_modules(libevent_windows REQUIRED IMPORTED_TARGET libevent_windows)
	else()
		pkg_check_modules(libevent_pthreads REQUIRED IMPORTED_TARGET
			libevent_pthreads)
	endif()
endif()

# curl
if (USE_BUNDLED_LIBCURL)
	hunter_add_package(CURL)
	find_package(CURL CONFIG REQUIRED)
else()
	find_package(PkgConfig REQUIRED) 
	pkg_check_modules(libcurl REQUIRED IMPORTED_TARGET libcurl)
endif()

# spdlog
if(USE_BUNDLED_SPDLOG)
	hunter_add_package(spdlog)
endif()
find_package(spdlog 1.0.0 CONFIG)
set_package_properties(spdlog PROPERTIES
    DESCRIPTION "Very fast, header only, C++ logging library"
    URL "https://github.com/gabime/spdlog"
    TYPE REQUIRED
)
target_link_libraries(sdn_client PUBLIC spdlog::spdlog)

# coeurl
if(USE_BUNDLED_COEURL)
	include(FetchContent)
	FetchContent_Declare(
		coeurl
		GIT_REPOSITORY https://nheko.im/Nheko-Reborn/coeurl.git
		GIT_TAG        v0.3.0
		)
	FetchContent_MakeAvailable(coeurl)
	target_link_libraries(sdn_client PUBLIC coeurl::coeurl)
elseif(coeurl_DIR)
	find_package(coeurl CONFIG REQUIRED)
	target_link_libraries(sdn_client PUBLIC coeurl::coeurl)
else()
	find_package(PkgConfig REQUIRED)
	pkg_check_modules(coeurl REQUIRED IMPORTED_TARGET coeurl>=0.3.0)
	target_link_libraries(sdn_client PUBLIC PkgConfig::coeurl)
endif()

if(USE_BUNDLED_SECP256K1)
	FetchContent_Declare(
			libsecp256k1
			GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
			GIT_TAG        v0.4.0
	)
	set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE INTERNAL "Build RECOVERY MODULE")
#	set(SECP256K1_INSTALL ON CACHE INTERNAL "Enable SECP256K1 Install")
	FetchContent_MakeAvailable(libsecp256k1)
	target_link_libraries(sdn_client PRIVATE secp256k1)
else()
	find_package(libsecp256k1)
	target_link_libraries(sdn_client PRIVATE libsecp256k1::secp256k1)
endif()

target_sources(sdn_client
	PRIVATE
	lib/http/client.cpp
	lib/crypto/client.cpp
	lib/crypto/ecdsa.cpp
	lib/crypto/encoding.cpp
	lib/crypto/types.cpp
	lib/crypto/utils.cpp
	lib/utils.cpp
	lib/log.cpp
	lib/structs/common.cpp
	lib/structs/errors.cpp
	lib/structs/events.cpp
	lib/structs/identifiers.cpp
	lib/structs/pushrules.cpp
	lib/structs/requests.cpp
	lib/structs/secret_storage.cpp
	lib/structs/user_interactive.cpp
	lib/structs/events/aliases.cpp
	lib/structs/events/avatar.cpp
	lib/structs/events/canonical_alias.cpp
	lib/structs/events/collections.cpp
	lib/structs/events/common.cpp
	lib/structs/events/create.cpp
	lib/structs/events/encrypted.cpp
	lib/structs/events/encryption.cpp
	lib/structs/events/guest_access.cpp
	lib/structs/events/history_visibility.cpp
	lib/structs/events/join_rules.cpp
	lib/structs/events/member.cpp
	lib/structs/events/name.cpp
	lib/structs/events/pinned_events.cpp
	lib/structs/events/policy_rules.cpp
	lib/structs/events/power_levels.cpp
	lib/structs/events/presence.cpp
	lib/structs/events/reaction.cpp
	lib/structs/events/redaction.cpp
	lib/structs/events/server_acl.cpp
	lib/structs/events/spaces.cpp
	lib/structs/events/tag.cpp
	lib/structs/events/tombstone.cpp
	lib/structs/events/topic.cpp
	lib/structs/events/unknown.cpp
	lib/structs/events/voip.cpp
	lib/structs/events/widget.cpp
	lib/structs/events/account_data/direct.cpp
	lib/structs/events/account_data/fully_read.cpp
	lib/structs/events/account_data/ignored_users.cpp
	lib/structs/events/ephemeral/receipt.cpp
	lib/structs/events/ephemeral/typing.cpp
	lib/structs/events/nheko_extensions/event_expiry.cpp
	lib/structs/events/nheko_extensions/hidden_events.cpp
	lib/structs/events/messages/audio.cpp
	lib/structs/events/messages/elementeffect.cpp
	lib/structs/events/messages/emote.cpp
	lib/structs/events/messages/file.cpp
	lib/structs/events/messages/image.cpp
	lib/structs/events/messages/notice.cpp
	lib/structs/events/messages/text.cpp
	lib/structs/events/messages/unknown.cpp
	lib/structs/events/messages/video.cpp
	lib/structs/events/mscs/image_packs.cpp
	lib/structs/responses/capabilities.cpp
	lib/structs/responses/common.cpp
	lib/structs/responses/create_room.cpp
	lib/structs/responses/crypto.cpp
	lib/structs/responses/device.cpp
	lib/structs/responses/empty.cpp
	lib/structs/responses/login.cpp
	lib/structs/responses/media.cpp
	lib/structs/responses/members.cpp
	lib/structs/responses/messages.cpp
	lib/structs/responses/notifications.cpp
	lib/structs/responses/profile.cpp
	lib/structs/responses/register.cpp
	lib/structs/responses/sync.cpp
	lib/structs/responses/turn_server.cpp
	lib/structs/responses/users.cpp
	lib/structs/responses/version.cpp
	lib/structs/responses/well-known.cpp
	lib/structs/responses/public_rooms.cpp)
add_library(SDNClient::SDNClient ALIAS sdn_client)
set_property(TARGET sdn_client  PROPERTY CXX_STANDARD 20)
set_property(TARGET sdn_client  PROPERTY CXX_EXTENSIONS OFF)
target_include_directories(
	sdn_client
	PUBLIC
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
	$<INSTALL_INTERFACE:include>)

if (NOT JSON_ImplicitConversions)
	set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
					INTERFACE_COMPILE_DEFINITIONS "JSON_USE_IMPLICIT_CONVERSIONS=\$<BOOL:OFF>;JSON_DIAGNOSTICS=\$<BOOL:OFF>"
					)
	target_compile_definitions(sdn_client PUBLIC JSON_USE_IMPLICIT_CONVERSIONS=0)
endif()

target_link_libraries(sdn_client
	PUBLIC
	OpenSSL::Crypto
	OpenSSL::SSL
	Olm::Olm
	nlohmann_json::nlohmann_json)

if(NOT MSVC AND NOT APPLE)
	target_link_libraries(sdn_client PUBLIC Threads::Threads)
elseif(MSVC)
	target_compile_options(sdn_client PUBLIC /Zc:__cplusplus /utf-8 /MP /Gm- /EHsc)
elseif(APPLE)
	target_link_libraries(sdn_client PUBLIC "-framework CoreFoundation" "-framework Security")
endif()

if(COVERAGE)
	include(CodeCoverage)
	add_custom_target(ctest COMMAND ${CMAKE_CTEST_COMMAND})
	target_compile_options(sdn_client PUBLIC
		-O0        # no optimization
		-g         # generate debug info
		--coverage # sets all required flags
		-fprofile-arcs -ftest-coverage # just to be sure, for clang!
		)
	target_link_options(sdn_client PUBLIC --coverage)
	setup_target_for_coverage(test_coverage ctest coverage)
endif()


if(IWYU)
	find_program(iwyu_path NAMES include-what-you-use iwyu)
	if(iwyu_path)
		set_property(TARGET sdn_client
			PROPERTY CXX_INCLUDE_WHAT_YOU_USE ${iwyu_path})
	else()
		message(WARNING "Could not find the program include-what-you-use")
	endif()
endif()

if(BUILD_LIB_EXAMPLES)
	add_subdirectory(examples)
endif()

feature_summary(WHAT ALL INCLUDE_QUIET_PACKAGES FATAL_ON_MISSING_REQUIRED_PACKAGES)

#
# Installation & Target configuration.
#
include(GNUInstallDirs)
set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/SDNClient)

install(TARGETS sdn_client secp256k1
	EXPORT sdn_client-targets
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

set_target_properties(sdn_client PROPERTIES EXPORT_NAME SDNClient)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT sdn_client-targets
	FILE
	SDNClientTargets.cmake
	NAMESPACE
	SDNClient::
	DESTINATION
	${INSTALL_CONFIGDIR})

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/SDNClientConfigVersion.cmake
	VERSION
	${PROJECT_VERSION}
	COMPATIBILITY
	AnyNewerVersion)

configure_package_config_file(
	${CMAKE_CURRENT_LIST_DIR}/cmake/SDNClientConfig.cmake.in
	${CMAKE_CURRENT_BINARY_DIR}/SDNClientConfig.cmake
	INSTALL_DESTINATION
	${INSTALL_CONFIGDIR})

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/SDNClientConfig.cmake
	${CMAKE_CURRENT_BINARY_DIR}/SDNClientConfigVersion.cmake
	DESTINATION
	${INSTALL_CONFIGDIR})

export(EXPORT
	sdn_client-targets
	FILE
	${CMAKE_CURRENT_BINARY_DIR}/SDNClientTargets.cmake
	NAMESPACE
	SDNClient::)
export(PACKAGE SDNClient)

set_property(TARGET sdn_client PROPERTY SOVERSION ${PROJECT_VERSION})

if(BUILD_LIB_TESTS)
	enable_testing()

	if(USE_BUNDLED_GTEST)
		hunter_add_package(GTest)
	endif()
	find_package(GTest REQUIRED)

	file(COPY tests/fixtures DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

	add_executable(client_api tests/client_api.cpp)
	target_link_libraries(client_api
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(client_api PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(media_api tests/media_api.cpp)
	target_link_libraries(media_api
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(media_api PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(e2ee tests/e2ee.cpp)
	target_link_libraries(e2ee
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(e2ee PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(device tests/device.cpp)
	target_link_libraries(device
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(device PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(utils tests/utils.cpp)
	target_link_libraries(utils
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(utils PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(pushrules tests/pushrules.cpp)
	target_link_libraries(pushrules
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(pushrules PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(connection tests/connection.cpp)
	target_link_libraries(connection
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)
	target_include_directories(connection PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/tests)

	add_executable(identifiers tests/identifiers.cpp)
	target_link_libraries(identifiers
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(events tests/events.cpp)
	target_link_libraries(events
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(messages tests/messages.cpp)
	target_link_libraries(messages
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(voip tests/voip.cpp)
	target_link_libraries(voip
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(responses tests/responses.cpp)
	target_link_libraries(responses
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(requests tests/requests.cpp)
	target_link_libraries(requests
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(errors tests/errors.cpp)
	target_link_libraries(errors
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_executable(crypto tests/crypto.cpp)
	target_link_libraries(crypto
		SDNClient::SDNClient
		GTest::GTest
		GTest::Main)

	add_test(BasicConnectivity connection)
	add_test(ClientAPI client_api)
	add_test(MediaAPI media_api)
	add_test(Encryption e2ee)
	add_test(Devices device)
	add_test(Utilities utils)
	add_test(Pushrules pushrules)
	add_test(Identifiers identifiers)
	add_test(Errors errors)
	add_test(CryptoStructs crypto)
	add_test(StateEvents events)
	add_test(RoomEvents messages)
	add_test(VoIPEvents voip)
	add_test(Responses responses)
	add_test(Requests requests)
endif()
