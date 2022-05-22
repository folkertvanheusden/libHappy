cmake_minimum_required(VERSION 3.7)

project(libhappy VERSION 0.0.1 DESCRIPTION "libHappy - a VOIP/SIP library")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

set(CMAKE_BUILD_TYPE Debug)

add_library(
  happy SHARED
  md5.cpp
  net.cpp
  sip.cpp
  utils.cpp
)

set_target_properties(happy PROPERTIES VERSION ${PROJECT_VERSION} PUBLIC_HEADER sip.h)

add_executable(
  testhappy
  testhappy.cpp
)

add_executable(
  testhappy-alsa
  testhappy-alsa.cpp
)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(happy Threads::Threads)

# for RPI
target_link_libraries(happy atomic)

target_link_libraries(testhappy happy)

target_link_libraries(testhappy-alsa happy)

include(FindPkgConfig)

pkg_check_modules(SAMPLERATE REQUIRED samplerate)
target_link_libraries(happy ${SAMPLERATE_LIBRARIES})
target_include_directories(happy PUBLIC ${SAMPLERATE_INCLUDE_DIRS})
target_compile_options(happy PUBLIC ${SAMPLERATE_CFLAGS_OTHER})

pkg_check_modules(SNDFILE REQUIRED sndfile)
target_link_libraries(happy ${SNDFILE_LIBRARIES})
target_include_directories(happy PUBLIC ${SNDFILE_INCLUDE_DIRS})
target_compile_options(happy PUBLIC ${SNDFILE_CFLAGS_OTHER})

find_package(OpenSSL REQUIRED)
target_include_directories(happy PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(happy OpenSSL::SSL OpenSSL::Crypto)

pkg_check_modules(ALSA REQUIRED alsa)
target_link_libraries(testhappy-alsa ${ALSA_LIBRARIES})
target_include_directories(testhappy-alsa PUBLIC ${ALSA_INCLUDE_DIRS})
target_compile_options(testhappy-alsa PUBLIC ${ALSA_CFLAGS_OTHER})

include(FindPkgConfig)

set_target_properties(happy PROPERTIES PUBLIC_HEADER "sip.h;utils.h")

include(GNUInstallDirs)

install(TARGETS happy
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME})

configure_file(libhappy.pc.in libhappy.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/libhappy.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

install(FILES testhappy-alsa.cpp testhappy.cpp README.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
