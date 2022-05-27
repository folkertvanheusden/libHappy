cmake_minimum_required(VERSION 3.7)

project(libhappy VERSION 0.3.0 DESCRIPTION "libHappy - a VOIP/SIP library")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall -pedantic)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

set(CMAKE_BUILD_TYPE Debug)

add_library(
  happy SHARED
  md5.cpp
  net.cpp
  sip.cpp
  utils.cpp
  libg722/g722_decode.c
  libg722/g722_encode.c
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

add_executable(
  testhappy-mpd
  testhappy-mpd.cpp
)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(happy Threads::Threads)

# for RPI
target_link_libraries(happy atomic)

target_link_libraries(testhappy happy)

target_link_libraries(testhappy-alsa happy)

target_link_libraries(testhappy-mpd happy)

include(FindPkgConfig)

pkg_check_modules(SAMPLERATE REQUIRED samplerate)
target_link_libraries(happy ${SAMPLERATE_LIBRARIES})
target_include_directories(happy PUBLIC ${SAMPLERATE_INCLUDE_DIRS})
target_compile_options(happy PUBLIC ${SAMPLERATE_CFLAGS_OTHER})

pkg_check_modules(ALSA REQUIRED alsa)
target_link_libraries(testhappy-alsa ${ALSA_LIBRARIES})
target_include_directories(testhappy-alsa PUBLIC ${ALSA_INCLUDE_DIRS})
target_compile_options(testhappy-alsa PUBLIC ${ALSA_CFLAGS_OTHER})

pkg_check_modules(MPD REQUIRED libmpd)
target_link_libraries(testhappy-mpd ${MPD_LIBRARIES})
target_include_directories(testhappy-mpd PUBLIC ${MPD_INCLUDE_DIRS})
target_compile_options(testhappy-mpd PUBLIC ${MPD_CFLAGS_OTHER})

include(FindPkgConfig)

set_target_properties(happy PROPERTIES PUBLIC_HEADER "sip.h;utils.h")

include(GNUInstallDirs)

install(TARGETS happy
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
	)

configure_file(libhappy.pc.in libhappy.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/libhappy.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

install(FILES libg722/g722_encoder.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/libg722)
install(FILES libg722/g722_decoder.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/libg722)
install(FILES libg722/g722.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}/libg722)

install(FILES testhappy-alsa.cpp testhappy.cpp README.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
