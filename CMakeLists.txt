cmake_minimum_required(VERSION 3.7)

project(libhappy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

set(CMAKE_BUILD_TYPE Debug)

add_library(
  happy
  net.cpp
  sip.cpp
  utils.cpp
)

add_executable(
  testhappy
  testhappy.cpp
)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(happy Threads::Threads)

target_link_libraries(testhappy happy)

include(FindPkgConfig)

pkg_check_modules(SAMPLERATE REQUIRED samplerate)
target_link_libraries(happy ${SAMPLERATE_LIBRARIES})
target_include_directories(happy PUBLIC ${SAMPLERATE_INCLUDE_DIRS})
target_compile_options(happy PUBLIC ${SAMPLERATE_CFLAGS_OTHER})

pkg_check_modules(SPEEX REQUIRED speex)
target_link_libraries(happy ${SPEEX_LIBRARIES})
target_include_directories(happy PUBLIC ${SPEEX_INCLUDE_DIRS})
target_compile_options(happy PUBLIC ${SPEEX_CFLAGS_OTHER})

find_package(OpenSSL REQUIRED)
target_include_directories(happy PUBLIC ${OPENSSL_INCLUDE_DIR})
target_link_libraries(happy OpenSSL::SSL OpenSSL::Crypto)

include(FindPkgConfig)
