cmake_minimum_required(VERSION 3.7)

project(libhappy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_options(-Wall)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)

set(CMAKE_BUILD_TYPE Debug)

add_library(
  happy
  any_addr.cpp
  sip.cpp
  utils.cpp
)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads)
target_link_libraries(happy Threads::Threads)

include(FindPkgConfig)
