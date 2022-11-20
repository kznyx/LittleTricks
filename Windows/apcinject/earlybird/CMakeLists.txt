cmake_minimum_required(VERSION 3.0.0)
project(earlybird VERSION 0.1.0)

include(CTest)
enable_testing()


add_executable(earlybird main.cpp)

set(CMAKE_BUILD_TYPE "Release")
set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
