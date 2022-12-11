cmake_minimum_required(VERSION 3.0.0)
project(demo VERSION 0.1.0)

include(CTest)
enable_testing()

add_executable(demo main.cpp)

if (MSVC)
    target_compile_options(demo PRIVATE /W4)
else()
    target_compile_options(demo PRIVATE -Wall)
endif()

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
