cmake_minimum_required(VERSION 3.24)
set(VCPKG_TARGET_TRIPLET "x86-windows" CACHE STRING "target triplet")

set(CMAKE_TOOLCHAIN_FILE C:/vcpkg/scripts/buildsystems/vcpkg.cmake
  CACHE STRING "Vcpkg toolchain file")


project(AVIRCLIENT)
add_executable(AVIRCLIENT AVIRclient.c)
  message(toolchain = "${CMAKE_TOOLCHAIN_FILE}")
  message(STATUS "Target triplet for release is " ${VCPKG_TARGET_TRIPLET})

find_package(CURL CONFIG REQUIRED) 
find_package(json-c CONFIG)

target_link_libraries(${PROJECT_NAME} PRIVATE json-c::json-c)

target_link_libraries(AVIRCLIENT PRIVATE CURL::libcurl)
