cmake_minimum_required(VERSION 3.10)
project(vpn-core)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(vpn-core src/main.cpp)
target_link_libraries(vpn-core PRIVATE OpenSSL::SSL)