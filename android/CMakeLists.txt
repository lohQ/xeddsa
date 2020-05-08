cmake_minimum_required(VERSION 3.5.0)

project(Xeddsa_plugin)

add_subdirectory(
    "../ios/Classes/xeddsa_lib" 
    "${CMAKE_CURRENT_BINARY_DIR}/xeddsa_lib_build")

