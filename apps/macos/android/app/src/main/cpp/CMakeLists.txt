cmake_minimum_required(VERSION 3.22.1)
project(credpivot_android LANGUAGES C)
add_library(credpivot_ffi SHARED IMPORTED)
set_target_properties(credpivot_ffi PROPERTIES
    IMPORTED_NO_SONAME TRUE
    IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../rustLibs/${ANDROID_ABI}/libcredpivot_ffi.so")
add_library(credpivot_android SHARED bridge.c)
target_link_libraries(credpivot_android PRIVATE credpivot_ffi)
target_link_options(credpivot_android PRIVATE "-Wl,-z,max-page-size=16384")
