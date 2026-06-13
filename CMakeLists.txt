cmake_minimum_required(VERSION 3.20)

project(modern_pki VERSION 0.0.0 LANGUAGES CXX)

add_library(modern_pki_core
    src/version.cpp
)
add_library(modern_pki::core ALIAS modern_pki_core)

target_compile_features(modern_pki_core PUBLIC cxx_std_20)
target_include_directories(modern_pki_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

include(CTest)

if(BUILD_TESTING)
    add_executable(modern_pki_version_test
        tests/version_test.cpp
    )
    target_link_libraries(modern_pki_version_test PRIVATE modern_pki::core)
    add_test(NAME modern_pki.version COMMAND modern_pki_version_test)
endif()
