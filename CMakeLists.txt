cmake_minimum_required(VERSION 3.20)

project(modern_pki VERSION 0.0.0 LANGUAGES CXX)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_library(modern_pki_core
    src/core/csr.cpp
    src/core/issue.cpp
    src/version.cpp
)
add_library(modern_pki::core ALIAS modern_pki_core)

target_compile_features(modern_pki_core PUBLIC cxx_std_20)
target_include_directories(modern_pki_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(modern_pki_core
    PRIVATE
        OpenSSL::Crypto
)

add_executable(modern-pki-core
    src/cli/main.cpp
)
target_link_libraries(modern-pki-core PRIVATE modern_pki::core)

if(WIN32 AND OPENSSL_ROOT_DIR)
    file(TO_CMAKE_PATH "${OPENSSL_ROOT_DIR}" OPENSSL_ROOT_DIR_CMAKE)
    file(GLOB OPENSSL_RUNTIME_DLLS CONFIGURE_DEPENDS "${OPENSSL_ROOT_DIR_CMAKE}/bin/*.dll")
    if(OPENSSL_RUNTIME_DLLS)
        add_custom_command(
            TARGET modern-pki-core
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    ${OPENSSL_RUNTIME_DLLS}
                    $<TARGET_FILE_DIR:modern-pki-core>
            COMMAND_EXPAND_LISTS
        )
    endif()
endif()

include(CTest)

if(BUILD_TESTING)
    add_executable(modern_pki_version_test
        tests/version_test.cpp
    )
    target_link_libraries(modern_pki_version_test PRIVATE modern_pki::core)
    add_test(NAME modern_pki.version COMMAND modern_pki_version_test)

    add_executable(modern_pki_core_cli_contract_test
        tests/core_cli_contract_test.cpp
    )
    target_link_libraries(modern_pki_core_cli_contract_test PRIVATE modern_pki::core)
    add_dependencies(modern_pki_core_cli_contract_test modern-pki-core)
    add_test(
        NAME modern_pki.core_cli_contract
        COMMAND modern_pki_core_cli_contract_test $<TARGET_FILE:modern-pki-core> ${CMAKE_CURRENT_BINARY_DIR}
    )

    add_executable(modern_pki_core_issue_profile_test
        tests/core_issue_profile_test.cpp
    )
    target_link_libraries(modern_pki_core_issue_profile_test PRIVATE modern_pki::core OpenSSL::Crypto)
    add_dependencies(modern_pki_core_issue_profile_test modern-pki-core)
    add_test(
        NAME modern_pki.core_issue_profile
        COMMAND modern_pki_core_issue_profile_test $<TARGET_FILE:modern-pki-core> ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()
