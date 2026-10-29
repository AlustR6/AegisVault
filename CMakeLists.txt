cmake_minimum_required(VERSION 3.21)

project(AegisVault
    VERSION 0.1.0
    LANGUAGES CXX
)


# ============================================================
# Project Configuration
# ============================================================

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR
        "Aegis Vault currently requires Windows."
    )
endif()


# ============================================================
# External Dependencies
# ============================================================

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)


# ============================================================
# Aegis Core Library
# ============================================================

# Only application implementation files belong here.
# Never add test_*.cpp files to aegis_core.

add_library(aegis_core STATIC
    src/secure_buffer.cpp
    src/secure_text.cpp
    src/terminal.cpp
    src/crypto.cpp
    src/vault_format.cpp
    src/vault_verification.cpp
    src/vault_credential.cpp
    src/vault_catalog.cpp
    src/vault_repository.cpp
)

target_include_directories(aegis_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_features(aegis_core
    PUBLIC
        cxx_std_20
)

target_link_libraries(aegis_core
    PUBLIC
        unofficial-sodium::sodium

    PRIVATE
        kernel32
)


# ============================================================
# Prevent Test Files From Being Added to Core
# ============================================================

get_target_property(AEGIS_CORE_SOURCES aegis_core SOURCES)

foreach(source_file IN LISTS AEGIS_CORE_SOURCES)

    get_filename_component(source_name "${source_file}" NAME)

    if(source_name MATCHES "^test_.*\\.cpp$")

        message(FATAL_ERROR
            "Test source ${source_file} cannot be part of aegis_core."
        )

    endif()

endforeach()


# ============================================================
# Aegis Vault Command-Line Application
# ============================================================

add_executable(aegis_vault
    src/main.cpp
)

target_link_libraries(aegis_vault
    PRIVATE
        aegis_core
)


# ============================================================
# GoogleTest Executable
# ============================================================

enable_testing()

add_executable(aegis_tests
    tests/test_main.cpp
    tests/test_smoke.cpp
    tests/test_secure_buffer.cpp
    tests/test_secure_text.cpp
    tests/test_crypto.cpp
    tests/test_aead.cpp
    tests/test_vault_format.cpp
    tests/test_vault_verification.cpp
    tests/test_vault_credential.cpp
    tests/test_vault_catalog.cpp
    tests/test_vault_repository.cpp
)

target_link_libraries(aegis_tests
    PRIVATE
        aegis_core
        GTest::gtest
)


# ============================================================
# CTest Registration
# ============================================================

add_test(
    NAME AegisTests
    COMMAND aegis_tests
)