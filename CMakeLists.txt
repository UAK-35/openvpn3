set(CLI_OVPNDCO "1")
# set(USE_OPENSSL "1")
set(CMAKE_INSTALL_CONFIG_NAME "Debug")
set(CMAKE_INSTALL_PREFIX "/home/mgr/O3/core/install2" CACHE PATH "Installation directory")

# set(CMAKE_GENERATOR "Unix Makefiles")
message("generator is set to ${CMAKE_GENERATOR}")

cmake_minimum_required(VERSION 3.5)
cmake_policy(SET CMP0048 NEW)

project(OpenVPN3-core VERSION 3)

# AddressSanitize - use CXX=clang++ CC=clang cmake -DCMAKE_BUILD_TYPE=asan to build with ASAN
# export  UBSAN_OPTIONS=print_stacktrace=1 helps debugging these
set(CMAKE_C_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
        FORCE)
set(CMAKE_CXX_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
        CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
        FORCE)

set(CMAKE_LINKER_FLAGS_ASAN
        "-fsanitize=address,undefined -fno-sanitize-recover=all -fsanitize-address-use-after-scope"
        CACHE STRING "Flags used by the linker during AddressSanitizer builds."
        FORCE)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake
                      ${CMAKE_MODULE_PATH})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 99)

include(findcoredeps)
include(ovpn-doxygen)

add_subdirectory(client)
add_subdirectory(test/unittests)
add_subdirectory(test/ovpncli)
add_subdirectory(test/ssl)

add_executable(example1 example1.cpp)
target_compile_definitions(example1 PRIVATE)
target_link_libraries(example1 xkey)
add_core_dependencies(example1)
#add_core_dependencies(ovpnclilib)

if (WIN32)
    add_subdirectory(openvpn/omi)
    add_subdirectory(openvpn/ovpnagent/win)
endif ()

if (APPLE)
    add_subdirectory(openvpn/ovpnagent/mac)
endif ()


if (ENABLE_DOXYGEN)
    # Exclude some project specific directories
    set(DOXYGEN_EXCLUDE_PATTERNS
        ${CMAKE_BINARY_DIR}/test/unittests/googletest-*
        ${PROJECT_SOURCE_DIR}/deps/*
        ${PROJECT_SOURCE_DIR}/test/unittests/googletest-*)

    # Use README.rst as the Doxygen main page
    # Due to some doxygen oddities, it rejects processing README.rst, but a .md file is fine
    # So we copy it into our build tree as a .md file and use that
    file(COPY "${CMAKE_SOURCE_DIR}/README.rst" DESTINATION "${CMAKE_BINARY_DIR}/doxygen")
    file(RENAME "${CMAKE_BINARY_DIR}/doxygen/README.rst" "${CMAKE_BINARY_DIR}/doxygen/mainpage.md")
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE "${CMAKE_BINARY_DIR}/doxygen/mainpage.md")

    configure_doxygen("OpenVPN 3 Core Library" "doxygen/core")
endif ()
