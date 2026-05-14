cmake_minimum_required(VERSION 3.16)
project(GoodbyeDPI VERSION 0.2.4 LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    set(PLATFORM_DIR "win32")
    add_definitions(-D_WIN32_WINNT=0x0601)
elseif(APPLE)
    set(PLATFORM_DIR "macos")
elseif(UNIX)
    set(PLATFORM_DIR "linux")
else()
    message(FATAL_ERROR "Unsupported platform")
endif()

message(STATUS "Building for platform: ${PLATFORM_DIR}")

# Common source files (platform-independent)
set(COMMON_SOURCES
    src/dnsredir.c
    src/fakepackets.c
    src/ttltrack.c
    src/blackwhitelist.c
    src/utils/repl_str.c
    src/utils/getline.c
)

# Platform-specific source files
if(WIN32)
    # On Windows, use the original goodbyedpi.c which directly uses WinDivert
    set(MAIN_SOURCE src/goodbyedpi.c)
    set(PLATFORM_SOURCES
        src/platform/win32/packet_capture.c
        src/platform/win32/service.c
        src/platform/win32/os_utils.c
        src/service.c
    )
else()
    # On Linux/macOS, use the new cross-platform main
    set(MAIN_SOURCE src/goodbyedpi_main.c)
    set(PLATFORM_SOURCES
        src/platform/${PLATFORM_DIR}/packet_capture.c
        src/platform/${PLATFORM_DIR}/service.c
        src/platform/${PLATFORM_DIR}/os_utils.c
    )
endif()

# Include directories
include_directories(
    src
    src/platform
    src/utils
)

# Create executable
add_executable(goodbyedpi ${MAIN_SOURCE} ${COMMON_SOURCES} ${PLATFORM_SOURCES})

# Platform-specific configuration
if(WIN32)
    # WinDivert
    if(DEFINED WINDIVERT_PATH)
        include_directories(${WINDIVERT_PATH}/include)
        link_directories(${WINDIVERT_PATH}/lib)
    else()
        message(STATUS "WINDIVERT_PATH not set, using system paths")
    endif()

    target_link_libraries(goodbyedpi ws2_32 WinDivert)
    target_compile_definitions(goodbyedpi PRIVATE _CRT_SECURE_NO_WARNINGS)

    # Windows resource file
    if(MINGW)
        enable_language(RC)
        target_sources(goodbyedpi PRIVATE src/goodbyedpi-rc.rc)
    endif()

    # Security flags
    if(MINGW)
        target_link_options(goodbyedpi PRIVATE
            -Wl,--dynamicbase,--nxcompat,--sort-common,--as-needed
        )
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_link_options(goodbyedpi PRIVATE -Wl,--high-entropy-va)
        endif()
    endif()

elseif(APPLE)
    # macOS: link against math library
    target_link_libraries(goodbyedpi m)

elseif(UNIX)
    # Linux: link against nfqueue and nfnetlink
    find_library(NFQUEUE_LIB netfilter_queue)
    find_library(NFNETLINK_LIB nfnetlink)
    if(NFQUEUE_LIB AND NFNETLINK_LIB)
        target_link_libraries(goodbyedpi ${NFQUEUE_LIB} ${NFNETLINK_LIB})
    else()
        message(WARNING "libnetfilter_queue not found. Install: apt install libnetfilter-queue-dev")
    endif()
    target_link_libraries(goodbyedpi m)
endif()

# Compiler warnings
target_compile_options(goodbyedpi PRIVATE
    -Wall -Wextra -Wpedantic
    -Wformat=2 -Wformat-security
    -Wshadow -Wcast-align
)

# Fortify source in release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(goodbyedpi PRIVATE _FORTIFY_SOURCE=2)
    target_compile_options(goodbyedpi PRIVATE -O2 -fstack-protector)
endif()

# Debug mode
option(ENABLE_DEBUG "Enable debug output" OFF)
if(ENABLE_DEBUG)
    target_compile_definitions(goodbyedpi PRIVATE DEBUG)
endif()

# Install
install(TARGETS goodbyedpi DESTINATION bin)
