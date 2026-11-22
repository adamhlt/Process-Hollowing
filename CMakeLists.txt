cmake_minimum_required(VERSION 3.20)

project(ProcessHollowing LANGUAGES CXX)

if (NOT WIN32)
    message(FATAL_ERROR "Process Hollowing only supports Windows.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(RUNPE_SOURCES
    Source/src/main.cpp
    Source/src/error.cpp
    Source/src/log.cpp
    Source/src/pe_image.cpp
    Source/src/process.cpp
    Source/src/thread_context.cpp
    Source/src/injector.cpp
)

add_executable(runpe ${RUNPE_SOURCES})
target_include_directories(runpe PRIVATE Source/include)
target_compile_definitions(runpe PRIVATE
    UNICODE
    _UNICODE
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00
)

if (MSVC)
    target_compile_options(runpe PRIVATE /W4 /permissive- /utf-8 /EHsc)
else()
    target_compile_options(runpe PRIVATE -Wall -Wextra -Wpedantic)
endif()

set_target_properties(runpe PROPERTIES OUTPUT_NAME "runpe")
