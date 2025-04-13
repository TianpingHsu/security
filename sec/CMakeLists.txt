cmake_minimum_required(VERSION 3.20)
project(security CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find MbedTLS package
find_package(MbedTLS REQUIRED)

# Add include directories
include_directories(${PROJECT_SOURCE_DIR}/inc)

# Get all source files
file(GLOB_RECURSE SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")

# Add source files
add_executable(security ${SOURCES})

target_include_directories(security PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
)

# Link against MbedTLS
target_link_libraries(security PRIVATE
    mbedtls
    mbedcrypto
    mbedx509
)

# Optional: Add tests if they exist
option(BUILD_TESTS "Build tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
