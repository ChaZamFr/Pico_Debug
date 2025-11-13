# Generated Cmake Pico project file

cmake_minimum_required(VERSION 3.13)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
add_compile_options(-O0)

# Initialise pico_sdk from installed location
# (note this can come from environment, CMake cache etc)

# == DO NOT EDIT THE FOLLOWING LINES for the Raspberry Pi Pico VS Code Extension to work ==
if(WIN32)
    set(USERHOME $ENV{USERPROFILE})
else()
    set(USERHOME $ENV{HOME})
endif()
set(sdkVersion 2.2.0)
set(toolchainVersion 14_2_Rel1)
set(picotoolVersion 2.2.0)
set(picoVscode ${USERHOME}/.pico-sdk/cmake/pico-vscode.cmake)
if (EXISTS ${picoVscode})
    include(${picoVscode})
endif()
# ====================================================================================
set(PICO_BOARD pico_w CACHE STRING "Board type")

# Pull in Raspberry Pi Pico SDK (must be before project)
#include(pico_sdk_import.cmake)
include(${CMAKE_SOURCE_DIR}/pico-sdk/external/pico_sdk_import.cmake)


project(matrix_mul C CXX ASM)

# Initialise the Raspberry Pi Pico SDK
pico_sdk_init()

# Add executable. Default name is the project name, version 0.1

add_executable(matrix_mul matrix_mul.cpp )

pico_set_program_name(matrix_mul "matrix_mul")
pico_set_program_version(matrix_mul "0.1")

# Modify the below lines to enable/disable output over UART/USB
pico_enable_stdio_uart(matrix_mul 0)
pico_enable_stdio_usb(matrix_mul 0)

# Add the standard library to the build
target_link_libraries(matrix_mul
        pico_stdlib)

# Add the standard include files to the build
target_include_directories(matrix_mul PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
)

# Add any user requested libraries
target_link_libraries(matrix_mul 
        pico_cyw43_arch_none
        )

pico_add_extra_outputs(matrix_mul)
