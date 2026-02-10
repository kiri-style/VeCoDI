zephyr_library()

zephyr_library_include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/Include
)

file(GLOB_RECURSE CMSIS_NN_SRC
    ${CMAKE_CURRENT_LIST_DIR}/Source/**/*.c
)

if(NOT CMSIS_NN_SRC)
    message(FATAL_ERROR "No CMSIS-NN source files found")
endif()

zephyr_library_sources(${CMSIS_NN_SRC})