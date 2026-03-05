cmake_minimum_required(VERSION 3.20.0)

# Ensure USART2 (VCP) overlay is applied (force cache for sysbuild)
set(DTC_OVERLAY_FILE ${CMAKE_CURRENT_LIST_DIR}/boards/nucleo_l552ze_q.overlay CACHE STRING "" FORCE)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(tensorflow_hello_world)

# ============================================================
# TF-M CONFIG
# ============================================================
if(TARGET tfm)
  get_target_property(TFM_BINARY_DIR tfm TFM_BINARY_DIR)

  configure_file(
    ${CMAKE_CURRENT_LIST_DIR}/dummy_partition/tfm_manifest_list.yaml.in
    ${CMAKE_CURRENT_BINARY_DIR}/dummy_partition/tfm_manifest_list.yaml
  )

  set_property(TARGET zephyr_property_target
    APPEND PROPERTY TFM_CMAKE_OPTIONS
    -DTFM_EXTRA_MANIFEST_LIST_FILES=${CMAKE_CURRENT_BINARY_DIR}/dummy_partition/tfm_manifest_list.yaml
    -DTFM_EXTRA_PARTITION_PATHS=${CMAKE_CURRENT_LIST_DIR}/dummy_partition
  )
endif()

# ============================================================
# C++ static init fix (important for Cortex-M)
# ============================================================
set(NO_THREADSAFE_STATICS $<TARGET_PROPERTY:compiler-cpp,no_threadsafe_statics>)
zephyr_compile_options($<$<COMPILE_LANGUAGE:CXX>:${NO_THREADSAFE_STATICS}>)

# ============================================================
# Application sources
# ============================================================
target_sources(app PRIVATE
    src/main.cpp
    src/create_enclave.cpp
    src/split_inference.cpp
    src/test_images.c
    src/benchmark.cpp
    src/secure_benchmark_ns.cpp
    src/provider_sim.cpp
    src/test_enclave_auth.c
    src/inference_protocol.cpp
    src/test_inference_protocol.cpp
    src/uart_protocol.cpp
    split_inference/late/L_nn_wt_encrypted_data.c
    src/run_enclave.cpp
)

target_link_options(app PRIVATE
    -Wl,--undefined=ns_run_enclave
)

zephyr_linker_sources(SECTIONS ${CMAKE_CURRENT_SOURCE_DIR}/src/model_ro.ld)
#zephyr_linker_sources(SECTIONS linker.ld)

# ============================================================
# Include directories (APP ONLY)
# ============================================================
target_include_directories(app PRIVATE
    ${TFM_BINARY_DIR}/api_ns/interface/include

    # TFLite Micro
    ${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro
    ${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro/tensorflow
    ${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro/tensorflow/lite
    ${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro/tensorflow/lite/micro
    ${ZEPHYR_BASE}/../optional/modules/lib/tflite-micro/tensorflow/lite/kernels

    # SecureQNN / generated headers
    ${CMAKE_CURRENT_LIST_DIR}/src
    #${CMAKE_CURRENT_LIST_DIR}/src/ns
    #${CMAKE_CURRENT_LIST_DIR}/src/s
)

# ============================================================
# CMSIS-NN (Zephyr library)
# ============================================================
add_subdirectory(src/CMSIS_NN)

# ============================================================
# Compile definitions
# ============================================================
target_compile_definitions(app PRIVATE
    TFM_PARTITION_DUMMY_PARTITION
    
)

# ================= CMSIS-NN =================
set(CMSIS_NN_PATH ${CMAKE_CURRENT_SOURCE_DIR}/src/CMSIS_NN)

zephyr_include_directories(
    ${CMSIS_NN_PATH}/Include
)

file(GLOB_RECURSE CMSIS_NN_SOURCES
    ${CMSIS_NN_PATH}/Source/*.c
)

target_sources(app PRIVATE ${CMSIS_NN_SOURCES})

