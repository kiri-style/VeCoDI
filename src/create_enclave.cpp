#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <cstring>
#include <psa/client.h>

#include "create_enclave.h"
#include "run_enclave.h"
#include "benchmark.h"
#include "split_inference.h"
#include "../split_inference/late/L_nn_wt_encrypted.h"

extern const uint8_t __model_ro_start[];
extern const uint8_t __model_ro_end[];
extern const uint8_t __inference_start[];
extern const uint8_t __inference_end[];

static size_t align_up_32(size_t value)
{
    return (value + 31U) & ~((size_t)31U);
}

static size_t resolve_requested_decrypt_size(size_t requested_size)
{
    const size_t full_size = (size_t)LATE_WT_TOTAL_SIZE;

    if (requested_size == 0U || requested_size >= full_size) {
        return full_size;
    }

    return requested_size;
}

/* ============================================================
 *                 CONFIGURATION
 * ============================================================ */

#define ENCLAVE_MEMORY_SIZE   (LATE_WT_TOTAL_SIZE)

#define ENCLAVE_STACK_SIZE    (8 * 1024)
#define ENCLAVE_THREAD_PRIORITY 5

/* PSA definitions (must match Secure manifest) */
#define ENCLAVE_SID  0xFFFFF002
#define ENCLAVE_VER  1

#define DP_CMD_SECRET_DIGEST   0
#define DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO 17U
#define DP_CMD_SET_LATE_SECRET_HASH 20U
#define DP_CMD_COMPUTE_ENCLAVE_INFO 10U
#define DP_CMD_CREATE_ENCLAVE 22U
#define DP_CMD_DESTROY_ENCLAVE 23U
#define DP_CMD_FINALIZE_CREATE_ENCLAVE 24U
#define DP_CMD_SAU_REGISTER_ROM 18U
#define DP_CMD_SAU_REGISTER_CODE 19U

/* ============================================================
 *                 GLOBALS
 * ============================================================ */

static bool enclave_created = false;
static uint32_t max_inferences_per_enclave = 0;
static bool model_ro_registered_once = false;
static bool inference_code_registered_once = false;
static bool boot_enclave_info_seeded_once = false;
static uint8_t boot_enclave_info_cache[32] = {0};
static int32_t last_create_secure_status = 0;

/* Forward declaration for reset function */
extern void reset_inference_counter(void);

/* Enclave isolated memory (late weights live here by default) */
alignas(32) static uint8_t enclave_memory[ENCLAVE_MEMORY_SIZE];
static uint8_t* enclave_region_base = enclave_memory;
static size_t enclave_region_size = ENCLAVE_MEMORY_SIZE;

K_THREAD_STACK_DEFINE(enclave_stack, ENCLAVE_STACK_SIZE);
static struct k_thread enclave_thread;

/* ============================================================
 *                 SAU ENCLAVE RAM ISOLATION (NS SIDE)
 * ============================================================ */

/* SAU/decrypt operations are now internal to Secure Create_Enclave. */

static int enclave_sau_register_rom_window(const uint8_t *base, uint32_t size)
{
    /* NS-side API call: DP_CMD_SAU_REGISTER_ROM. */
    if (base == NULL || size == 0U) {
        return -1;
    }

    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        return -1;
    }

    uint32_t cmd = DP_CMD_SAU_REGISTER_ROM;
    uint32_t params[2] = {
        (uint32_t)(uintptr_t)base,
        size,
    };
    psa_invec in_v[2] = {
        { &cmd, sizeof(cmd) },
        { params, sizeof(params) },
    };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, NULL, 0);
    psa_close(h);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

static int enclave_sau_register_code_window(const uint8_t *base, uint32_t size)
{
    /* NS-side API call: DP_CMD_SAU_REGISTER_CODE. */
    if (base == NULL || size == 0U) {
        return -1;
    }

    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        return -1;
    }

    uint32_t cmd = DP_CMD_SAU_REGISTER_CODE;
    uint32_t params[2] = {
        (uint32_t)(uintptr_t)base,
        size,
    };
    psa_invec in_v[2] = {
        { &cmd, sizeof(cmd) },
        { params, sizeof(params) },
    };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, NULL, 0);
    psa_close(h);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

int ensure_model_ro_registered(void)
{
    if (model_ro_registered_once) {
        return 0;
    }

    uint32_t rom_size = (uint32_t)(__model_ro_end - __model_ro_start);
    if (rom_size == 0U) {
        printk("[NS] model_ro section empty\n");
        return -1;
    }

    if (enclave_sau_register_rom_window(__model_ro_start, rom_size) != 0) {
        return -1;
    }
    model_ro_registered_once = true;
    return 0;
}

int ensure_inference_code_registered(void)
{
    if (inference_code_registered_once) {
        return 0;
    }

    uint32_t code_size = (uint32_t)(__inference_end - __inference_start);
    if (code_size == 0U) {
        printk("[NS] inference_ro section empty\n");
        return -1;
    }

    if (enclave_sau_register_code_window(__inference_start, code_size) != 0) {
        return -1;
    }
    inference_code_registered_once = true;
    return 0;
}

static int seed_late_secret_hash_secure(void)
{
    /* NS-side API call: DP_CMD_SET_LATE_SECRET_HASH. */
    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        return -1;
    }

    uint32_t cmd = DP_CMD_SET_LATE_SECRET_HASH;
    psa_invec in_v[2] = {
        { &cmd, sizeof(cmd) },
        { late_wt_encrypted, late_wt_encrypted_len }
    };

    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, NULL, 0);
    psa_close(h);
    return (st == PSA_SUCCESS) ? 0 : -1;
}

static int validate_boot_enclave_info_before_create(void)
{
    if (initialize_secure_enclave_info_boot() != 0) {
        printk("[NS] Failed to initialize secure boot EnclaveInfo\n");
        return -1;
    }
    /* Late-secret hash is seeded in Secure at boot initialization.
     * Re-seeding from NS during runtime can fail once model_ro is closed. */

    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        printk("[NS] psa_connect failed for current-vs-boot EnclaveInfo validation\n");
        return -1;
    }

    uint32_t cmd = DP_CMD_VALIDATE_BOOT_ENCLAVE_INFO;
    uint8_t match = 0U;
    psa_invec in_v = { &cmd, sizeof(cmd) };
    psa_outvec out_v = { &match, sizeof(match) };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, &in_v, 1, &out_v, 1);
    psa_close(h);

    if (st != PSA_SUCCESS) {
        printk("[NS] Secure current-vs-boot EnclaveInfo validation failed: %d\n", (int)st);
        return -1;
    }

    if (match != 1U) {
        printk("[NS] EnclaveInfo mismatch with boot-time reference, enclave creation denied\n");
        return -1;
    }

    printk("[NS] EnclaveInfo validated against boot-time reference\n");
    return 0;
}

int validate_enclave_info_before_inference(void)
{
    return validate_boot_enclave_info_before_create();
}

int initialize_secure_enclave_info_boot(void)
{
    if (boot_enclave_info_seeded_once) {
        return 0;
    }

    if (ensure_model_ro_registered() != 0) {
        return -1;
    }
    if (ensure_inference_code_registered() != 0) {
        return -1;
    }
    if (seed_late_secret_hash_secure() != 0) {
        return -1;
    }

    uint8_t enclave_info[32] = {0};
    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        return -1;
    }
    /* NS-side API call: DP_CMD_COMPUTE_ENCLAVE_INFO. */
    uint32_t cmd = DP_CMD_COMPUTE_ENCLAVE_INFO;
    psa_invec in_v = { &cmd, sizeof(cmd) };
    psa_outvec out_v = { enclave_info, sizeof(enclave_info) };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, &in_v, 1, &out_v, 1);
    psa_close(h);
    if (st != PSA_SUCCESS) {
        return -1;
    }

    memcpy(boot_enclave_info_cache, enclave_info, sizeof(boot_enclave_info_cache));
    boot_enclave_info_seeded_once = true;
    printk("[NS] Secure boot EnclaveInfo initialized\n");
    return 0;
}

static int create_enclave_secure_into_ns(size_t decrypt_size_bytes)
{
    /* NS-side API call: DP_CMD_CREATE_ENCLAVE. */
    BENCHMARK_START(decrypt);
    
    uint8_t *out_buf = enclave_region_base;
    size_t out_size = enclave_region_size;
    size_t send_size = decrypt_size_bytes;

    if (send_size > (size_t)late_wt_encrypted_len) {
        send_size = (size_t)late_wt_encrypted_len;
    }

    printk("[NS] Requesting late weights decryption...\n");
    printk("[NS] → Encrypted late weights ptr=%p, len=%u\n",
           (void*)late_wt_encrypted, (unsigned)send_size);
    printk("[NS] → Output buffer ptr=%p, size=%zu\n", (void*)out_buf, out_size);

    if (send_size == 0U || send_size > out_size) {
        printk("[NS] ✗ Late weights buffer too small\n");
        return -1;
    }

    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (late weights), handle=%d\n", (int)handle);
        last_create_secure_status = (int32_t)handle;
        return -1;
    }

    uint32_t cmd = DP_CMD_CREATE_ENCLAVE;
    uint8_t iv_hsid_and_region[56] = {0};
    memcpy(iv_hsid_and_region, late_wt_iv, sizeof(late_wt_iv));
    memcpy(iv_hsid_and_region + sizeof(late_wt_iv), boot_enclave_info_cache, sizeof(boot_enclave_info_cache));
    uint32_t *region_params = (uint32_t *)(void *)(iv_hsid_and_region + 48U);
    region_params[0] = (uint32_t)(uintptr_t)out_buf;
    region_params[1] = (uint32_t)out_size;

    psa_invec in_vec[3] = {
        { &cmd, sizeof(cmd) },
        { late_wt_encrypted, send_size },
        { iv_hsid_and_region, sizeof(iv_hsid_and_region) }
    };

    psa_outvec out_vec = {
        out_buf,
        out_size
    };

    psa_status_t status = psa_call(handle,
                                   PSA_IPC_CALL,
                                   in_vec, 3,
                                   &out_vec, 1);

    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Secure Create_Enclave failed, status=%d\n", status);
        last_create_secure_status = (int32_t)status;
        return -1;
    }

    last_create_secure_status = 0;

    BENCHMARK_END(decrypt, g_benchmark_metrics.aes_decrypt_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.aes_decrypt_cycles,
                         g_benchmark_metrics.aes_decrypt_sum_cycles,
                         g_benchmark_metrics.aes_decrypt_min_cycles,
                         g_benchmark_metrics.aes_decrypt_max_cycles,
                         g_benchmark_metrics.aes_decrypt_count);
    printk("[NS] ✓ Secure Create_Enclave completed (%u cycles, %u ms)\n",
           g_benchmark_metrics.aes_decrypt_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.aes_decrypt_cycles));
    return 0;
}

static int finalize_create_enclave_secure(void)
{
    /* NS-side API call: DP_CMD_FINALIZE_CREATE_ENCLAVE. */
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (finalize create), handle=%d\n", (int)handle);
        last_create_secure_status = (int32_t)handle;
        return -1;
    }

    uint32_t cmd = DP_CMD_FINALIZE_CREATE_ENCLAVE;
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, NULL, 0);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Secure finalize create failed, status=%d\n", (int)status);
        last_create_secure_status = (int32_t)status;
        return -1;
    }

    return 0;
}

/* ============================================================
 *                 ENCLAVE CREATION
 * ============================================================ */

int create_enclave_with_size(size_t decrypt_size_bytes)
{
    BENCHMARK_START(create_enc);

    const size_t requested_decrypt_size = resolve_requested_decrypt_size(decrypt_size_bytes);
    const size_t aligned_decrypt_size = align_up_32(requested_decrypt_size);
    const size_t full_late_size = (size_t)LATE_WT_TOTAL_SIZE;
    
    if (enclave_created) {
        printk("[NS] Enclave already created\n");
        last_create_secure_status = 1;
        return -1;
    }

    if (validate_boot_enclave_info_before_create() != 0) {
        printk("[NS] ✗ EnclaveInfo pre-create validation failed\n");
        last_create_secure_status = -3;
        return -1;
    }

        printk("\n--- CREATE ENCLAVE ---\n");
        enclave_region_base = enclave_memory;
        enclave_region_size = aligned_decrypt_size;
        printk("[NS] Enclave region reserved: base=%p size=%zu\n",
            (void*)enclave_region_base, enclave_region_size);
        if (requested_decrypt_size != full_late_size) {
            printk("[NS] Benchmark mode: decrypting %zu bytes (full blob=%zu bytes)\n",
                   requested_decrypt_size, full_late_size);
        }

    printk("[NS] Configuration:\n");
        printk("      Enclave memory size: %zu bytes\n", enclave_region_size);
        printk("      Enclave memory addr: %p\n", (void*)enclave_region_base);
    printk("      Stack size: %d bytes\n", ENCLAVE_STACK_SIZE);
    
    printk("[NS] Initializing enclave memory...\n");
        memset(enclave_region_base, 0, enclave_region_size);
    printk("[NS] \u2713 Memory cleared\n");

    if (create_enclave_secure_into_ns(requested_decrypt_size) != 0) {
        printk("[NS] \u2717 Secure Create_Enclave failed\n");
        return -1;
    }

    /* Bind freshly decrypted late weights to split-inference pipeline.
     * RAM remains open until finalize step so we can compute hash now. */
    set_late_weights_buffer(enclave_region_base, enclave_region_size);

    if (requested_decrypt_size == full_late_size) {
        if (precompute_late_weights_hash() != 0) {
            printk("[NS] ✗ Late-weights hash precompute failed during create\n");
            (void)finalize_create_enclave_secure();
            last_create_secure_status = -2;
            return -1;
        }
    } else {
        printk("[NS] Skipping late-weights hash precompute for partial decrypt benchmark\n");
    }

    if (finalize_create_enclave_secure() != 0) {
        printk("[NS] ✗ Finalize create failed (RAM close)\n");
        return -1;
    }

    /* Get max inferences policy from secure side */
    printk("[NS] Requesting max inferences policy from secure...\n");
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (max inferences), handle=%d\n", (int)handle);
        last_create_secure_status = (int32_t)handle;
        return -1;
    }

    uint32_t cmd = 4; /* DP_CMD_GET_MAX_INFERENCES */
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_outvec out_vec = { &max_inferences_per_enclave, sizeof(max_inferences_per_enclave) };

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Failed to get max inferences, status=%d\n", status);
        last_create_secure_status = (int32_t)status;
        return -1;
    }
    printk("[NS] ✓ Max inferences per enclave: %u\n", max_inferences_per_enclave);

    enclave_created = true;
    last_create_secure_status = 0;
    g_benchmark_metrics.enclave_recreations++;

    BENCHMARK_END(create_enc, g_benchmark_metrics.enclave_create_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.enclave_create_cycles,
                         g_benchmark_metrics.enclave_create_sum_cycles,
                         g_benchmark_metrics.enclave_create_min_cycles,
                         g_benchmark_metrics.enclave_create_max_cycles,
                         g_benchmark_metrics.enclave_create_count);
    printk("[NS] ✓ Enclave creation complete (%u cycles, %u ms)\n",
           g_benchmark_metrics.enclave_create_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.enclave_create_cycles));
    printk("--- END CREATE ENCLAVE ---\n\n");
    return 0;
}

int create_enclave(void)
{
    return create_enclave_with_size(0U);
}
/* ============================================================
 *                 PUBLIC ACCESSORS
 * ============================================================ */

uint8_t* get_enclave_region(void)
{
    return enclave_region_base;
}

size_t get_enclave_region_size(void)
{
    return enclave_region_size;
}

uint32_t get_max_inferences_per_enclave(void)
{
    return max_inferences_per_enclave;
}

size_t get_model_ro_size(void)
{
    return (size_t)(__model_ro_end - __model_ro_start);
}

size_t get_inference_code_size(void)
{
    return (size_t)(__inference_end - __inference_start);
}

bool is_enclave_created(void)
{
    return enclave_created;
}
/* ============================================================
 *                 THREAD ENTRY (INFERENCE)
 * ============================================================ */

static void enclave_thread_entry(void *, void *, void *)
{
    printk("[NS] Enclave running on dedicated stack\n");
    if (!enclave_created) {
        printk("[NS] Enclave not created\n");
        return;
    }

    run_enclave();
}

int enter_enclave(void)
{
    if (!enclave_created) {
        printk("[NS] Enclave not created\n");
        return -1;
    }

    printk("[NS] Starting enclave thread...\n");

    k_tid_t tid = k_thread_create(&enclave_thread,
                                  enclave_stack,
                                  ENCLAVE_STACK_SIZE,
                                  enclave_thread_entry,
                                  NULL, NULL, NULL,
                                  ENCLAVE_THREAD_PRIORITY,
                                  0,
                                  K_NO_WAIT);

    printk("Thread pointer: %p\n", tid);

    k_thread_join(tid, K_FOREVER);

    printk("[NS] Enclave thread finished\n");

    return 0;
}

/* ============================================================
 *                 DESTROY ENCLAVE
 * ============================================================ */

int destroy_enclave(void)
{
    BENCHMARK_START(destroy_enc);
    
    if (!enclave_created) {
        printk("[NS] No enclave to destroy\n");
        return -1;
    }

    printk("[NS] Destroying enclave...\n");

    /* NS-side API call: DP_CMD_DESTROY_ENCLAVE (Shangri-La Destroy API)
     *
     * Secure-side execution:
     *  1. Erase all sensitive data in data_priv (zeroize)
     *  2. Mark F, data_pub, data_priv as Non-Secure (release SAU windows)
     *  3. Set lifecycle state to Non-Exist
     *
     * Normal-side responsibility:
     *  - Clear enclave_created flag
     *  - Zeroize Normal World copy of SAU window (enclave_region_base)
     *  - Set max_inferences_per_enclave to 0 (quota released)
     */
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (destroy), handle=%d\n", (int)handle);
        return -1;
    }
    uint32_t cmd = DP_CMD_DESTROY_ENCLAVE;
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, NULL, 0);
    psa_close(handle);
    if (status != PSA_SUCCESS) {
        printk("[NS] Secure destroy failed, status=%d\n", status);
        return -1;
    }

    memset(enclave_region_base, 0, enclave_region_size);

    enclave_created = false;
    max_inferences_per_enclave = 0;

    BENCHMARK_END(destroy_enc, g_benchmark_metrics.enclave_destroy_cycles);
    BENCHMARK_ACCUMULATE(g_benchmark_metrics.enclave_destroy_cycles,
                         g_benchmark_metrics.enclave_destroy_sum_cycles,
                         g_benchmark_metrics.enclave_destroy_min_cycles,
                         g_benchmark_metrics.enclave_destroy_max_cycles,
                         g_benchmark_metrics.enclave_destroy_count);
    printk("[NS] ✓ Enclave destroyed (memory zeroed, counters reset, %u cycles, %u ms)\n",
           g_benchmark_metrics.enclave_destroy_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.enclave_destroy_cycles));
    return 0;
}

int update_rate_limit(uint32_t new_limit)
{
    return set_max_inferences(new_limit);
}

int32_t get_last_create_secure_status(void)
{
    return last_create_secure_status;
}