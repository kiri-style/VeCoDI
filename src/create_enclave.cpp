#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <cstring>
#include <psa/client.h>

#include "create_enclave.h"
#include "run_enclave.h"
#include "benchmark.h"
#include "../split_inference/late/L_nn_wt_encrypted.h"

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
#define DP_CMD_DECRYPT_LATE_WEIGHTS 3
#define DP_CMD_SAU_REGISTER    14U  /* Register enclave RAM window with Secure */
#define DP_CMD_SAU_CONTROL     15U  /* SAU cmd: 1=CLOSE, 2=OPEN */

/* ============================================================
 *                 GLOBALS
 * ============================================================ */

static bool enclave_created = false;
static uint32_t max_inferences_per_enclave = 0;

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

/* Tell the Secure partition where enclave RAM window lives so it can
 * configure SAU regions.  Can be called by enclave setup and SAU tests. */
int enclave_sau_register_window(const uint8_t *base, uint32_t size)
{
    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) {
        printk("[NS SAU] psa_connect failed for REGISTER\n");
        return -1;
    }
    uint32_t cmd = DP_CMD_SAU_REGISTER;
    uint32_t params[2] = { (uint32_t)(uintptr_t)base, size };
    psa_invec  in_v[2] = { {&cmd, sizeof(cmd)}, {params, sizeof(params)} };
    uint8_t    resp    = 0U;
    psa_outvec out_v   = { &resp, 1U };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, &out_v, 1);
    psa_close(h);
    if (st != PSA_SUCCESS) {
        printk("[NS SAU] REGISTER failed: %d\n", (int)st);
        return -1;
    }
    printk("[NS SAU] Enclave registered: base=%p size=%u resp=0x%02X\n",
           (void *)base, size, resp);
    return 0;
}

/* Public helpers called by run_enclave.cpp and sau_test.cpp. */
int enclave_sau_open(void)
{
    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) { printk("[NS SAU] psa_connect failed for OPEN\n"); return -1; }
    uint32_t cmd  = DP_CMD_SAU_CONTROL;
    uint8_t  ctrl = 2U;  /* OPEN */
    psa_invec  in_v[2] = { {&cmd, sizeof(cmd)}, {&ctrl, 1U} };
    uint8_t    resp    = 0U;
    psa_outvec out_v   = { &resp, 1U };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, &out_v, 1);
    psa_close(h);
    if (st != PSA_SUCCESS) {
        printk("[NS SAU] OPEN failed: %d\n", (int)st);
        return -1;
    }
    printk("[NS SAU] stage open: status=0, byte=0x%02x\n", resp);
    return 0;
}

int enclave_sau_close(void)
{
    psa_handle_t h = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (h <= 0) { printk("[NS SAU] psa_connect failed for CLOSE\n"); return -1; }
    uint32_t cmd  = DP_CMD_SAU_CONTROL;
    uint8_t  ctrl = 1U;  /* CLOSE */
    psa_invec  in_v[2] = { {&cmd, sizeof(cmd)}, {&ctrl, 1U} };
    uint8_t    resp    = 0U;
    psa_outvec out_v   = { &resp, 1U };
    psa_status_t st = psa_call(h, PSA_IPC_CALL, in_v, 2, &out_v, 1);
    psa_close(h);
    if (st != PSA_SUCCESS) {
        printk("[NS SAU] CLOSE failed: %d\n", (int)st);
        return -1;
    }
    printk("[NS SAU] stage close: status=0, byte=0x%02x\n", resp);
    return 0;
}



static int decrypt_late_weights_into_ns(void)
{
    BENCHMARK_START(decrypt);
    
    uint8_t *out_buf = enclave_region_base;
    size_t out_size = enclave_region_size;

    printk("[NS] Requesting late weights decryption...\n");
    printk("[NS] → Encrypted late weights ptr=%p, len=%u\n",
           (void*)late_wt_encrypted, (unsigned)late_wt_encrypted_len);
    printk("[NS] → Output buffer ptr=%p, size=%zu\n", (void*)out_buf, out_size);

    if (late_wt_encrypted_len > out_size) {
        printk("[NS] ✗ Late weights buffer too small\n");
        return -1;
    }

    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (late weights), handle=%d\n", (int)handle);
        return -1;
    }

    uint32_t cmd = DP_CMD_DECRYPT_LATE_WEIGHTS;
    psa_invec in_vec[3] = {
        { &cmd, sizeof(cmd) },
        { late_wt_encrypted, late_wt_encrypted_len },
        { late_wt_iv, sizeof(late_wt_iv) }
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
        printk("[NS] Secure decrypt failed (late weights), status=%d\n", status);
        return -1;
    }

    BENCHMARK_END(decrypt, g_benchmark_metrics.aes_decrypt_cycles);
    printk("[NS] ✓ Late weights decrypted into NS RAM (%u cycles, %u ms)\n",
           g_benchmark_metrics.aes_decrypt_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.aes_decrypt_cycles));
    return 0;
}

/* ============================================================
 *                 ENCLAVE CREATION
 * ============================================================ */

int create_enclave(void)
{
    BENCHMARK_START(create_enc);
    
    if (enclave_created) {
        printk("[NS] Enclave already created\n");
        return -1;
    }

        printk("\n--- CREATE ENCLAVE ---\n");
        enclave_region_base = enclave_memory;
        enclave_region_size = ENCLAVE_MEMORY_SIZE;
        printk("[NS] Enclave region reserved: base=%p size=%zu\n",
            (void*)enclave_region_base, enclave_region_size);

    /* Register enclave RAM window with Secure partition so SAU can protect it. */
    printk("[NS] Registering enclave window with Secure (SAU)...\n");
    if (enclave_sau_register_window(enclave_region_base,
                            (uint32_t)enclave_region_size) != 0) {
        printk("[NS] WARNING: SAU register failed, isolation disabled\n");
    }

    printk("[NS] Configuration:\n");
        printk("      Enclave memory size: %zu bytes\n", enclave_region_size);
        printk("      Enclave memory addr: %p\n", (void*)enclave_region_base);
    printk("      Stack size: %d bytes\n", ENCLAVE_STACK_SIZE);
    
    printk("[NS] Initializing enclave memory...\n");
        memset(enclave_region_base, 0, enclave_region_size);
    printk("[NS] \u2713 Memory cleared\n");

    if (decrypt_late_weights_into_ns() != 0) {
        printk("[NS] \u2717 Late weights decrypt failed\n");
        return -1;
    }

    /* Enclave decryption complete: close the SAU window.
     * The window will re-open only during inference. */
    printk("[NS] Closing SAU enclave window (weights now Secure)...\n");
    enclave_sau_close();

    /* Get max inferences policy from secure side */
    printk("[NS] Requesting max inferences policy from secure...\n");
    psa_handle_t handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (max inferences), handle=%d\n", (int)handle);
        return -1;
    }

    uint32_t cmd = 4; /* DP_CMD_GET_MAX_INFERENCES */
    psa_invec in_vec = { &cmd, sizeof(cmd) };
    psa_outvec out_vec = { &max_inferences_per_enclave, sizeof(max_inferences_per_enclave) };

    psa_status_t status = psa_call(handle, PSA_IPC_CALL, &in_vec, 1, &out_vec, 1);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Failed to get max inferences, status=%d\n", status);
        return -1;
    }
    printk("[NS] ✓ Max inferences per enclave: %u\n", max_inferences_per_enclave);

    /* Reset inference counter in Secure side */
    printk("[NS] Resetting Secure inference counter...\n");
    handle = psa_connect(ENCLAVE_SID, ENCLAVE_VER);
    if (handle <= 0) {
        printk("[NS] psa_connect failed (reset counter), handle=%d\n", (int)handle);
        return -1;
    }

    cmd = 7; /* DP_CMD_RESET_COUNTER */
    psa_invec reset_vec = { &cmd, sizeof(cmd) };
    status = psa_call(handle, PSA_IPC_CALL, &reset_vec, 1, NULL, 0);
    psa_close(handle);

    if (status != PSA_SUCCESS) {
        printk("[NS] Failed to reset Secure counter, status=%d\n", status);
        return -1;
    }
    printk("[NS] ✓ Secure inference counter reset to 0\n");

    enclave_created = true;

    BENCHMARK_END(create_enc, g_benchmark_metrics.enclave_create_cycles);
    printk("[NS] ✓ Enclave creation complete (%u cycles, %u ms)\n",
           g_benchmark_metrics.enclave_create_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.enclave_create_cycles));
    printk("--- END CREATE ENCLAVE ---\n\n");
    return 0;
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

    /* Open SAU window temporarily so NS can zero sensitive model memory. */
    enclave_sau_open();

    /* Zeroize sensitive model memory */
    memset(enclave_region_base, 0, enclave_region_size);

    /* Re-close: weights are gone but keep window Secure as a clean state. */
    enclave_sau_close();

    enclave_created = false;
    max_inferences_per_enclave = 0;

    BENCHMARK_END(destroy_enc, g_benchmark_metrics.enclave_destroy_cycles);
    printk("[NS] ✓ Enclave destroyed (memory zeroed, counters reset, %u cycles, %u ms)\n",
           g_benchmark_metrics.enclave_destroy_cycles,
           benchmark_cycles_to_ms(g_benchmark_metrics.enclave_destroy_cycles));
    return 0;
}