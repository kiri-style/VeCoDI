#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
//#include <zephyr/app_memory/app_memdomain.h>
#include <zephyr/app_memory/mem_domain.h>


#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"
//#include "tensorflow/lite/version.h"

#include "model_data.h"
#include "test_images.h"

#include "ns_irq.h"


/* ================= TOKEN ================== */
#include <psa/client.h>
#include <stdint.h>

#include <cmsis_core.h>
#include "mpu_model.h"
#include "mpu_inference.h"


/* ================= K_mem_inference ================= */
extern "C" {
    void mpu_inference_init(void);
    extern struct k_mem_domain inference_domain;
}

/* ===== Model linker symbols (NS only) ===== */
extern uint32_t __model_ro_start;
extern uint32_t __model_ro_end;

/* Copie locale des IDs (contrat ABI) */
#define TFM_DP_SECRET_DIGEST_SID     0xFFFFF001
#define TFM_DP_SECRET_DIGEST_VERSION 1

/* ===== PSA dummy commands (MUST match Secure side) ===== */
#define CMD_OPEN_ACCESS   0x01
#define CMD_CLOSE_ACCESS  0x02
#define CMD_VERIFY_TOKEN 0x03
#define CMD_OPEN_MODEL_ACCESS     0x10
#define CMD_CLOSE_MODEL_ACCESS    0x11
#define CMD_RUN_INFERENCE 0x20
#define CMD_OPEN_INFERENCE_ACCESS   0x30
#define CMD_CLOSE_INFERENCE_ACCESS  0x31

/* ===== Model region descriptor ===== */
struct model_region_desc {
    uint32_t start;
    uint32_t size;
};
/* ===== Inference (tensor arena) region descriptor ===== */
struct inference_region_desc {
    uint32_t start;
    uint32_t size;
};
/* ================= CONFIG ================= */
#define TENSOR_ARENA_SIZE (70 * 1024)
#define INPUT_H 32
#define INPUT_W 32
#define INPUT_C 3
#define NUM_CLASSES 10

/* ================= GLOBALS ================= */
/* Nom de l'app domain */
/*K_APPMEM_PARTITION_DEFINE(tflm_partition);

K_APP_BMEM(tflm_partition)
__aligned(32)
uint8_t tensor_arena[TENSOR_ARENA_SIZE];

struct k_mem_domain tflm_domain;*/
alignas(32) static uint8_t tensor_arena[TENSOR_ARENA_SIZE];

//__attribute__((section(".user_ram"), aligned(32)))
//uint8_t tensor_arena[TENSOR_ARENA_SIZE];

static tflite::MicroInterpreter* interpreter;
static TfLiteTensor* input;
static TfLiteTensor* output;

/* ================= INIT ================= */
/*static void tflm_init(void)
{
    printk("[TFLM] Init\n");

    const tflite::Model* model =
        tflite::GetModel(cifar_resnet_int8_tflite);

    if (model->version() != TFLITE_SCHEMA_VERSION) {
        printk("Schema mismatch\n");
        return;
    }

    static tflite::MicroMutableOpResolver<20> resolver;
    resolver.AddConv2D();
    resolver.AddDepthwiseConv2D();
    resolver.AddFullyConnected();
    resolver.AddAveragePool2D();
    resolver.AddMaxPool2D();
    resolver.AddReshape();
    resolver.AddSoftmax();
    resolver.AddAdd();
    resolver.AddMul();

    static tflite::MicroInterpreter static_interpreter(
        model,
        resolver,
        tensor_arena,
        TENSOR_ARENA_SIZE
    );

    interpreter = &static_interpreter;

    if (interpreter->AllocateTensors() != kTfLiteOk) {
        printk("AllocateTensors FAILED\n");
        interpreter = NULL;
        return;
    }

    input  = interpreter->input(0);
    output = interpreter->output(0);

    printk("[TFLM] Ready\n");
}*/





/* ================= LOAD IMAGE ================= */
/*static void load_cifar_image(const uint8_t* img)
{
    int size = INPUT_H * INPUT_W * INPUT_C;

    /* uint8 [0,255] -> int8 [-128,127] */
    /*for (int i = 0; i < size; i++) {
        input->data.int8[i] = (int8_t)((int)img[i] - 128);
    }
}*/

/* ================= ARGMAX ================= */
/*static int get_prediction(void)
{
    int best = 0;
    int8_t max = output->data.int8[0];

    for (int i = 1; i < NUM_CLASSES; i++) {
        int8_t v = output->data.int8[i];
        if (v > max) {
            max = v;
            best = i;
        }
    }
    return best;
}*/
/*================= inference ==========*/
//static void run_cifar_inference(void)
/*extern "C" void run_cifar_inference(void)
{
    printk("[USER] Starting inference\n");

    tflm_init();
    if (!interpreter) {
        printk("Interpreter init failed\n");
        return;
    }

    printk("\n[Test 0] Expected label = %d\n", label_0);
    load_cifar_image(img_0);

    if (interpreter->Invoke() == kTfLiteOk) {
        printk("Prediction = %d\n", get_prediction());
    } else {
        printk("Invoke failed\n");
    }

    k_sleep(K_SECONDS(2));

    printk("\n[Test 1] Expected label = %d\n", label_1);
    load_cifar_image(img_1);

    if (interpreter->Invoke() == kTfLiteOk) {
        printk("Prediction = %d\n", get_prediction());
    } else {
        printk("Invoke failed\n");
    }
}*/

/* ================ user =======*/
/*void inference_thread(void *, void *, void *)
{
    printk("[DBG] In user mode = %d\n", k_is_user_context());
    run_cifar_inference();
}*/

/* ===== USER inference thread ===== */
K_THREAD_STACK_DEFINE(inf_stack, 4096);
struct k_thread inf_thread;

/* Flag simple de synchro */
volatile bool model_access_closed = false;



/* ================= inference isr ================= */

/* ================= MPU INFERENCE ================= */

/* ================= MAIN ================= */
int main(void)
{
    printk("\n================= NS MAIN START =================\n");
    printk("[DBG] NS booted | user mode = %d\n", k_is_user_context());

    psa_handle_t handle;
    psa_status_t status;

    /* =====================================================
     * IRQ INIT
     * ===================================================== */
    printk("\n[STEP] ns_irq_init()\n");
    ns_irq_init();
    printk("[DBG] After IRQ init | user mode = %d\n", k_is_user_context());

    /* =====================================================
     * MPU INIT (MODEL)
     * ===================================================== */
    printk("\n[STEP] mpu_model_init()\n");
    mpu_model_init();
    printk("[MPU] Model MPU init done\n");
    printk("[DBG] After MPU model | user mode = %d\n", k_is_user_context());

    /* =====================================================
     * MPU INIT (INFERENCE / TENSOR ARENA)
     * ===================================================== */
    printk("\n[STEP] mpu_inference_init()\n");
    mpu_inference_init();

    uintptr_t inf_start = mpu_inference_get_start();
    size_t    inf_size  = mpu_inference_get_size();

    printk("[MPU] Tensor arena start : 0x%08lx\n", (unsigned long)inf_start);
    printk("[MPU] Tensor arena size  : %u bytes\n", (unsigned int)inf_size);

    /* =====================================================
     * TEST 1 : BAD TOKEN
     * ===================================================== */
    printk("\n========== TEST 1 : BAD TOKEN ==========\n");

    uint32_t bad_token = 0xDEADBEEF;
    psa_invec bad_vec[] = {
        { .base = &bad_token, .len = sizeof(bad_token) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);
    printk("[DBG] psa_connect = %d\n", handle);

    if (handle > 0) {
        status = psa_call(handle, PSA_IPC_CALL, bad_vec, 1, NULL, 0);
        printk("[BAD TOKEN] status = %d\n", status);
        psa_close(handle);
    }

    /* =====================================================
     * TEST 2 : REQUEST VALID TOKEN
     * ===================================================== */
    printk("\n========== TEST 2 : REQUEST TOKEN ==========\n");

    uint32_t token = 0;
    psa_outvec out_vec = {
        .base = &token,
        .len  = sizeof(token)
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    if (handle <= 0) {
        printk("[ERR] psa_connect failed (token)\n");
        return 0;
    }

    status = psa_call(handle, PSA_IPC_CALL, NULL, 0, &out_vec, 1);
    psa_close(handle);

    printk("[NS] Token received = 0x%08X\n", token);

    if (token != 0xA5A5A5A5) {
        printk("[SEC] Invalid token → STOP\n");
        return 0;
    }

    printk("[SEC] Token VALID\n");

    /* =====================================================
     * OPEN MODEL ACCESS (FLASH)
     * ===================================================== */
    printk("\n========== OPEN MODEL ACCESS ==========\n");

    extern uint32_t __model_ro_start;
    extern uint32_t __model_ro_end;

    struct model_region_desc model_desc = {
        .start = (uint32_t)&__model_ro_start,
        .size  = (uint32_t)&__model_ro_end -
                 (uint32_t)&__model_ro_start
    };

    printk("[MODEL] start=0x%08X size=%u\n",
           model_desc.start, model_desc.size);

    uint32_t cmd_open_model = CMD_OPEN_MODEL_ACCESS;

    psa_invec model_open_vec[] = {
        { .base = &cmd_open_model, .len = sizeof(cmd_open_model) },
        { .base = &model_desc,     .len = sizeof(model_desc) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    status = psa_call(handle, PSA_IPC_CALL,
                      model_open_vec, 2, NULL, 0);
    psa_close(handle);

    printk("[MODEL] OPEN status = %d\n", status);

    if (status != PSA_SUCCESS) {
        printk("[ERR] Model open failed\n");
        return 0;
    }

    /* =====================================================
     * OPEN INFERENCE ACCESS (SRAM)
     * ===================================================== */
    printk("\n========== OPEN INFERENCE ACCESS ==========\n");

    struct inference_region_desc inf_desc = {
        .start = (uint32_t)inf_start,
        .size  = (uint32_t)inf_size
    };

    printk("[INF] start=0x%08X size=%u\n",
           inf_desc.start, inf_desc.size);

    uint32_t cmd_open_inf = CMD_OPEN_INFERENCE_ACCESS;

    psa_invec inf_open_vec[] = {
        { .base = &cmd_open_inf, .len = sizeof(cmd_open_inf) },
        { .base = &inf_desc,     .len = sizeof(inf_desc) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    status = psa_call(handle, PSA_IPC_CALL,
                      inf_open_vec, 2, NULL, 0);
    psa_close(handle);

    printk("[INF] OPEN status = %d\n", status);

    if (status != PSA_SUCCESS) {
        printk("[ERR] Inference open failed\n");
        return 0;
    }

    /* =====================================================
     * RUN INFERENCE (SECURE TRIGGER)
     * ===================================================== */
    printk("\n========== RUN INFERENCE ==========\n");

    uint32_t cmd_run = CMD_RUN_INFERENCE;
    psa_invec run_vec[] = {
        { .base = &cmd_run, .len = sizeof(cmd_run) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    status = psa_call(handle, PSA_IPC_CALL, run_vec, 1, NULL, 0);
    psa_close(handle);

    printk("[RUN] CMD_RUN_INFERENCE status = %d\n", status);

    /* =====================================================
     * CLOSE INFERENCE ACCESS
     * ===================================================== */
    printk("\n========== CLOSE INFERENCE ACCESS ==========\n");

    uint32_t cmd_close_inf = CMD_CLOSE_INFERENCE_ACCESS;

    psa_invec inf_close_vec[] = {
        { .base = &cmd_close_inf, .len = sizeof(cmd_close_inf) },
        { .base = &inf_desc,      .len = sizeof(inf_desc) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    status = psa_call(handle, PSA_IPC_CALL,
                      inf_close_vec, 2, NULL, 0);
    psa_close(handle);

    printk("[INF] CLOSE status = %d\n", status);

    /* =====================================================
     * CLOSE MODEL ACCESS
     * ===================================================== */
    printk("\n========== CLOSE MODEL ACCESS ==========\n");

    uint32_t cmd_close_model = CMD_CLOSE_MODEL_ACCESS;

    psa_invec model_close_vec[] = {
        { .base = &cmd_close_model, .len = sizeof(cmd_close_model) },
        { .base = &model_desc,      .len = sizeof(model_desc) }
    };

    handle = psa_connect(TFM_DP_SECRET_DIGEST_SID,
                         TFM_DP_SECRET_DIGEST_VERSION);

    status = psa_call(handle, PSA_IPC_CALL,
                      model_close_vec, 2, NULL, 0);
    psa_close(handle);

    printk("[MODEL] CLOSE status = %d\n", status);

    printk("\n[MAIN] Secure inference lifecycle COMPLETE\n");
    printk("[MAIN] Any access now SHOULD FAULT\n");

    while (1) {
        k_sleep(K_FOREVER);
    }
}