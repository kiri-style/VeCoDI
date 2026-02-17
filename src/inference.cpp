#include "inference.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/micro/micro_mutable_op_resolver.h"
#include "tensorflow/lite/schema/schema_generated.h"

#include "cifar_resnet_lite_int8_data.h"  // New lightweight model
#include "create_enclave.h"  // Pour accéder à enclave_memory
#include "test_images.h"


// Placer tout le code dans une section spéciale pour contrôle MPU
//__attribute__((section(".inference_ro"), aligned(32), used))

/* ================= CONFIG ================= */
#define TENSOR_ARENA_SIZE (56 * 1024)
#define INPUT_H 32
#define INPUT_W 32
#define INPUT_C 3
#define NUM_CLASSES 10

/* ================= GLOBALS (file-local) ================= */
alignas(32) static uint8_t tensor_arena[TENSOR_ARENA_SIZE];
static tflite::MicroInterpreter* interpreter = nullptr;
static TfLiteTensor* input = nullptr;
static TfLiteTensor* output = nullptr;

/* ================= PRIVATE FUNCTIONS ================= */
static void tflm_init(void)
{
    printk("\n--- TFLM INITIALIZATION ---\n");
    printk("[INF] Loading model from RAM enclave...\n");

    /* Access model from RAM enclave (copied during create_enclave) */
    extern uint8_t* get_enclave_memory(void);
    const uint8_t* model_ram = get_enclave_memory();
    
    printk("[INF] Model address (RAM): %p\n", (void*)model_ram);
    printk("[INF] Tensor arena: %u bytes at %p\n", (unsigned)TENSOR_ARENA_SIZE,
            (void*)tensor_arena);
    
    const tflite::Model* model = tflite::GetModel(model_ram);
    printk("[INF] ✓ Model loaded from RAM enclave\n");

    if (model->version() != TFLITE_SCHEMA_VERSION) {
        printk("[INF] \u2717 Schema mismatch (got %d, expected %d)\n",
               model->version(), TFLITE_SCHEMA_VERSION);
        interpreter = nullptr;
        return;
    }
    printk("[INF] \u2713 Schema version OK (%d)\n", TFLITE_SCHEMA_VERSION);

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
    resolver.AddMean();  // For GlobalAveragePooling2D in lite model
    resolver.AddQuantize();
    resolver.AddDequantize();

    static tflite::MicroInterpreter static_interpreter(
        model,
        resolver,
        tensor_arena,
        TENSOR_ARENA_SIZE
    );

    interpreter = &static_interpreter;

    if (interpreter->AllocateTensors() != kTfLiteOk) {
        printk("[INF] AllocateTensors FAILED\n");
        interpreter = nullptr;
        return;
    }

    input  = interpreter->input(0);
    output = interpreter->output(0);

    printk("[INF] TFLM ready\n");
}

static void load_cifar_image(const uint8_t* img)
{
    int size = INPUT_H * INPUT_W * INPUT_C;

    for (int i = 0; i < size; i++) {
        input->data.int8[i] = (int8_t)((int)img[i] - 128);
    }
}

static int get_prediction(void)
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
}

/* =========================================================
 *  PUBLIC ENTRY POINT
 * ========================================================= */
extern "C" void run_cifar_inference(void)
{
    printk("\n[INF] ===== INFERENCE START =====\n");
    printk("[INF] user mode = %d\n", k_is_user_context());

    if (!interpreter) {
        printk("[INF] Interpreter not ready, initializing...\n");
        tflm_init();
        if (!interpreter) {
            printk("[INF] Interpreter init failed\n");
            return;
        }
    } else {
        printk("[INF] Interpreter already initialized\n");
    }

    for (int test_id = 0; test_id < 2; test_id++) {
        const uint8_t* img = (test_id == 0) ? img_0 : img_1;
        int expected_label = (test_id == 0) ? label_0 : label_1;

        printk("[INF] Test %d | expected = %d\n", test_id, expected_label);
        load_cifar_image(img);
        
        printk("[INF] Image loaded into input tensor\n");

        TfLiteStatus status = interpreter->Invoke();
        printk("[INF] Invoke returned status = %d\n", status);

        if (status == kTfLiteOk) {
            int pred = get_prediction();
            printk("[INF] Prediction = %d\n", pred);
        } else {
            printk("[INF] Invoke FAILED\n");
        }

        k_sleep(K_MSEC(500));
    }
    /* Zeroize sensitive memory */
    for (int i = 0; i < TENSOR_ARENA_SIZE; i++) {
        tensor_arena[i] = 0;
    }
    printk("[INF] ===== INFERENCE END =====\n\n");
}