/* ================= MODEL (FLASH, RO) ================= */
.model_ro :
{
    . = ALIGN(32);
    __model_ro_start = .;
    KEEP(*(.model_ro*))
    KEEP(*(.rodata.model_ro*))
    /* C++ mangled symbols from split_inference.cpp (early ROM weights/biases). */
    KEEP(*(.rodata._ZL9wt_conv2d))
    KEEP(*(.rodata._ZL11wt_conv2d_*))
    KEEP(*(.rodata._ZL11bias_conv2d))
    KEEP(*(.rodata._ZL13bias_conv2d_*))
    . = ALIGN(32);
    __model_ro_end = .;

    ASSERT(__model_ro_end - __model_ro_start < 0x20000,
           "ERROR: MODEL_RO section too large (flash overflow risk)");
} > FLASH


/* Section pour le code d’inférence (hashé dans EnclaveInfo) */
.inference_ro : ALIGN(32) {
    __inference_start = .;
    KEEP(*(.inference_ro*))
    . = ALIGN(32);
    __inference_end = .;
} > FLASH