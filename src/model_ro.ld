/* ================= MODEL (FLASH, RO) ================= */
.model_ro :
{
    . = ALIGN(32);
    __model_ro_start = .;
    KEEP(*(.model_ro*))
    KEEP(*(.rodata.model_ro*))
    . = ALIGN(32);
    __model_ro_end = .;

    ASSERT(__model_ro_end - __model_ro_start < 0x20000,
           "ERROR: MODEL_RO section too large (flash overflow risk)");
} > FLASH


/* Section pour l’inférence */
/* NS linker script fragment */
.inference_ro (NOLOAD) : ALIGN(32) {
    __inference_start = .;
    KEEP(*(.inference_ro*))
    __inference_end = .;
} > FLASH_NS