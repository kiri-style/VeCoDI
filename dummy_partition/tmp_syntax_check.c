/* minimal typedefs to check syntax */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef int psa_status_t;
typedef unsigned int psa_signal_t;

typedef struct {
    size_t in_size[4];
    size_t out_size[1];
    int handle;
    int type;
} psa_msg_t;

#define PSA_ERROR_PROGRAMMER_ERROR -1
#define PSA_ERROR_INVALID_ARGUMENT -2
#define PSA_ERROR_NOT_SUPPORTED -3
#define PSA_ERROR_GENERIC_ERROR -4
#define PSA_SUCCESS 0

/* insert the ipc handler body from dummy_partition.c up to before dp_signal_handle */
/* Copying function body from original file (truncated) */
#include "dummy_partition.c"

