Expected validation
===================

The claim runner should exit with status 0 and print these successful stages:

    EnclaveInfo attestation verified
    M_update accepted
    Enclave created
    Inference result: pred=<label>, expected=<label>
    PoX verified
    Enclave destroyed

The exact prediction and cycle counts are firmware/model dependent. The
reference outputs from previous runs are stored in this directory. New
reviewer-generated outputs are written to claims/claim1/results/.