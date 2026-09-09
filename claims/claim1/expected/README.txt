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
runner writes case_study_claim1.json and case_study_claim1.csv under build/.