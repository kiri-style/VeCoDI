# VECODI Case Study (Provider / Model Customer)

## Objective
This case study defines a two-identity operational flow based on the existing Mac provider protocol.

Identities:
1. **Provider**: entity that sends `M_update` to authorize usage.
2. **Model Customer**: entity that requests enclave lifecycle operations and inference.

## Identity 1: Provider

### Role
The Provider authorizes model usage by sending a valid `M_update` over the secure UART protocol.

### Responsibilities
1. Establish secure session context.
2. Retrieve and verify EnclaveInfo.
3. Send `M_update` with a strictly increasing `c_limit`.
4. Optionally verify current quota and counters.

### Command-level flow (Mac provider)
1. `1` Fetch EnclaveInfo
2. `2` Compute EnclaveInfo
3. `3` Send `M_update`

Optional quota checks:
- `5` Get max inferences
- `7` Get inference count
- `8` Get remaining inferences

### Security requirements
- `M_update` must be encrypted/authenticated (AES-GCM transport).
- Device enforces anti-replay: reject if `c_limit <= current max`.
- Authorization is a precondition for verified inference.

## Identity 2: Model Customer

### Role
The Model Customer consumes the authorized quota by explicitly managing enclave lifecycle and requesting inference.

### Responsibilities
1. Request enclave creation.
2. Trigger verified inference requests.
3. Request enclave destruction at the end of use.

### Command-level flow (Mac provider)
1. `21` Create enclave
2. `9` Verified inference
3. `22` Destroy enclave

Optional status check:
- `17` Session status (includes enclave created state)

### Security requirements
- Inference must not auto-create enclave.
- Verified inference is accepted only if session/auth/lifecycle preconditions are met.
- Quota is decremented only on successful inference completion.

## End-to-End Sequence (Provider -> Model Customer)

1. Provider runs secure authorization:
   - `1` -> `2` -> `3`
2. Model Customer starts controlled execution:
   - `21` -> `9` (repeat while quota remains) -> `22`
3. Optional monitoring:
   - `5`, `7`, `8`, and `17`

## Protocol Preconditions Summary

Before `9` (Verified inference), the device expects:
1. Successful static session-key setup.
2. Successful `M_update` validation.
3. Enclave explicitly created.

If any precondition is missing, request is rejected.

## Practical Notes for the CCS Case Study Section

- This split of identities highlights policy separation:
  - Provider controls authorization policy (`M_update` / quota).
  - Model Customer controls runtime usage (create/infer/destroy).
- The flow supports auditable lifecycle transitions and controlled resource exposure.
- The design maps directly to real command IDs already implemented in `tools/mac_provider.py` and device UART handlers.
