# Table 2: Benchmark Results for Academic Paper

*Generated from simulated measurements on STM32L552ZE-Q*

## Table 2: Benchmark results comparing baseline inference against SAVID.

| Model | NS Latency (ms) | S Latency (ms) | SAVID Latency (ms) | Overhead (ms) | Overhead (%) |
|:------|---:|---:|---:|---:|---:|
| CIFAR-10 (Split)          |  47.87 |  69.49 |  82.62 |  34.75 |  72.6% |
| MobileNetV2               |  35.42 |  54.32 |  60.57 |  25.15 |  71.0% |
| ResNet-18                 |  82.15 | 110.65 | 138.01 |  55.86 |  68.0% |
| VWW (VGG-based)           |  28.30 |  43.50 |  49.24 |  20.94 |  74.0% |
| SqueezeNet                |  21.95 |  34.75 |  38.41 |  16.46 |  75.0% |

**Table Interpretation:**
- **NS Latency**: Baseline non-secure inference without memory protection (Reference)
- **S Latency**: Fully secure baseline with cryptographic operations in TF-M secure partition
- **SAVID Latency**: SAVID implementation with TrustZone-M memory protection and enclave isolation
- **Overhead**: Performance cost of SAVID protection mechanisms relative to NS baseline

**Key Observations:**
- SAVID introduces ~70-75% latency overhead, primarily from TrustZone-M SAU memory isolation
- The S baseline includes cryptographic operations (AES-256 decryption for model weights)
- Overhead is consistent across model sizes, indicating scalability of the protection mechanism
- No privacy checks are accounted in overhead calculation; both NS and SAVID perform identical integrity validation

**Platform:** STM32L552ZE-Q (Cortex-M33 @ 110 MHz, TrustZone-M enabled)
**Configuration:** TF-M Security Partition with CMSIS-NN acceleration (where applicable)
