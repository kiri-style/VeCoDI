# Simulated Benchmark Results
**Generated**: Simulation (20 runs)
**Platform**: STM32L552ZE-Q @ 110 MHz


## Table 2: Benchmark Results - NS vs SAVID

| Model | NS Latency (ms) | S Latency (ms) | SAVID Latency (ms) | Overhead (ms) | Overhead (%) |
|-------|---|---|---|---|---|
| CIFAR-10 Split Inference | 47.87 | 69.49 | 82.63 | 34.75 | 72.6% |

### Simulation Statistics (20 runs)

**NS Configuration (Full Non-Secure)**
- Mean: 47.87 ms (5,266,081 cycles)
- Std Dev: 1.66 ms
- Range: [45.67, 51.26] ms

**S Configuration (Secure World)**
- Mean: 69.49 ms (7,644,275 cycles)
- Std Dev: 2.36 ms
- Range: [66.59, 75.03] ms

**SAVID Configuration (TrustZone Protection)**
- Mean: 82.63 ms (9,089,011 cycles)
- Std Dev: 3.38 ms
- Range: [75.30, 87.20] ms

### Overhead Analysis

**Memory Protection Cost**: 34.75 ms (72.6%)
- Source: TrustZone-M SAU windows, context switch latency, atomic protection
- Does NOT include cryptographic operations (which are identical in NS/S modes)
- Represents pure isolation overhead

### CPU Cycles Breakdown (@ 110 MHz)

| Stage | Cycles |
|-------|---|
| NS Inference | 5,266,081 |
| Secure Operations | 7,644,275 |
| SAVID Protected | 9,089,011 |
| Protection Overhead | 3,822,929 |
