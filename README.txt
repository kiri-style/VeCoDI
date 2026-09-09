VeCoDI ACSAC Artifact
====================

This repository contains the source code, firmware build configuration, host
drivers, benchmark scripts, and result files used by the VeCoDI evaluation.
The artifact is intended to reproduce the paper's embedded confidential
inference case study on an STM32L552ZE NUCLEO-L552ZE-Q board.

Quick start
-----------

1. Install host-side Python dependencies:

       ./install.sh

2. Install Zephyr and the Zephyr SDK as described in BUILD_FLASH.md. The
   artifact was tested with Zephyr SDK 0.17.4, West 1.5.0, and Zephyr 4.3.99.

3. Connect a NUCLEO-L552ZE-Q board and identify its serial device.

4. Build and flash:

       . /path/to/zephyr/zephyr-env.sh
       west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always
       west flash

5. Reproduce the main case-study claim:

       VECODI_SERIAL_PORT=/dev/cu.usbmodemXXXX claims/claim1/run.sh

The script runs one verified inference by default and writes JSON/CSV results
under build/. Set VECODI_RUNS for repeated measurements. See use.txt for the
intended use and limitations, and infrastructure/README.txt for the hardware
access rationale.

Benchmark commands
------------------

All board commands use 115200 baud. Replace the example serial device with the
device assigned by the host operating system. The commands below assume they
are run from the repository root after ./install.sh.

Run the case study directly and save benchmark results:

       python3 tools/vecodi_case_study.py /dev/cu.usbmodemXXXX \
           --c-limit 10 --runs 1 \
           --benchmark-json build/case_study.json \
           --benchmark-csv build/case_study.csv

Run repeated verified inferences:

       python3 tools/vecodi_case_study.py /dev/cu.usbmodemXXXX \
           --c-limit 10 --runs 10 \
           --benchmark-json build/case_study_10runs.json \
           --benchmark-csv build/case_study_10runs.csv

Run the interactive provider/customer workflow:

       python3 tools/vecodi_case_study.py /dev/cu.usbmodemXXXX \
           --c-limit 10 --interactive

Run with a host image. PNG/JPEG input is resized to 32x32 RGB; raw input must
contain exactly 3072 bytes:

       python3 tools/vecodi_case_study.py /dev/cu.usbmodemXXXX \
           --c-limit 10 --runs 1 --image tools/blank_img.bin \
           --image-label 0

The CREATE_ENCLAVE size benchmark requires an authorized VECODI session. After
each firmware flash, run one case study first to fetch EnclaveInfo and send
M_update:

          python3 tools/vecodi_case_study.py /dev/cu.usbmodemXXXX \
                 --c-limit 10 --runs 1 \
                 --benchmark-json build/benchmark_setup.json \
                 --benchmark-csv build/benchmark_setup.csv

Then measure CREATE_ENCLAVE for the full encrypted model size:

          python3 tools/create_enclave_size_benchmark.py \
                 /dev/cu.usbmodemXXXX --size 39552 \
                 --runs 10 --output build/create_enclave_size.json

Additional sizes can be supplied when supported by the firmware:

       python3 tools/create_enclave_size_benchmark.py \
           /dev/cu.usbmodemXXXX --size 1024 4096 16384 39552 \
           --runs 10 --output build/create_enclave_size.json

The value 39552 is the full late-weight blob size used by this artifact.

Read TCB and memory-size counters:

       python3 tools/fetch_tcb_benchmark.py

Before running this command, set the PORT constant near the top of
tools/fetch_tcb_benchmark.py to the board serial device if it is not
`/dev/tty.usbmodem1203`. The command writes build/tcb_benchmark.json.

Measure the time to zero the non-secure stack directly on the board:

       python3 tools/ns_stack_zero_time.py \
           --port /dev/cu.usbmodemXXXX --stack-bytes 3072

Convert a previously measured cycle count without connecting to hardware:

       python3 tools/ns_stack_zero_time.py --cycles 18522 \
           --stack-bytes 3072

Or read a cycle count from a JSON file:

       python3 tools/ns_stack_zero_time.py --json build/ns_stack_zero.json \
           --json-key stack_zero_cycles --stack-bytes 3072

Full-flow benchmark
-------------------

Run the detailed benchmark for M_update, enclave creation, verified
inference, PoX completion, and enclave destruction:

          python3 tools/full_flow_benchmark.py /dev/cu.usbmodemXXXX \
                 --runs 1 --c-limit 10 \
                 --output build/full_flow_benchmark.json

The secure counter for c_limit persists across sessions on the board. If
M_update rejects the selected value, rerun with a larger strictly increasing
value, for example `--c-limit 11`. The successful run writes the detailed
per-stage measurements to the JSON output path.

Case study versus full-flow benchmark
-------------------------------------

Both tools execute the same main protocol:

       M_update -> create enclave -> verified inference -> PoX -> destroy enclave

Use `tools/vecodi_case_study.py` as the functional artifact runner. It checks
attestation and PoX verification, confirms the prediction, reports the device
state, and writes JSON/CSV results. This is the recommended command for the
ACSAC reproducibility claim and for a quick end-to-end validation.

Use `tools/full_flow_benchmark.py` for detailed performance measurements. It
records host-side duration and separates NS/Secure cycle counters for
M_update, enclave creation, inference, PoX completion, and destruction. With
multiple runs it also reports averages and standard deviations. Its output is
a detailed JSON benchmark rather than the claim-oriented CSV/JSON pair.

Repository map
--------------

artifact/       Submission manifest and artifact scope
claims/         Reproduction scripts and expected validation information
infrastructure/ Hardware requirements and remote-access guidance
src/, dummy_partition/, split_inference/, tools/
                Firmware and host-side implementation
BUILD_FLASH.md  Detailed Zephyr build and flash instructions