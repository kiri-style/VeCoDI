Infrastructure and access
=========================

Public-infrastructure rationale
-------------------------------

The main claim is not viable on CPU-only public infrastructure because it
depends on an STM32L552ZE Cortex-M33, TF-M secure/non-secure execution, an
ST-LINK programmer, and the board's UART. A public VM or Colab notebook can
run host-side syntax checks and inspect supplied results, but it cannot
reproduce the measured hardware behavior.

Required local or remote resources
----------------------------------

* NUCLEO-L552ZE-Q (STM32L552ZE, 512 KB flash)
* ST-LINK connection and USB serial link
* macOS or Linux host
* Python 3.10 or newer, West 1.5.0 or newer
* Zephyr SDK 0.17.4 and STM32CubeProgrammer 2.21.0

Access and evaluator requirements
---------------------------------

No remote SSH, desktop session, live serial endpoint, or shared physical board
is provided with this artifact. The complete experience must be reproduced by
the evaluator with their own NUCLEO-L552ZE-Q board, ST-LINK connection, and USB
serial link. This physical-hardware requirement is necessary for TF-M secure /
non-secure execution, flash programming, UART protocol exchange, and the
device-side cycle counters reported by the benchmarks.

Without the board, evaluators can still run install.sh, Python syntax checks,
inspect the supplied CSV/JSON outputs, and review the source code, but they
cannot reproduce the firmware execution, hardware isolation, or measured cycle
counts. No credentials, private keys, or remote-access tokens are included in
the artifact.