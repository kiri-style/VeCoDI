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

Remote evaluation
-----------------

For remote review, authors should provide a time-limited SSH/desktop session
to a host with the board attached, or a live serial endpoint plus access to
STM32CubeProgrammer. The reviewer then runs install.sh, sets
VECODI_SERIAL_PORT to the forwarded serial device, and executes
claims/claim1/run.sh. No credentials or private keys are part of this
artifact; access credentials must be exchanged through the conference's
approved channel.