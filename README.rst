Hello CIFAR Clean – Build & Flash Instructions

Environment Information

west --version
# West version: v1.5.0

Zephyr SDK Version:

zephyr-sdk-0.17.4

Flashing Tool:

STM32CubeProgrammer v2.21.0


⸻

Target Board Information
	•	Board: NUCLEO-L552ZE-Q
	•	MCU: STM32L552ZE-Q
	•	CPU: Cortex-M33
	•	Flash Size: 512 KB
	•	Device ID: 0x472
	•	Revision: Rev Z

ST-LINK Configuration
	•	ST-LINK SN: 066CFF565282494867012735
	•	Firmware: V2J47M34
	•	Voltage: 3.27V
	•	SWD Frequency: 4000 KHz
	•	Connect Mode: Under Reset
	•	Reset Mode: Hardware reset

⸻

Build Instructions

Clean and build the project for the Non-Secure target:

west build -b nucleo_l552ze_q/stm32l552xx/ns --pristine=always


⸻

Flash Instructions

Flash the compiled firmware to the board:

west flash -d build

The flash process uses STM32CubeProgrammer as the runner.

⸻

Notes
	•	Ensure the board is connected via ST-LINK before flashing.
	•	If flashing fails, verify ST-LINK connection, power supply, and SWD frequency.
	•	The project is built for the Non-Secure (NS) domain of the STM32L5 (TrustZone enabled).
