# IDA Pro RISC-V Plugin

## Installation

To add the plugin to your copy of IDA Pro (not provided), follow these steps.
`$IDA` is the path to the top of your IDA Pro installation.

1. Copy **RISC-V.py** (64-bit) and **RISC-V32.py** (32-bit) into **$IDA/procs/**.
2. Start Ida Pro, and select _NEW_, select the path to the RISC-V binary you wish to analyze.
3. Within the new context window, note _ELF64 for unknown CPU, [243]_. _243_ is RISC-V's identification number in ELF binaries.
4. Select _RISCV_ as processor type, don't change other options and then select _OK_.
5. You will receive two harmless error messages. The first warns about an unknown processor number, and the second is an "Are you sure?" confirmation. Acknowledge both.
6. The binary is now loaded, disassembled and ready for analysis.
7. **When closing IDA Pro, check the _Don’t Save the Database_ checkbox before clicking the _OK_ button.** If you fail to do this, next time you open the same file IDA Pro will not re-do the disassembly, and you will have to manually tell it to reload.
