# Modbus Demo
We have prepared a demonstration of a bug detected by this fuzzer in the libmodbus library.

## Target
- An open-source library utilized for Modbus device communication, written in C.
- Target version: Libmodbus v3.1.7.
## Identified Vulnerability

- CVE-2022-0367: A Heap-based Buffer Overflow.
- Issue Detail: Lack of validation for start_write_address in function code 23, allowing out-of-range write operations.
 
## R0fuzz Approach:
- Initial Test: Generation-based fuzzing to map possible address ranges.
- Refined Test: Mutation-based fuzzing to craft packets with critical address values, triggering the server-side crash.

## Setup and Execution

```shell
cd server/modbus

# to run the target binary to fuzz
LD_PRELOAD=./libmodbus.so.5 ./check_kill.sh

# On another terminal session

python3 r0fuzz.py -t modbus -i 127.0.0.1 -p 1502 mutate -s ./sample/ics.pcapng
```

## Video

<p align="left">
<img src="../../static/modbus.gif" alt="modbus-demo" width="800" height="480"/>
</p>

