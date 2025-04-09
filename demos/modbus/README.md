# Modbus Demo
Demonstration of a bug detected by this fuzzer in libmodbus.

## Target
- An open-source library utilized for Modbus device communication, written in C.
- Target version: Libmodbus v3.1.7

## Identified Vulnerability
- CVE-2022-0367: A Heap-based Buffer Overflow.
- Issue Detail: Lack of validation for start_write_address in function code 23, allowing out-of-range write operations.
 
## r0fuzz Approach:
- Initial Test: Generation-based fuzzing to map possible address ranges.
- Refined Test: Mutation-based fuzzing to craft packets with critical address values, triggering the server-side crash.

## Setup and Execution

### Server setup
```bash
# Terminal 1
python3 run_server.py --server server/modbus/server
--library server/modbus/libmodbus.so.5
```

### Fuzzer Setup
```bash
# Terminal 2
python3 r0fuzz.py -t modbus -i 127.0.0.1 -p 1502 mutate -s sample/modbus-pcap/modbus.pcap
```

### Replay Setup
```bash
# Terminal 1
python3 run_server.py --server server/modbus/server --library server/modbus/libmodbus.so.5 --replay
```

```bash
# Terminal 2
python3 r0fuzz.py -t modbus -i 127.0.0.1 -p 1502 replay -log crashes/crashes_09042025204436.log
```


## r0fuzz in action
<p align="center">
<video src="modbus-demo.mp4" width=800 autoplay loop preload></video>
</p>

## Replaying crash packets
<p align="center">
<video src="modbus-replay.mp4" width=800 autoplay loop preload></video>
</p>
