# r0fuzz

*r0fuzz* aims to find security flaws in the hardware network protocols like MODBUS, DNP3 etc.

## Setup

- Python virtual environment

```shell
git clone https://github.com/traboda/r0fuzz.git
cd r0fuzz


pip install virtualenv 
virtualenv fuzz_env
source fuzz_env/bin/activate
pip install -r requirements.txt
```

* Server side to simulate `modbus slave`
  
  * [ModbusPal](https://github.com/zeelos/ModbusPal) 
  * [libmodbus](https://github.com/stephane/libmodbus) 

- Run the below command if libmodbus is not installed, v3.1.6 

`patchelf --replace-needed libmodbus.so.5 ./libmodbus.so.5 server`

## Usage

```shell
usage: r0fuzz.py [-h] -t TARGET [-v] [-i IP] [-p PORT] {dumb,mutate,generate} ...

A grammar based fuzzer for SCADA protocols

positional arguments:
  {dumb,mutate,generate}
    dumb                Apply dumb fuzzing technique
    mutate              Apply mutation based fuzzing technique
    generate            Apply generation based fuzzing technique

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target protocol
  -v, --verbosity       Log level
  -i IP, --ip IP        Target IP Address
  -p PORT, --port PORT  Target Port

```

## Features

- Dumb-Fuzzing/Brute Force
  - Basic Fuzzer using brute force approach
- Supports smart Fuzzing approaches:
  - Generation based
- Current fuzzes:
  - MODBUS
  - DNP3

## TODO:

- Enhance the fuzzer experience
- Incorporate other protocols
