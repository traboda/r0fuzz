# DNP3 Demo

We have prepared a demonstration of a bug detected by this fuzzer in an application called `bro` which uses the dnp3 protocol.

## Target
- [The Zeek Network Security Monitor](https://github.com/bro/bro)

## Identified Vulnerability

- CVE-2015-1522 
- Issue Detail: analyzer/protocol/dnp3/DNP3.cc in Bro before 2.3.2 does not reject certain non-zero values of a packet length, which allows remote attackers to cause a denial of service (buffer overflow or buffer over-read) via a crafted DNP3 packet.
 
## R0fuzz Approach:
- We will use Generation based fuzzing to target the various parameters of the packet to trigger the bug.

## Setup and Execution

We have created a custom listener by taking just a part of the code from `bro` to show this demo.

```shell
cd server/dnp3/
make
./dn3p_listener

python3 r0fuzz.py -t dnp3 -i 127.0.0.1 -p 8080 generate
```

## Video

<p align="left">
<video src="../../static/dnp3.mp4" alt="dnp3-demo" width="800" height="480"/>
</p>
