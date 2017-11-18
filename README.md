# sand leek
experimental vanity onion address whatchamacallit

[![Build Status](https://travis-ci.org/phillid/sand-leek.svg?branch=master)](https://travis-ci.org/phillid/sand-leek)

## Usage

Typical usage is something like

	sand-leek -s mycoolsite -t 4 > key.pem

to spawn 4 worker threads each looking for a key for an address starting
with 'mycoolsite'. It might find a private key for any of the addresses:

	mycoolsite5avt44.onion
	mycoolsiteane4hb.onion
	mycoolsitewtetnf.onion
	mycoolsiterkom5h.onion

or a large number of other valid addresses. Beware of using too long a
search. While you may luck out and get a key quickly, on average, it
may take a very long time to crack a long search.

## Platforms Supported

Travis CI performs automated builds and tests on OSX and Linux platforms,
with both gcc and clang. Builds are carried out manually for Windows with
MinGW on Linux.

## Future work
I have every intention to add GPU capability to sand leek.

## Benchmarks
Preliminary benching shows sand leek to be faster than some of the other
similar tools out there when pushing work across cores.

| CPU(s)                                      | CPU GHz | Max throughput | -t | Notes      |
|---------------------------------------------|--------:|---------------:|---:|------------|
| 2× Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz |     2.6 |     108.1 MH/s | 32 | x64 Linux  |
| Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz     |     3.4 |      44.3 MH/s |  8 | x64 Linux  |
| Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz     |     3.4 |      40.0 MH/s |  8 | x64 Linux  |
| AMD A6-3430MX with Radeon(TM) HD Graphics   |     1.7 |      12.8 MH/s |  4 | Win64      |
| ARMv7 Processor rev 4 (v7l)                 |     1.2 |       5.3 MH/s |  4 | RPi 3      |
| AMD A4-1200 APU with Radeon(TM) HD Graphics |     1.0 |       2.8 MH/s |  2 | x64 Linux  |
| Intel(R) Pentium(R) M processor 1.60GHz     |     1.6 |       1.9 MH/s |  1 | x64 Linux  |
| ARMv6-compatible processor rev 7 (v6l)      |     0.7 |      0.26 MH/s |  1 | RPi B+     |

## Inspiration
sand leek was greatly inspired by schallot, escahlot and scallion.

