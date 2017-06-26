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

## Future work
I have every intention to add GPU capability to sand leek.

## Benchmarks
Preliminary benching shows sand leek to be faster than some of the other
similar tools out there when pushing work across cores.

| CPU(s)                                      | Max throughput | -t |
|---------------------------------------------|---------------:|---:|
| 2× Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz |     108.1 MH/s | 32 |
| Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz     |      44.3 MH/s |  8 |
| Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz     |      40.0 MH/s |  8 |
| AMD A4-1200 APU with Radeon(TM) HD Graphics |       2.8 MH/s |  2 |
| Intel(R) Pentium(R) M processor 1.60GHz     |       1.9 MH/s |  1 |
| ARMv6-compatible processor rev 7 (v6l)      |      0.26 MH/s |  1 |

## Inspiration
sand leek was greatly inspired by schallot, escahlot and scallion.

