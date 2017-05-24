# sand leek
experimental vanity onion address whatchamacallit

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

Additionally, as outlined above, sand leek really needs to be verifying
that keys are sane.

## Benchmarks
Preliminary benching shows sand leek to be faster than some of the other
similar tools out there when pushing work across cores.

I have also written a "slightly parallel" base32 algorithm which uses
SSSE3 if support is given from the compiler and target platform.
Preliminary benchmarks seem to indicate that this gives a performance
benefit of between roughly 3% and 30%. Although, these higher
performance gains seem to be only when running at a reduced worker
thread count.

| CPU(s)                                      | Max throughput | -t |
|---------------------------------------------|---------------:|---:|
| 2× Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz |     103.3 MH/s | 32 |
| Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz     |      39.2 MH/s |  8 |
| Intel(R) Core(TM) i7-4770 CPU @ 3.40GHz     |      33.4 MH/s |  8 |
| AMD A4-1200 APU with Radeon(TM) HD Graphics |       2.6 MH/s |  2 |
| ARMv6-compatible processor rev 7 (v6l)      |      0.22 MH/s |  1 |

## Inspiration
sand leek was greatly inspired by schallot, escahlot and scallion.

