# sand leek
## experimental vanity onion address whatchamacallit

Still early days.
Warning: this tool doesn't yet do sanity checking on the keys produced.
Use at your own risk and verify the keys' sanity yourself.

## Future work
I have every intention to add GPU capability to sand leek.

Additionally, as outlined above, sand leek really needs to be verifying
that keys are sane.

## Benchmarks
Preliminary benching shows sand leek to be faster than some of the other
similar tools out there when pushing work across cores.

CPU(s)                                      | Max throughput | -t
--------------------------------------------+----------------+---
2× Intel(R) Xeon(R) CPU E5-2670 0 @ 2.60GHz | 94 MH/s        | 16
Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz     | 38 MH/s        | 8
AMD A4-1200 APU with Radeon(TM) HD Graphics | 2.3 MH/s       | 2
