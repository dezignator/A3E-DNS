# C reference implementation

This directory contains independent reference implementations of three
primitives that the A3E-DNS extended suite relies on:

- the negacyclic number-theoretic transform over `Z_Q[X]/(X^N + 1)`,
- the CDT Gaussian sampler with the ML-DSA parameter set,
- the minimal classic pcap reader used by the dataset loaders.

## Purpose

These implementations exist to **cross-check** the Rust and Python
implementations. A round-trip test on any implementation proves only
that its forward and inverse agree; it does not prove that the
transform is the one the thesis claims. The C reference is written in
the "obvious" style — naive polynomial multiplication, explicit
pre-twiddle tables built at runtime, no lookup-table optimisation — so
that a reviewer who knows the Cooley-Tukey algorithm can check it by
eye against the published variant.

The key test, `test_ntt_agrees_with_naive`, checks that the NTT-based
convolution equals the naive `O(N^2)` multiplication on random inputs.
That is a real correctness check; the Rust integration test performs
the same check independently, and the Python module cross-checks
against the Rust implementation when the extension is present.

## Building

```bash
make all      # build the two test binaries
make test     # run both test suites
make clean    # remove build/ artefacts
