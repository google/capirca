# SRX address-book benchmark

Measured October 10, 2026 on an Apple M4 with 16 GiB RAM, macOS 15.6.1,
CPython 3.14.4, and rustc 1.94.1 (`aarch64-apple-darwin`). The extension used
the Cargo release profile, the checked-in lockfile, and no target-specific flags.

## Default CLI

Complete CLI invocations against unmodified upstream commit
`fcca84f5df6e8262d55ecca20635c166009c2c09`, with `--max_renderers=1` and
otherwise default options. Imports, process startup, the multiprocessing manager,
definition loading, parsing, rendering, and file writes are included.

| Workload | Upstream median | Rust median | Speedup |
| --- | ---: | ---: | ---: |
| All bundled samples | 15.8686 s | 1.7551 s | 9.04x |
| Large SRX/Palo Alto sample | 14.6689 s | 0.6051 s | 24.24x |
| Small SRX sample | 0.2501 s | 0.2510 s | 1.00x |

All 49 distinct files in the complete sample run matched byte-for-byte. The
large mixed-target sample produced two matching files, and the small sample
produced one. The CLI timings contain three measured runs per backend and
workload, preceded by one warm-up. Run order alternates, filesystem caches are
warm, and each invocation uses a fresh Python process. `PYTHONHASHSEED=0` is
set in both processes because the unrelated Arista generator emits counters
in set iteration order.

## Optimized rendering and Python control

These runs enable address optimization and execute in one Python process.
They include definition loading through file writing, but exclude imports and
process startup. The Python column uses the unchanged insertion routine through
the fallback; the integer control uses the same range comparisons and batching
as Rust, implemented in Python. Five measured runs per backend follow one warm-up;
backend order rotates.

| Workload | Python median | Integer control median | Rust median |
| --- | ---: | ---: | ---: |
| All bundled samples | 5.752011 s | 1.635033 s | 1.341342 s |
| Large SRX/Palo Alto sample | 4.671460 s | 0.554711 s | 0.252233 s |
| Small SRX sample | 0.002287 s | 0.002282 s | 0.002289 s |

The integer control accounts for a substantial part of the improvement.
Rust is 1.22x faster than that control over the complete optimized sample run
and 2.20x faster on the large mixed-target policy. The small policy shows no
meaningful improvement. Every backend produced identical output hashes.

These are bundled sample fixtures, including the synthetic large networks in
`def/LARGE_NETWORK.net`; they do not establish performance on a production
policy corpus or with multiple rendering workers.

## Correctness and build checks

- Full local suite with Rust: 1,725 passed, plus 19 subtests.
- Full local suite with the extension uninstalled: 1,718 passed, seven native-only tests skipped, plus 13 subtests.
- Differential tests compare selected object identities after each batch, including first-match replacement, duplicate existing entries, mixed families, full address ranges, and 36,000 seeded incoming networks.
- Scoped IPv6 and custom network subclasses use the Python path.
- An integration test verifies that policy rendering invokes the native function and matches fallback output.
- Release wheel build, Rust formatting, and Clippy with warnings denied passed.
- Changed Python files pass the repository CI lint selections. Repository-wide lint finds the same pre-existing W391 and two F824 findings on unchanged upstream.

## Reproduction

The raw files retain individual timings, output digests, source revisions, and
input-file SHA-256 hashes: [CLI](./cli-default.json) and
[optimized rendering](./render-optimized.json). The application implementation
is commit `5d650c71e77f48d7a47484b9b1ae1a19418d6806`; subsequent changes before
measurement adjust benchmark reporting and test configuration.

From the repository root, in an activated Python 3.14 environment:

```sh
python -m pip install -r native/benchmarks/python-environment.txt
python -m pip install --no-deps -e .
python -m pip install --no-build-isolation ./native
git worktree add --detach ../capirca-baseline fcca84f5df6e8262d55ecca20635c166009c2c09
PYTHONHASHSEED=0 python tools/benchmark_srx.py --rounds 3 --no-optimize --baseline ../capirca-baseline --output cli-default.json
PYTHONHASHSEED=0 python tools/benchmark_srx.py --rounds 5 --output render-optimized.json
```

Use rustc 1.94.1 for the recorded build configuration. Absolute runtimes depend
on the host, background activity, Python version, and policy contents.
