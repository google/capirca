# SRX address-book extension

The optional Rust extension batches the subnet checks used to construct Juniper
SRX address books. Capirca uses it when installed and otherwise uses its existing
Python implementation.

[Benchmark results and reproduction commands](./benchmarks/README.md).

## Installation

Building the extension requires Python 3.9 or later and Rust 1.83 or later:

```sh
python -m pip install ./native
```

The extension has a separate wheel. Installing Capirca itself does not require
Rust or change its Python version requirement. To use the Python implementation
again:

```sh
python -m pip uninstall capirca-native
```

CI runs the SRX tests on Python 3.9 and the full project suite on Python 3.14
across Linux, macOS, and Windows.

## Behavior

Each batch updates one zone and network group. The extension returns indices
into the existing and incoming addresses; Python retains the original objects
and their comments, tokens, and identities. Existing address-book lists are
updated in place.

Insertion stops at the first overlapping network, as in the Python implementation.
A containing incoming network replaces the first matching network and any equal
entries, leaving later contained networks in place. It does not collapse the
whole group. IPv4 and IPv6 remain separate. Scoped IPv6 addresses and custom
network subclasses use the Python path.

## Verification

From the repository root, with the extension installed:

```sh
python -m pip install -r requirements.txt pytest
python -m pytest
cargo fmt --manifest-path native/Cargo.toml --check
cargo clippy --locked --manifest-path native/Cargo.toml --all-targets -- -D warnings
python tools/benchmark_srx.py --rounds 5 --output benchmark.json
python tools/benchmark_srx.py --rounds 5 --no-optimize --output benchmark-default.json
```

The benchmark rotates between the Python fallback, Rust, and a Python integer
comparison control. It checks exact output hashes, includes definition loading,
parsing, rendering, and writing, and records every run. Imports and process
startup are excluded. Each backend receives one warm-up per workload; all renders
use one worker. The fixtures are the repository's existing policies and network
definitions. Small policies and the complete sample set are included alongside
the large SRX sample.

Pass `--baseline /path/to/unmodified/capirca` to compare separate CLI processes
against an upstream source tree instead. This mode includes imports, process
startup, and the multiprocessing manager, and verifies that both trees contain
identical fixture files. Both subprocesses use `PYTHONHASHSEED=0` because the
Arista generator emits counters in set iteration order.
