"""Compare complete sample-policy renders with and without the SRX extension."""

import argparse
import hashlib
import json
import logging as python_logging
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

from absl import logging
from capirca import aclgen
from capirca.lib import junipersrx
from capirca.lib import naming


def integer_indices(networks, existing):
  """Control using the same integer comparisons as the Rust implementation."""
  ranges = [(version, start, start | ((1 << ((32 if version == 4 else 128)
                                           - prefix)) - 1))
            for version, start, prefix in networks]
  selected = list(range(existing))
  for next_index in range(existing, len(ranges)):
    version, start, end = ranges[next_index]
    for index in selected:
      old_version, old_start, old_end = ranges[index]
      if version != old_version:
        continue
      if old_start <= start and old_end >= end:
        break
      if start <= old_start and end >= old_end:
        selected = [next_index if ranges[i] == ranges[index] else i
                    for i in selected]
        break
    else:
      selected.append(next_index)
  return selected


def render(root, policies, optimize):
  with tempfile.TemporaryDirectory() as directory:
    output = pathlib.Path(directory)
    start = time.perf_counter()
    definitions = naming.Naming(str(root / 'def'))
    writes = []
    for path in policies:
      aclgen.RenderFile(str(root / 'policies'), path, output, definitions,
                        2, optimize, False, writes)
    aclgen.WriteFiles(writes)
    seconds = time.perf_counter() - start
    digest = hashlib.sha256()
    for path in sorted(output.rglob('*')):
      if path.is_file():
        digest.update(str(path.relative_to(output)).encode())
        digest.update(b'\0')
        digest.update(path.read_bytes())
    return {'seconds': seconds, 'sha256': digest.hexdigest(),
            'files': len(writes)}


def render_cli(root, policy_paths, optimize):
  with tempfile.TemporaryDirectory() as directory:
    command = [sys.executable, '-m', 'capirca.aclgen', '--max_renderers=1',
               '--base_directory=' + str(root / 'policies'),
               '--definitions_directory=' + str(root / 'def'),
               '--output_directory=' + directory]
    if len(policy_paths) == 1:
      command.append('--policy_file=' + str(root / policy_paths[0]))
    if optimize:
      command.append('--optimize')
    environment = os.environ.copy()
    environment['PYTHONPATH'] = str(root)
    environment['PYTHONHASHSEED'] = '0'
    start = time.perf_counter()
    subprocess.run(command, cwd=root, env=environment, check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    seconds = time.perf_counter() - start
    digest = hashlib.sha256()
    paths = sorted(path for path in pathlib.Path(directory).rglob('*')
                   if path.is_file())
    for path in paths:
      digest.update(str(path.relative_to(directory)).encode())
      digest.update(b'\0')
      digest.update(path.read_bytes())
    return {'seconds': seconds, 'sha256': digest.hexdigest(), 'files': len(paths)}


def main():
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--rounds', type=int, default=5)
  parser.add_argument('--output', type=pathlib.Path, required=True)
  parser.add_argument('--no-optimize', action='store_true')
  parser.add_argument('--baseline', type=pathlib.Path,
                      help='compare CLI processes against an unmodified source tree')
  args = parser.parse_args()
  if args.rounds < 1:
    parser.error('--rounds must be positive')
  root = pathlib.Path(__file__).resolve().parents[1]
  native = junipersrx._capirca_native
  if native is None:
    parser.error('install the native extension first')
  logging.set_verbosity(logging.ERROR)
  python_logging.disable(python_logging.WARNING)
  backends = {'python': None, 'rust': native,
              'python-integers': SimpleNamespace(
                  address_book_indices=integer_indices)}
  if args.baseline:
    backends = {'upstream': None, 'rust': native}
  workloads = {
      'all-samples': sorted(aclgen.DescendDirectory(
          str(root / 'policies'), ['DEPRECATED', 'def'])),
      'srx-large': [root / 'policies/pol/sample_stateful_multitarget_complex.pol'],
      'srx-small': [root / 'policies/pol/sample_srx.pol'],
  }
  results = {'revision': subprocess.check_output(
      ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
             'dirty': bool(subprocess.check_output(
                 ['git', 'status', '--porcelain'], cwd=root, text=True).strip()),
             'python': platform.python_version(),
             'platform': platform.platform(),
             'optimize': not args.no_optimize,
             'cli': bool(args.baseline),
             'hash_seed': '0' if args.baseline else os.environ.get('PYTHONHASHSEED'),
             'workers': 1, 'runs': [], 'summary': {},
             'inputs': {str(path.relative_to(root)): hashlib.sha256(
                 path.read_bytes()).hexdigest()
                        for directory in ('def', 'policies')
                        for path in sorted((root / directory).rglob('*'))
                        if path.is_file()}}
  names = list(backends)
  if args.baseline:
    args.baseline = args.baseline.resolve()
    results['baseline_revision'] = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=args.baseline, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'],
                               cwd=args.baseline, text=True).strip():
      parser.error('baseline checkout must be clean')
    for path, digest in results['inputs'].items():
      if hashlib.sha256((args.baseline / path).read_bytes()).hexdigest() != digest:
        parser.error('baseline fixture mismatch: ' + path)
  for workload, policies in workloads.items():
    expected = None
    for round_number in range(-1, args.rounds):
      offset = max(round_number, 0) % len(names)
      order = names[offset:] + names[:offset]
      for backend in order:
        junipersrx._capirca_native = backends[backend]
        if args.baseline:
          source = args.baseline if backend == 'upstream' else root
          result = render_cli(source, [path.relative_to(root) for path in policies],
                              not args.no_optimize)
        else:
          result = render(root, policies, not args.no_optimize)
        if expected is None:
          expected = result['sha256']
        if result['sha256'] != expected:
          raise RuntimeError('output mismatch: %s/%s' % (workload, backend))
        result.update(workload=workload, backend=backend, round=round_number)
        results['runs'].append(result)
        print(json.dumps(result), flush=True)
    results['summary'][workload] = {
        backend: statistics.median(run['seconds'] for run in results['runs']
                                   if run['workload'] == workload and
                                   run['backend'] == backend and run['round'] >= 0)
        for backend in names}
    args.output.write_text(json.dumps(results, indent=2) + '\n')
  junipersrx._capirca_native = native


if __name__ == '__main__':
  main()
