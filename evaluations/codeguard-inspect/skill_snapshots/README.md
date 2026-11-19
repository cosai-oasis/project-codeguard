# Evaluation skill catalog

`catalog.json` lists permanent, hash-pinned skill snapshots in this directory.
Each selected task installs one snapshot without changing its bytes.

- `codeguard-1.5` contains the unchanged CodeGuard 1.5.0 bundle. The benchmark
  packages' CodeGuard tasks install it through `CODEGUARD_VARIANT`.
- `security-reminder-v1` contains the previously reviewed one-line reminder,
  with its original name and discovery description.

Add revised guidance as a new snapshot and catalog entry. Keep existing files,
IDs and hashes unchanged. Catalog entries are available experiment inputs;
saved runs and reports show which models and benchmarks tested them.
