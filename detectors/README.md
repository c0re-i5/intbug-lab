# Third-party detectors (not vendored)

This directory is intentionally empty in the published tree. Clone the public
PoCs yourself if you want ground-truth comparison against our battery:

```bash
# arkrwn --safe accounting PoC (used by scripts/proof.sh)
git clone https://github.com/arkrwn/NGINX2Root-CVE-2026-123007.git \
  detectors/arkrwn-nginx2root
(cd detectors/arkrwn-nginx2root && cargo build --release)
# binary lands at detectors/arkrwn-nginx2root/target/release/poc
# optional convenience copy:
#   cp detectors/arkrwn-nginx2root/target/release/poc bin/poc-safe

# Rapid7 reproduction notes / scripts (reference only; not required to run our battery)
git clone https://github.com/sfewer-r7/CVE-2026-123007.git \
  detectors/sfewer-r7-cve
```

Our invariant battery (`ours/`, `./scripts/run-all.sh`) does **not** need these
clones. They exist only so you can cross-check the known-vuln nginx listener
against an independent `--safe` proof.
