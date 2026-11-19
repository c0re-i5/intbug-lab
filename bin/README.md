# Optional binaries (not vendored)

This directory is empty in the published tree. Download or build tools here if
you want the optional helpers:

## h2spec (zero-WU RFC cross-check)

Used by `./scripts/run-h2spec-zero-wu.sh` and `make zero-wu`.

```bash
# summerwind h2spec v2.6.0 linux/amd64 (example)
curl -fsSL -o /tmp/h2spec.tgz \
  https://github.com/summerwind/h2spec/releases/download/v2.6.0/h2spec_linux_amd64.tar.gz
tar -xzf /tmp/h2spec.tgz -C bin h2spec
chmod +x bin/h2spec
```

## arkrwn poc-safe

Optional ground-truth binary for `./scripts/proof.sh`. Prefer building from the
clone under `detectors/` (see `detectors/README.md`) rather than copying a
prebuilt binary from elsewhere:

```bash
cp detectors/arkrwn-nginx2root/target/release/poc bin/poc-safe
chmod +x bin/poc-safe
```

Neither binary is required for `./scripts/run-all.sh` / `make battery`.
