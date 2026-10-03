#!/usr/bin/env bash
# Run the lab integration tests (build tag "lab") against the Samba lab on
# the lab host (planning/docs/lab.md).
#
# The test binaries are compiled here (CGO off, so they run on Fedora and
# Debian alike), copied to the lab host and run there, because only that host
# reaches the lab network. The ad package tests run on the host; the
# sambatool tests run as root on dc1, where samba-tool lives. Secrets are read
# on the lab host from ~/conductor-lab/secrets.env and never leave it.
#
#   scripts/lab-test.sh                 # LAB_HOST=server-home
#   LAB_HOST=local scripts/lab-test.sh  # when already on the lab host
#   RUN=TestLabPaging scripts/lab-test.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

LAB_HOST="${LAB_HOST:-server-home}"
RUN="${RUN:-Lab}"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

export GOWORK=off CGO_ENABLED=0
go test -c -tags lab -o "$out/ad.test" .
go test -c -tags lab -o "$out/sambatool.test" ./sambatool
cp scripts/lab-run-remote.sh "$out/run.sh"

if [ "$LAB_HOST" = local ]; then
  dir="$HOME/samba-conductor-labtest"
  mkdir -p "$dir" && cp "$out"/* "$dir"/
  RUN="$RUN" bash "$dir/run.sh"
else
  rsync -a "$out/" "$LAB_HOST:samba-conductor-labtest/"
  ssh -o BatchMode=yes "$LAB_HOST" "RUN='$RUN' bash samba-conductor-labtest/run.sh"
fi
