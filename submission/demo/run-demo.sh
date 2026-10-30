#!/usr/bin/env bash
# Reproducible RevokeTrace demonstration.
#
# Makes a clean clone of the current commit, builds the release binary with the
# documented command, and runs the real CLI against the bundled fixture.
# Nothing here contacts the network except cloning the local repository and
# resolving Cargo dependencies. The fixture is a STORED snapshot, not newly
# obtained network state.
#
# Usage: submission/demo/run-demo.sh > transcript.txt 2>&1
set -u

SRC="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d)"
BIN=""
trap 'rm -rf "$WORK"' EXIT

ISSUER=GBYEWT4YXA5QJPJDYFESK6T23OJGUFZDTHAFHUZNFVZLWMOJG4IOTUEG
TRUSTOR=GAPOZN3WOIXJSEMGT4N6YCFL6ESLCFZZDQKKYC3WKBZUTXWRA54HERMB

step() { printf '\n\n### %s\n' "$*"; }
# Prints the command shell-quoted, with the temporary directory shown as $WORK
# and the built binary shown as revoketrace, then runs it and prints its exit code.
run() {
  printf '$'
  for arg in "$@"; do
    if [ "$arg" = "$BIN" ]; then
      printf ' revoketrace'
    else
      printf ' %q' "${arg//$WORK/\$WORK}"
    fi
  done
  printf '\n'
  "$@"
  local code=$?
  printf '[exit code %s]\n' "$code"
  return 0
}

echo "RevokeTrace demonstration transcript"
echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Source commit: $(git -C "$SRC" rev-parse HEAD)"
echo "Fixture note: fixtures/live-testnet-discovery.json is a stored snapshot from an earlier Testnet capture."
echo "It is not newly obtained network state, and no network request is made below."

step "1. Clean checkout and toolchain"
git clone -q "$SRC" "$WORK/checkout"
cd "$WORK/checkout" || exit 1
run git log -1 --format=%H
run cat rust-toolchain.toml
run rustc --version
run cargo --version

step "2. Release build (documented command)"
run cargo build --release --locked --bin revoketrace 2>&1
BIN="$WORK/checkout/target/release/revoketrace"

step "3. help"
run "$BIN" help

step "4. version"
run "$BIN" version

SNAPSHOT=fixtures/live-testnet-discovery.json
ARGS=(--snapshot "$SNAPSHOT" --operation SetTrustLineFlags
  --source-account "$ISSUER" --trustor "$TRUSTOR"
  --asset-code FLUTTER --asset-issuer "$ISSUER"
  --before-flags 1 --after-flags 0
  --tx-source-account "$ISSUER" --sequence 42 --operation-index 0)

step "5. Offline analysis of the stored fixture"
echo "Expected: UNVERIFIED_FORECAST and exit code 10."
echo "Exit code 10 means the forecast is internally consistent but carries warnings."
echo "It is not a successful preflight and not transaction approval."
run "$BIN" analyze "${ARGS[@]}"

step "6. JSON report, written twice to prove deterministic output"
run "$BIN" analyze "${ARGS[@]}" --format json --output "$WORK/report-a.json"
run "$BIN" analyze "${ARGS[@]}" --format json --output "$WORK/report-b.json"
if cmp -s "$WORK/report-a.json" "$WORK/report-b.json"; then
  echo "Determinism check: report-a.json and report-b.json are byte-identical."
else
  echo "Determinism check FAILED: the two reports differ."
fi
printf 'SHA-256: '; sha256sum "$WORK/report-a.json" | cut -d' ' -f1
echo "schema_version and report_type from the file:"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print({k:d[k] for k in ('schema_version','report_type')})" "$WORK/report-a.json"

step "7. Fail closed: refusing to overwrite an existing report"
run "$BIN" analyze "${ARGS[@]}" --format json --output "$WORK/report-a.json"

step "8. Inspect the saved report"
echo "inspect reads a caller-supplied file. It does not authenticate it or recompute the forecast."
run "$BIN" inspect --report "$WORK/report-a.json"

step "9. Inspect a doctored report"
echo "The evidence classification below was edited by hand to COMPLETE_AUTHORITATIVE_LEDGER."
python3 - "$WORK/report-a.json" "$WORK/doctored.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["evidence"]["evidence_classification"] = "COMPLETE_AUTHORITATIVE_LEDGER"
d["evidence"]["limitations"] = []
json.dump(d, open(sys.argv[2], "w"))
PY
run "$BIN" inspect --report "$WORK/doctored.json"

step "10. Fail closed: unsupported protocol version"
echo "The snapshot's protocol_version is set to 30, outside the reviewed range 18 to 29."
python3 - "$SNAPSHOT" "$WORK/protocol30.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
d["protocol_version"] = 30
json.dump(d, open(sys.argv[2], "w"))
PY
P30=("${ARGS[@]}")
P30[1]="$WORK/protocol30.json"
run "$BIN" analyze "${P30[@]}" --format json --output "$WORK/report-p30.json"
echo "The report written for that run (classification and error only):"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d['forecast']['classification'], [e['message'] for e in d['errors']])" "$WORK/report-p30.json"

step "11. Fail closed: invalid input"
BAD=("${ARGS[@]}")
BAD[7]=not-an-account
echo "A malformed trustor account is rejected before any analysis:"
run "$BIN" analyze "${BAD[@]}"
echo "Live mode refuses a non-Testnet passphrase and a cleartext non-loopback endpoint before any request:"
run "$BIN" live --network-passphrase 'Public Global Stellar Network ; September 2015' --horizon-url https://horizon.example --rpc-url https://rpc.example --operation SetTrustLineFlags --source-account "$ISSUER" --trustor "$TRUSTOR" --asset-code FLUTTER --asset-issuer "$ISSUER" --before-flags 1 --after-flags 0
run "$BIN" live --network-passphrase 'Test SDF Network ; September 2015' --horizon-url http://horizon.example --rpc-url https://rpc.example --operation SetTrustLineFlags --source-account "$ISSUER" --trustor "$TRUSTOR" --asset-code FLUTTER --asset-issuer "$ISSUER" --before-flags 1 --after-flags 0

echo
echo "End of transcript."
