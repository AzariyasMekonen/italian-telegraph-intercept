#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

echo "============================================================"
echo " [1/3] Direct Python Dynamic File Generation Test"
echo "============================================================"
OUT_DIR="$HERE/test_output"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

TEST_FLAG="AdwaCTF{DYNAMIC_PCAP_TEST_$RANDOM}"
FLAG="$TEST_FLAG" USER_ID="operative_alula_1896" OUTPUT_DIR="$OUT_DIR" OUTPUT_FILENAME="intercept.pcap" python3 src/generate.py

if [ ! -s "$OUT_DIR/intercept.pcap" ]; then
    echo "[-] ERROR: intercept.pcap was not generated or is empty"
    exit 1
fi

if [ ! -s "$OUT_DIR/wiretap_log.txt" ]; then
    echo "[-] ERROR: wiretap_log.txt was not generated or is empty"
    exit 1
fi

echo "[+] Verifying generated file with solver..."
SOLVED_FLAG=$(python3 solve/solve.py "$OUT_DIR/intercept.pcap" | grep -o "AdwaCTF{[^}]*}")
if [ "$SOLVED_FLAG" != "$TEST_FLAG" ]; then
    echo "[-] ERROR: Flag mismatch in direct Python run. Expected $TEST_FLAG, got $SOLVED_FLAG"
    exit 1
fi
echo "SUCCESS: Python dynamic generator verified: $SOLVED_FLAG"

echo ""
echo "============================================================"
echo " [2/3] Container Engine Verification (Podman / Docker)"
echo "============================================================"

CONTAINER_CMD=""
if command -v podman &>/dev/null; then
    CONTAINER_CMD="podman"
elif command -v docker &>/dev/null; then
    CONTAINER_CMD="docker"
else
    echo "[!] Neither podman nor docker found. Skipping container test."
    rm -rf "$OUT_DIR"
    exit 0
fi

IMAGE_TAG="adwactf/italian-telegraph-intercept-generator:latest"
echo "[+] Building container with $CONTAINER_CMD..."
$CONTAINER_CMD build -t "$IMAGE_TAG" -f Dockerfile .

rm -rf "$OUT_DIR"/*
CONTAINER_FLAG="AdwaCTF{CONTAINER_TELEGRAPH_PASSED_1896}"

echo "[+] Running container with dynamic FLAG=$CONTAINER_FLAG..."
$CONTAINER_CMD run --rm \
    -e FLAG="$CONTAINER_FLAG" \
    -e USER_ID="participant_test_telegraph" \
    -e OUTPUT_FILENAME="intercept.pcap" \
    -v "$OUT_DIR:/output:Z" \
    "$IMAGE_TAG"

echo ""
echo "============================================================"
echo " [3/3] Verifying Container Output File"
echo "============================================================"
if [ ! -s "$OUT_DIR/intercept.pcap" ]; then
    echo "[-] ERROR: Container did not generate intercept.pcap"
    exit 1
fi

CONTAINER_SOLVED_FLAG=$(python3 solve/solve.py "$OUT_DIR/intercept.pcap" | grep -o "AdwaCTF{[^}]*}")
if [ "$CONTAINER_SOLVED_FLAG" != "$CONTAINER_FLAG" ]; then
    echo "[-] ERROR: Container flag mismatch! Expected $CONTAINER_FLAG, got $CONTAINER_SOLVED_FLAG"
    exit 1
fi

echo "SUCCESS: Container generated file verified! Flag: $CONTAINER_SOLVED_FLAG"
rm -rf "$OUT_DIR"
echo "[+] All tests passed successfully."
