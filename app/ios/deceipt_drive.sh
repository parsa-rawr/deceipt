#!/usr/bin/env bash
#
# deceipt_drive.sh — drive the physical iPhone through the Deceipt flows with
# XCUITest, without touching the phone by hand.
#
#   ./ios/deceipt_drive.sh merchant [UDID]
#       Runs the merchant flow on the device and prints the deceipt1: QR payload
#       between QR_PAYLOAD_BEGIN / QR_PAYLOAD_END markers.
#
#   ./ios/deceipt_drive.sh customer "<deceipt1:...>" [UDID]
#       Runs the customer flow on the device with that payload (typically the one
#       captured from the Android merchant). The payload is injected by rewriting
#       the .xctestrun's EnvironmentVariables, which is the only reliable way to
#       pass a value into the XCUITest runner process (a bare KEY=value on the
#       xcodebuild command line does NOT reach it).
#
# NOTE: the merchant payload carries T_BINDING_QR = 300 s, so run `merchant`,
# capture the payload, and run `customer` within ~5 minutes.
#
set -euo pipefail

TEAM="${DEVELOPMENT_TEAM:-DCV47WR2CS}"
DEVICE="${2:-${UDID:-00008150-000D28D002C0C01C}}"   # "Mateo's iPhone" (iPhone 18,3)
CONFIG="${CONFIG:-Debug}"
DERIVED="${DERIVED:-/tmp/deceipt-uitest-dev2}"
WORKSPACE="ios/DeceiptApp.xcworkspace"
SCHEME="DeceiptApp"
ONLY="DeceiptAppUITests/DeceiptUITests"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(dirname "$here")"
cd "$app_dir"

build() {
  xcodebuild build-for-testing \
    -workspace "$WORKSPACE" -scheme "$SCHEME" -configuration "$CONFIG" \
    -destination "id=$DEVICE" -derivedDataPath "$DERIVED" \
    DEVELOPMENT_TEAM="$TEAM" -allowProvisioningUpdates >/dev/null
}

xctestrun() {
  # The device xctestrun for the current OS.
  ls "$DERIVED"/Build/Products/DeceiptApp_iphoneos*.xctestrun | head -1
}

inject_env() {
  # $1 = KEY, $2 = VALUE. Writes the value into the UI test target's
  # EnvironmentVariables AND TestingEnvironmentVariables in the device
  # .xctestrun; `-xctestrun` is then used directly (a `-scheme` run would
  # regenerate the file and discard this edit).
  local key="$1" value="$2" file
  file="$(xctestrun)"
  for dict in "EnvironmentVariables" "TestingEnvironmentVariables"; do
    /usr/libexec/PlistBuddy -c "Set :DeceiptAppUITests:$dict:$key $value" "$file" 2>/dev/null \
      || /usr/libexec/PlistBuddy -c "Add :DeceiptAppUITests:$dict:$key string $value" "$file"
  done
  echo "injected $key into $(basename "$file")"
}

run() {
  local only="$1"
  xcodebuild test-without-building \
    -xctestrun "$(xctestrun)" \
    -destination "id=$DEVICE" \
    -only-testing:"$ONLY/$only" \
    DEVELOPMENT_TEAM="$TEAM" -allowProvisioningUpdates
}

case "${1:-}" in
  merchant)
    echo "== building UI tests for $DEVICE =="; build
    echo "== running merchant flow =="
    run testMerchantPrintsQrPayload 2>&1 | grep -aE "QR_PAYLOAD_BEGIN|QR_PAYLOAD_END|^deceipt1:|Test Case '|passed \(|failed \(|XCTAssert" || true
    ;;
  customer)
    payload="${2:-}"; DEVICE="${3:-${UDID:-00008150-000D28D002C0C01C}}"
    if [[ -z "$payload" ]]; then echo "usage: $0 customer '<deceipt1:...>' [UDID]" >&2; exit 2; fi
    case "$payload" in deceipt1:*) ;; *) echo "payload must start with deceipt1:" >&2; exit 2;; esac
    echo "== building UI tests for $DEVICE =="; build
    # Write the payload file too (belt and braces) and inject it into the runner.
    printf '%s' "$payload" > /tmp/deceipt-qr-payload
    inject_env QR_PAYLOAD "$payload"
    echo "== running customer flow =="
    run testCustomerFlowFromQrPayload 2>&1 | grep -aE "OFFER_CARD|RECEIPT_RESULT|RECEIPT_STATUS|VERIFICATION_PILL|HISTORY_ROW_0|Test Case '|passed \(|failed \(|XCTAssert|offer-card never" || true
    ;;
  *)
    echo "usage: $0 {merchant|customer '<payload>'} [UDID]" >&2
    exit 2
    ;;
esac
