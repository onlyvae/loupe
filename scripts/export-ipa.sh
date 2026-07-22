#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT="${REPO_ROOT}/code/Loupe.xcodeproj"
SCHEME="Loupe"
CONFIGURATION="Release"
OUTPUT_DIR="${REPO_ROOT}/build/ipa"
EXPORT_METHOD="debugging"
TEAM_ID=""
BUNDLE_ID=""
ALLOW_PROVISIONING_UPDATES=false

usage() {
  cat <<'EOF'
Archive Loupe and export a signed IPA.

Usage: scripts/export-ipa.sh [options]

Options:
  --method METHOD       development (default), app-store, ad-hoc, or enterprise
  --output-dir PATH     IPA output directory (default: build/ipa)
  --team-id ID          Override the Apple Developer Team ID
  --bundle-id ID        Override the app bundle identifier
  --allow-provisioning-updates
                        Let Xcode create or download signing assets
  -h, --help            Show this help

Examples:
  scripts/export-ipa.sh
  scripts/export-ipa.sh --method app-store --allow-provisioning-updates
  scripts/export-ipa.sh --team-id ABCDE12345 --bundle-id com.example.loupe
EOF
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --method)
      [[ $# -ge 2 ]] || fail "--method requires a value"
      case "$2" in
        app-store|app-store-connect) EXPORT_METHOD="app-store-connect" ;;
        ad-hoc|release-testing) EXPORT_METHOD="release-testing" ;;
        development|debugging) EXPORT_METHOD="debugging" ;;
        enterprise) EXPORT_METHOD="enterprise" ;;
        *) fail "unsupported export method: $2" ;;
      esac
      shift 2
      ;;
    --output-dir)
      [[ $# -ge 2 ]] || fail "--output-dir requires a value"
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --team-id)
      [[ $# -ge 2 ]] || fail "--team-id requires a value"
      TEAM_ID="$2"
      shift 2
      ;;
    --bundle-id)
      [[ $# -ge 2 ]] || fail "--bundle-id requires a value"
      BUNDLE_ID="$2"
      shift 2
      ;;
    --allow-provisioning-updates)
      ALLOW_PROVISIONING_UPDATES=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

command -v xcodebuild >/dev/null 2>&1 || fail "xcodebuild was not found; install Xcode first"
[[ -d "$PROJECT" ]] || fail "Xcode project not found at $PROJECT"
[[ -z "$TEAM_ID" || "$TEAM_ID" =~ ^[A-Za-z0-9]{10}$ ]] || fail "team ID must contain 10 letters or digits"
[[ -n "$OUTPUT_DIR" ]] || fail "output directory cannot be empty"

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/loupe-ipa.XXXXXX")"
ARCHIVE_PATH="${WORK_DIR}/${SCHEME}.xcarchive"
EXPORT_DIR="${WORK_DIR}/export"
EXPORT_OPTIONS="${WORK_DIR}/ExportOptions.plist"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

cat > "$EXPORT_OPTIONS" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>method</key>
  <string>${EXPORT_METHOD}</string>
  <key>signingStyle</key>
  <string>automatic</string>
  <key>stripSwiftSymbols</key>
  <true/>
  <key>uploadSymbols</key>
  <true/>
  <key>manageAppVersionAndBuildNumber</key>
  <false/>
EOF

if [[ -n "$TEAM_ID" ]]; then
  cat >> "$EXPORT_OPTIONS" <<EOF
  <key>teamID</key>
  <string>${TEAM_ID}</string>
EOF
fi

cat >> "$EXPORT_OPTIONS" <<'EOF'
</dict>
</plist>
EOF

ARCHIVE_ARGS=(
  -project "$PROJECT"
  -scheme "$SCHEME"
  -configuration "$CONFIGURATION"
  -destination "generic/platform=iOS"
  -archivePath "$ARCHIVE_PATH"
  archive
)

EXPORT_ARGS=(
  -exportArchive
  -archivePath "$ARCHIVE_PATH"
  -exportPath "$EXPORT_DIR"
  -exportOptionsPlist "$EXPORT_OPTIONS"
)

if [[ -n "$TEAM_ID" ]]; then
  ARCHIVE_ARGS+=("DEVELOPMENT_TEAM=${TEAM_ID}")
fi

if [[ -n "$BUNDLE_ID" ]]; then
  ARCHIVE_ARGS+=("PRODUCT_BUNDLE_IDENTIFIER=${BUNDLE_ID}" "LOUPE_BUNDLE_ID=${BUNDLE_ID}")
fi

if [[ "$ALLOW_PROVISIONING_UPDATES" == true ]]; then
  ARCHIVE_ARGS+=(-allowProvisioningUpdates)
  EXPORT_ARGS+=(-allowProvisioningUpdates)
fi

printf 'Archiving %s (%s)...\n' "$SCHEME" "$CONFIGURATION"
xcodebuild "${ARCHIVE_ARGS[@]}"

if [[ "$EXPORT_METHOD" == "app-store-connect" ]]; then
  printf '%s\n' 'App Store export requires an Apple Distribution certificate and an App Store provisioning profile.'
  if [[ "$ALLOW_PROVISIONING_UPDATES" == false ]]; then
    printf '%s\n' 'Use --allow-provisioning-updates if Xcode should obtain the profile from your signed-in developer account.'
  fi
fi

printf 'Exporting IPA with method %s...\n' "$EXPORT_METHOD"
xcodebuild "${EXPORT_ARGS[@]}"

IPA_PATH="$(find "$EXPORT_DIR" -maxdepth 1 -type f -name '*.ipa' -print -quit)"
[[ -n "$IPA_PATH" ]] || fail "Xcode completed without producing an IPA"

mkdir -p "$OUTPUT_DIR"
FINAL_IPA="${OUTPUT_DIR}/${SCHEME}.ipa"
FINAL_TIPA="${OUTPUT_DIR}/${SCHEME}.tipa"
cp "$IPA_PATH" "$FINAL_IPA"
cp "$FINAL_IPA" "$FINAL_TIPA"

printf 'IPA exported to %s\n' "$FINAL_IPA"
printf 'TIPA copied to %s\n' "$FINAL_TIPA"
