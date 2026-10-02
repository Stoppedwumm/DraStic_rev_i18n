#!/bin/sh
# Builds a second copy of the APK that installs next to the normal one
# (package com.dsemu.drastic.p2, label "DraStic P2"), for testing local
# multiplayer with two DraStic instances on one device.
#
# Usage (from the repo root): ./wfc/make_p2.sh path/to/apktool.jar path/to/uber-apk-signer.jar
# Output: drastic_p2-aligned-debugSigned.apk
set -e

APKTOOL=${1:?usage: $0 apktool.jar uber-apk-signer.jar}
SIGNER=${2:?usage: $0 apktool.jar uber-apk-signer.jar}
PKG=com.dsemu.drastic.p2
WORK=build_p2

rm -rf "$WORK"
cp -R universal "$WORK"
rm -rf "$WORK/build"

# New application id; class names stay com.dsemu.drastic.*.
# (apktool.yml has CRLF line endings; this form works with GNU and BSD sed.)
sed -i.bak "/^packageInfo:/a\\
\  renameManifestPackage: $PKG
" "$WORK/apktool.yml"

# Provider authorities must be unique per installed app.
sed -i.bak "s/android:authorities=\"com\.dsemu\.drastic\./android:authorities=\"$PKG./g" \
    "$WORK/AndroidManifest.xml"

# Distinguishable name in the launcher.
sed -i.bak 's|<string name="app_name">\([^<]*\)</string>|<string name="app_name">\1 P2</string>|' \
    "$WORK/res/values/strings.xml"
find "$WORK" -name '*.bak' -delete

java -jar "$APKTOOL" b -o drastic_p2.apk "$WORK"
java -jar "$SIGNER" --apks drastic_p2.apk
rm -rf "$WORK"
echo "built drastic_p2-aligned-debugSigned.apk"
