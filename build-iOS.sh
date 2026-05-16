#!/bin/bash

set -e

NAME=unfair
SDK_VERSION=13.0

function build() {
  START=$(date +%s)

  swift build  \
    -c release \
    -Xswiftc "-sdk" \
    -Xswiftc "$(xcrun --sdk iphoneos --show-sdk-path)" \
    -Xswiftc "-target" \
    -Xswiftc "arm64-apple-ios$SDK_VERSION" \
    -Xcc "-arch" \
    -Xcc "arm64" \
    -Xcc "--target=arm64-apple-ios$SDK_VERSION" \
    -Xcc "-isysroot" \
    -Xcc "$(xcrun --sdk iphoneos --show-sdk-path)" \
    -Xcc "-mios-version-min=$SDK_VERSION" \
    -Xcc "-miphoneos-version-min=$SDK_VERSION"

  END=$(date +%s)
  TIME=$(($END - $START))
  echo "build in $TIME seconds"
}

function main() {
  build
}

main

mv .build/release/unfair-swift .
chmod +x unfair-swift
ldid -Sglobal.xml unfair-swift
mv unfair-swift unfair

# if ip is provided, send to the device in one go
if [ -n "$1" ]; then
  scp unfair global.xml root@$1:~/
  ssh root@$1 'LDID=/var/jb/usr/bin/ldid; if [ ! -x "$LDID" ]; then LDID=/usr/bin/ldid; fi; "$LDID" -Sglobal.xml unfair && chmod +x unfair'
fi
