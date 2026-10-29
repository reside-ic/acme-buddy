#!/bin/sh
set -eu

file="vendor/github.com/docker/docker/pkg/archive/archive_deprecated.go"

sed -i \
  -e 's/func DetectCompression(source \[\]byte) archive\.Compression/func DetectCompression(source []byte) compression.Compression/' \
  -e 's/func Tar(path string, compression archive\.Compression)/func Tar(path string, compression compression.Compression)/' \
  "$file"
