#!/bin/sh
set -eu

kernel_release=${1:-${KVERSION:-$(uname -r)}}
kernel_major=${kernel_release%%.*}
kernel_tail=${kernel_release#*.}
kernel_minor=${kernel_tail%%[!0-9]*}

case "$kernel_major:$kernel_minor" in
  *[!0-9:]*|:|*:)
    echo "xt_banset: cannot parse kernel release '$kernel_release'" >&2
    exit 2
    ;;
esac

if [ "$kernel_major" -lt 6 ] || {
     [ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -lt 12 ];
   }; then
  echo "xt_banset: Linux 6.12 or newer is required (found $kernel_release)" >&2
  exit 1
fi
