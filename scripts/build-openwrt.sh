#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

# Actions checks out this repository. Only SDK/library dependencies are OpenWrt.
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
work_dir="$repo_dir/build-openwrt"
sdk_name="openwrt-sdk-24.10.3-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
sdk_sha="5e189d938c2320c4c86a9565133970436a7ddf684ef8d01ee1c18c561c4ed643"
mkdir -p "$work_dir" "$repo_dir/artifacts/openwrt"
cd "$work_dir"
if [[ ! -f "$sdk_name" ]]; then
    curl --fail --location --retry 3 \
        "https://downloads.openwrt.org/releases/24.10.3/targets/x86/64/$sdk_name" -o "$sdk_name"
fi
printf '%s  %s\n' "$sdk_sha" "$sdk_name" | sha256sum --check --strict
if [[ -e sdk ]]; then
    echo "Refusing to overwrite existing $work_dir/sdk; use a clean build directory." >&2
    exit 1
fi
mkdir sdk
tar --zstd -xf "$sdk_name" -C sdk --strip-components=1

# Host compiler creates the embedded BPF object; runtime needs no clang/bpftool.
clang -O2 -g -Wall -Werror -target bpf \
    -I"/usr/include/$(gcc -dumpmachine)" \
    -c "$repo_dir/src/bpf/pppoe_fastpath.bpf.c" -o pppoe_fastpath.bpf.o
bpftool gen skeleton pppoe_fastpath.bpf.o > pppoe_fastpath.skel.h

package_dir="$work_dir/sdk/package/rp-pppoe-relay-fastpath"
mkdir -p "$package_dir/source"
cp "$repo_dir/openwrt/Makefile" "$package_dir/Makefile"
cp -a "$repo_dir/openwrt/files" "$package_dir/files"
git -C "$repo_dir" archive HEAD src doc | tar -x -C "$package_dir/source"
cp -p pppoe_fastpath.bpf.o pppoe_fastpath.skel.h "$package_dir/source/src/bpf/"

cd sdk
# SDK contains base recipes for libbpf/libelf/zlib. Never install official rp-pppoe.
cat >> .config <<'CONFIG'
CONFIG_PACKAGE_rp-pppoe-relay-fastpath=m
CONFIG_PACKAGE_libbpf=m
CONFIG_PACKAGE_libelf=m
CONFIG_PACKAGE_zlib=m
CONFIG_ALL_NONSHARED=n
CONFIG_ALL_KMODS=n
CONFIG_ALL=n
CONFIG
make defconfig
make package/rp-pppoe-relay-fastpath/compile V=s -j"$(nproc)"
find bin/packages -type f \( -name 'rp-pppoe-relay-fastpath_*.ipk' \
    -o -name 'libbpf*.ipk' -o -name 'libelf*.ipk' -o -name 'zlib*.ipk' \) \
    -exec cp '{}' "$repo_dir/artifacts/openwrt/" \;
compgen -G "$repo_dir/artifacts/openwrt/rp-pppoe-relay-fastpath_*.ipk" > /dev/null
git -C "$repo_dir" rev-parse HEAD > "$repo_dir/artifacts/openwrt/SOURCE_COMMIT"
cd "$repo_dir/artifacts/openwrt"
sha256sum ./*.ipk > SHA256SUMS
