#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail

# Actions checks out this repository. Only SDK/library dependencies are OpenWrt.
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
series="${1:-24.10}"
case "$series" in
    24.10|24.10.8)
        version=24.10.8
        sdk_name="openwrt-sdk-${version}-x86-64_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
        sdk_sha=ac4a0405d2eea821b06f93c14ba13ffa90ad0457648903df7dde02570027ab21
        base_commit=443ec4032a78cbeb52c5761b7702033904fa6a11
        package_ext=ipk
        ;;
    25.12|25.12.5)
        version=25.12.5
        sdk_name="openwrt-sdk-${version}-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst"
        sdk_sha=0c8df0151a1e88feb7c03d694d61f6a18d51872815b7c811d76e2b77504d5e9c
        base_commit=f5dae5ece4805730c5e2850f8aa84765af2f6b32
        package_ext=apk
        ;;
    *) echo "Usage: $0 [24.10|25.12]" >&2; exit 2 ;;
esac
work_dir="$repo_dir/build-openwrt/$version"
output_dir="$repo_dir/artifacts/openwrt/$version"
mkdir -p "$work_dir" "$output_dir"
cd "$work_dir"
if [[ ! -f "$sdk_name" ]]; then
    curl --fail --location --retry 3 \
        "https://downloads.openwrt.org/releases/$version/targets/x86/64/$sdk_name" -o "$sdk_name"
fi
printf '%s  %s\n' "$sdk_sha" "$sdk_name" | sha256sum --check --strict
if [[ -e sdk ]]; then
    echo "Refusing to overwrite existing $work_dir/sdk; use a clean build directory." >&2
    exit 1
fi
mkdir sdk
tar --zstd -xf "$sdk_name" -C sdk --strip-components=1

# Host compiler creates the embedded BPF object; runtime needs no clang/bpftool.
clang -O2 -g -Wall -Werror -target bpf -mcpu=v3 \
    -I"/usr/include/$(gcc -dumpmachine)" \
    -c "$repo_dir/src/bpf/pppoe_relay.bpf.c" -o pppoe_relay.bpf.o
bpftool gen skeleton pppoe_relay.bpf.o > pppoe_relay.skel.h

package_dir="$work_dir/sdk/package/pppoe-relay-bpf"
mkdir -p "$package_dir/source"
cp "$repo_dir/openwrt/Makefile" "$package_dir/Makefile"
cp -a "$repo_dir/openwrt/files" "$package_dir/files"
mkdir -p "$package_dir/source/src/bpf"
cp "$repo_dir/LICENSE" "$package_dir/source/"
cp "$repo_dir/src/Makefile" "$repo_dir/src/relay_bpf.c" "$package_dir/source/src/"
cp "$repo_dir/src/bpf/pppoe_relay.bpf.c" "$repo_dir/src/bpf/relay_shared.h" "$package_dir/source/src/bpf/"
cp -p pppoe_relay.bpf.o pppoe_relay.skel.h "$package_dir/source/src/bpf/"

cd sdk
# SDK omits some base recipes. Install ONLY the matching release's library
# recipes; relay still comes exclusively from this repository's current source tree.
printf '%s\n' "src-git base https://github.com/openwrt/openwrt.git^$base_commit" > feeds.conf
./scripts/feeds update base
./scripts/feeds install -p base libbpf libelf zlib
cat >> .config <<'CONFIG'
CONFIG_PACKAGE_pppoe-relay-bpf=m
CONFIG_PACKAGE_libbpf=m
CONFIG_PACKAGE_libelf=m
CONFIG_PACKAGE_zlib=m
CONFIG_ALL_NONSHARED=n
CONFIG_ALL_KMODS=n
CONFIG_ALL=n
CONFIG
make defconfig
make package/pppoe-relay-bpf/compile V=s -j"$(nproc)"
mapfile -t packages < <(find bin/packages -type f -name "pppoe-relay-bpf*.$package_ext")
if [[ ${#packages[@]} != 1 ]]; then
    echo "Expected exactly one relay package, found ${#packages[@]}" >&2
    exit 1
fi
cp "${packages[0]}" "$output_dir/pppoe-relay-bpf_1.0.0_openwrt-${version}_x86_64.$package_ext"
git -C "$repo_dir" rev-parse HEAD > "$output_dir/SOURCE_COMMIT"
git -C "$repo_dir" status --short > "$output_dir/SOURCE_WORKTREE"
printf 'OpenWrt=%s\nSDK=%s\nSDK_SHA256=%s\nBASE_COMMIT=%s\n' \
    "$version" "$sdk_name" "$sdk_sha" "$base_commit" > "$output_dir/BUILD_INFO"
cd "$output_dir"
sha256sum ./*.$package_ext > SHA256SUMS
