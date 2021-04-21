#!/bin/bash

dpdk_dir=$(readlink -f $(dirname $0))/dpdk
build_dir=$dpdk_dir/build
install_dir=$build_dir/install

# Fetch DPDK repository
if [[ ! -d $dpdk_dir || -z $(ls $dpdk_dir/*) ]]; then
    echo "Fetching DPDK repository from git..."
    git submodule update --init
fi
cd $dpdk_dir

# Create the DPDK build dir
if [[ -d $build_dir ]]; then
    read -p "DPDK build dir exists. Do you want to delete it? [Y|n]" ans
    if [[ -z $ans || $ans =~ [Yy] ]]; then
        rm $build_dir
    fi
fi

echo "Configuring DPDK..."
meson -Dprefix=$install_dir build
cd build

# Make DPDK, install locally
echo "Making DPDK..."
ninja
ninja install

