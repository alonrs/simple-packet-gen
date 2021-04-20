#!/bin/bash

dpdk_dir=$(readlink -f $(dirname $0))/dpdk
build_dir=$dpdk_dir/build
install_dir=$build_dir/install

if [[ -f $build_dir ]]; then
    read -p "DPDK build dir exists. Do you want to delete it? [Y|n]" ans
    if [[ -z $ans || $ans =~ [Yy] ]]; then
        rm $build_dir
    fi
fi

git submodule update --init
cd $dpdk_dir

meson -Dprefix=$install_dir build

cd build
ninja
ninja install

