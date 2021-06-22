#!/bin/bash

bdir=$(readlink -f $(dirname $0))
ldir=$(readlink -f $(dirname $(find -name "librte_ethdev.so.20.0" | head -1)))

# Start DPDK as sudo with a custom library path (GDB)
if [[ $# -gt 0 && $1 -eq gdb ]]; then
    sudo LD_LIBRARY_PATH=$ldir gdb --args $bdir/bin/client.exe "${@:2}"
    exit 0
fi

# Start DPDK as sudo with a custom library path
sudo LD_LIBRARY_PATH=$ldir $bdir/bin/client.exe "$@"

