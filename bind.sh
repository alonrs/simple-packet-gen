#!/bin/bash

# Must run this as root
[[ $EUID -ne 0 ]] && \
    echo "Please run me as root." && \
    exit 1

# Load DPDK drivers
modprobe uio
dpdk_drivers="igb_uio uio_pci_generic"
dpdk_driver=
for driver in $dpdk_drivers; do
    echo -n "Trying to load DPDK driver '$driver'... "
    if modprobe $driver &>/dev/null; then
        dpdk_driver=$driver
        echo "okay"
        break
    fi
    echo "error"
done
if [[ -z $dpdk_driver ]]; then
    echo "Error - cannot load any DPDK driver."
    exit 1
fi

echo "Fetching NIC status..."

base=$(readlink -f $(dirname $0))
devbind="$base/dpdk/usertools/dpdk-devbind.py"
devs=$($devbind --status-dev net)
pci=$(echo "$devs" | grep -P "^0000:")

pci_kernel=($(echo "$pci" | grep -vF "drv=$dpdk_driver" | cut -d" " -f1))
pci_dpdk=($(echo "$pci" | grep "drv=$dpdk_driver" | cut -d" " -f1))

# In case there are arguments, bind them to DPDK
if [[ $# -gt 0 ]]; then
    for pci in $@; do
        cmd="$devbind -b $dpdk_driver $pci"
        echo $cmd
        eval $cmd 2>/dev/null
    done
    exit 0
fi


echo "$devs"
echo

read -p "Do you wish to bind devices to DPDK? [Y|n] " ans

# Configure DPDK devices
if [[ -z $ans || $ans =~ [yY] ]]; then

    echo "Select which devices to bind to the DPDK driver (e.g., 1 3)"
    for (( i=0; i<${#pci_kernel[@]}; i++ )); do
        echo " $i: ${pci_kernel[i]}"
    done
    
    read -p "> " ans
    for x in $ans; do
            cmd="$devbind -b $dpdk_driver ${pci_kernel[x]}"
            echo $cmd
            eval $cmd
    done

# Configure Kernel devices
else
    echo "Select which devices to bind to the Kernel driver (e.g., 1 3)"
    for (( i=0; i<${#pci_dpdk[@]}; i++ )); do
        echo " $i: ${pci_dpdk[i]}"
    done
    read -p "> " ans

    read -p "Enter the Kernel driver name: " kernel_driver

    for x in $ans; do
            cmd="$devbind -b $kernel_driver ${pci_dpdk[x]}"
            echo $cmd
            eval $cmd
    done

fi

