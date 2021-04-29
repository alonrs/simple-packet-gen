#!/bin/bash

echo "Caching sudo..."
sudo whoami &>/dev/null

echo "Loading igb_uio module..."
sudo modprobe uio
sudo modprobe igb_uio

echo "Fetching NIC status..."

dpdk_driver=igb_uio

devbind="./dpdk/usertools/dpdk-devbind.py"
devs=$($devbind --status-dev net)
pci=$(echo "$devs" | grep -P "^0000:")

pci_kernel=($(echo "$pci" | grep -vF "drv=$dpdk_driver" | cut -d" " -f1))
pci_dpdk=($(echo "$pci" | grep "drv=$dpdk_driver" | cut -d" " -f1))

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
            cmd="sudo $devbind -b $dpdk_driver ${pci_kernel[x]}"
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
            cmd="sudo $devbind -b $kernel_driver ${pci_dpdk[x]}"
            echo $cmd
            eval $cmd
    done

fi

