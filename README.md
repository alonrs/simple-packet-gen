# Installation

Configure GIT submodules:
```
git submodule update --init
```

Install DPDK 20.11 (LTS) system-wide:
```
cd dpdk
meson build
cd build
ninja
sudo ninja install
cd ../../
```

Make application:
```
make
```