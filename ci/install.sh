#!/bin/bash
set -eux

CORES="2" && [ -r /proc/cpuinfo ] && CORES=$(grep -c '^$' /proc/cpuinfo)

# botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ]; then
  git clone https://github.com/randombit/botan ~/builds/botan
  cd ~/builds/botan
  ./configure.py --prefix="${BOTAN_INSTALL}"
  make -j${CORES} install
fi

