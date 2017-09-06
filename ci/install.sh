#!/bin/bash
set -eux

: "${CORES:=2}"

# botan
if [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.so" ] && [ ! -e "${BOTAN_INSTALL}/lib/libbotan-2.dylib" ]; then
  git clone https://github.com/randombit/botan "${LOCAL_BUILDS}/botan"
  cd "${LOCAL_BUILDS}/botan"
  ./configure.py --prefix="${BOTAN_INSTALL}"
  make -j${CORES} install
fi

