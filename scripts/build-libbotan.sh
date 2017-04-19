#!/bin/bash
set -eu

if [ ! -e "$HOME/builds/libbotan/libbotan-2.so" ]; then
  git clone https://github.com/randombit/botan ~/builds/libbotan
  cd ~/builds/libbotan
  ./configure.py
  make libs
fi

