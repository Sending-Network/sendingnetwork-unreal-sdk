#! /bin/bash

cd /build/libkazv
mkdir -p build && cd build

CC=gcc-9 CXX=g++-9 cmake .. -DCMAKE_INSTALL_PREFIX=/opt/libkazv -DCMAKE_PREFIX_PATH=/opt/libkazv-deps -DCMAKE_BUILD_TYPE=Debug -Dlibkazv_BUILD_TESTS=OFF -Dlibkazv_BUILD_EXAMPLES=ON -Dlibkazv_BUILD_KAZVJOB=ON

make -j4
make -j4 install
