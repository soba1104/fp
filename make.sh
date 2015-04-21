#!/bin/sh

cd src/ss && cmake . && make clean && make && make install
cd ../../
make clean
cmake .
make
