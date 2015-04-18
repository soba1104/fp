#!/bin/sh

cd src/ss && cmake . && make install
cd ../../
cmake .
make
