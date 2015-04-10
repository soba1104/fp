#!/bin/sh

cd src/ss && cmake . && make install
cmake .
make
