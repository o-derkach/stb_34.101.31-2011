#!/bin/bash
ls cmake &> /dev/null
RES=$?
if [[ $RES != 0 ]]; then
	mkdir cmake
fi
cd cmake
rm -rf *
cmake ..
make
RES=$?
if [[ $RES != 0 ]]; then
	echo -e "\e[1;31merror occur"
else
	echo -e "\e[1;31mYou can find your binary in $(pwd)"
fi
