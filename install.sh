#!/bin/bash

g++ --version &> /dev/null
RES=$?
if [[ $RES != 0 ]]; then
	sudo apt-get install g++
fi

cmake --version &> /dev/null
RES=$?
if [[ $RES != 0 ]]; then
	sudo apt-get install cmake
fi

openssl version &> /dev/null
RES=$?
if [[ $RES != 0 ]]; then
	sudo apt-get install libssl-dev
fi
