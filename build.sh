#!/bin/bash

ls cmake &> /dev/null
RES=$?
if [[ $RES != 0 ]]; then
	mkdir cmake
fi
cd cmake
if [[ $1 ]]; then 
	if [[ $1 == "rebuild" ]]; then
		rm -rf *
	fi
fi
cmake ..
make
RES=$?
if [[ $RES != 0 ]]; then
	echo -e "\e[1;31merror occur\e[0m"
else
	echo -e "\e[1;31mYou can find your binary in $(pwd)\e[0m"
fi

exit $RES
