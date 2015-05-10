#!/bin/bash
./build.sh $1
RES=$?
if [[ $RES == 0 ]]; then
        ./cmake/main
fi
