#!/bin/bash
#if debug arg is passed add build arg

if [ "$1" == "debug" ]; then
    docker build --build-arg BUILD_TYPE=Debug  --build-arg CASH=$(date +%s) -t dangr .
else
    docker build $@ -t dangr . 
fi
