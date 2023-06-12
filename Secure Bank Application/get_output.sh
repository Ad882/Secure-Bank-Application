#!/bin/bash

gcc -o hello hello.c
output=$(./hello)

if [ $? -ne 0 ]; then
    echo "Failed to get output from hello program"
    exit 1
fi

export OUTPUT="$output"
