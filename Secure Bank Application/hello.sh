#!/bin/bash

output=0
yes=true

echo "Hello and welcome to the bank application!"

while $yes; do
    echo "If you are already a client and you want to log in, press 'L'."
    echo "If you are a new client and you want to enroll in our bank, press 'E'."
    
    read -r response
    response="${response^^}"  
    
    if [[ $response == "L" ]]; then
        output=1
        unset hello_out   
        export hello_out=$output
        yes=false
    elif [[ $response == "E" ]]; then
        output=2
        unset hello_out   
        export hello_out=$output
        yes=false
    else
        echo "Sorry, wrong operation. You have to press either 'L' or 'E'."
    fi
done

