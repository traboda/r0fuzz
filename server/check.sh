#!/bin/bash

while :
do
	x=$(pgrep server)
	if [ -z "$x" ]; then 
		sleep 2
		./server
	fi

done
