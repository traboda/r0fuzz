#!/bin/bash

while :
do
	#pkill -9 server	
	#./server
	./server || {
		sleep 2
	    # executes this block of code when:     $? -ne 0
	    # and nothing if the command succeeds:  $? -eq 0
	}

done
