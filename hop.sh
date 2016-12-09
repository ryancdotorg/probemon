#!/bin/sh
while true
do
	iw mon3 set channel 2
	sleep 0.7
	iw mon3 set channel 10
        sleep 0.7
	iw mon3 set channel 3
        sleep 0.7
	iw mon3 set channel 9
        sleep 0.7
	iw mon3 set channel 4
        sleep 0.7
	iw mon3 set channel 8
        sleep 0.7
	iw mon3 set channel 5
        sleep 0.7
	iw mon3 set channel 7
        sleep 0.7
done
