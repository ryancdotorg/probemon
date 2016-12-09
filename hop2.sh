#!/bin/sh
while true
do
	iw mon9 set channel 2
	sleep 0.7
	iw mon9 set channel 10
        sleep 0.7
	iw mon9 set channel 3
        sleep 0.7
	iw mon9 set channel 9
        sleep 0.7
	iw mon9 set channel 5
        sleep 0.7
	iw mon9 set channel 7
        sleep 0.7
done
