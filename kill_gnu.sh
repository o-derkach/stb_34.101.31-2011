#!/bin/bash
#ps ax -o pid= -o comm | grep gnuplot
#RES=$?
for p in $(ps ax -o pid= -o comm | grep gnuplot)
do
	if [[ $p != "gnuplot" ]]; then
		kill -15 $p
	fi
done
