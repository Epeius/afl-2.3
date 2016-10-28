#!/bin/bash
# Prepare a clean environment for afl
total=$(ipcs -m | awk 'END{print NR}') 
_index=4
while [ $_index -lt $total ]
do
	shmid=$(ipcs -m | sed -n ''$_index'p' | awk '{print $2}')
	size=$(ipcs -m | sed -n ''$_index'p' | awk '{print $5}')
	if [ $size = 65536 ]
	then
		echo '--------------'
		echo "shmid=$shmid, size=$size"
		echo `ipcrm -m  $shmid`
	fi
	_index=`expr $_index + 1`;
done

exit 
mkdir /tmp/afltestcase
mkdir /tmp/afltracebits

rm -rf /tmp/afltestcase/*
rm -rf /tmp/afltracebits/*

rm -f /tmp/afl_qemu_queue

cp /home/epeius/work/afl-1.96b/tests/plot/aa.jpeg /home/epeius/work/afl-1.96b/tests/seed/aa.jpeg

rm -rf /home/epeius/work/afl-1.96b/tests/output/*
