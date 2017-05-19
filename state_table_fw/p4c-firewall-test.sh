#!/bin/bash
echo ' '
echo '============================================================= '
echo                Starting Test for P4/C Firewall
echo '============================================================= '
echo ' '

tcpdump -U -i $1 2>/dev/null &
sleep 1
tcpreplay -i $2 drop.pcap > /dev/null
echo 'This packet should Drop'
pid=$(ps -e | pgrep tcpdump)
sleep 1
kill -2 $pid

echo ' '
echo '------------------------------------------------------------- '
echo ' '

tcpdump -U -i $2 2>/dev/null &
sleep 1 
tcpreplay -i $1 out.pcap > /dev/null
echo 'This packet should Forward'
echo 'The output should be: 111.111.111.111.1025 > 192.168.0.10:4000'
pid=$(ps -e | pgrep tcpdump)
sleep 1
kill -2 $pid

echo ' '
echo '------------------------------------------------------------- '
echo ' '

tcpdump -U -i $1 2>/dev/null &
sleep 1
tcpreplay -i $2 in.pcap > /dev/null
echo 'This packet should Forward'
echo 'The output should be: 192.168.0.10:4000 > 10.0.0.1:3000'
pid=$(ps -e | pgrep tcpdump)
sleep 1
kill -2 $pid

echo ' '
echo '------------------------------------------------------------- '
echo ' '

