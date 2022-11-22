#!/bin/bash
echo "Start scanning scope $1..."
rm scope_tmp.txt
nmap -sP -n $1 > scope_tmp.txt 
echo "Found hosts:"
cat scope_tmp.txt | grep for | cut -d ' ' -f 5 > no_scanned_ip.txt
cat no_scanned_ip.txt
  
rm scope_tmp.txt
echo "File for scanning was created. Use multiscan."
