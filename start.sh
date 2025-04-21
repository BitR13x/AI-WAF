#!/bin/bash

if [ "$1" == "-d" ]; then
  echo "❌ Deleting rules";
  sudo iptables -D INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
  sudo iptables -D INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1
else
  echo "✅ Adding rules";
  sudo iptables -A INPUT -p tcp --dport 80 -j NFQUEUE --queue-num 1
  sudo iptables -A INPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1
fi
