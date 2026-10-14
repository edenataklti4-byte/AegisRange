#!/bin/bash
mkdir -p evidence/linux
ssh   ciel@172.16.134.132 "  cat /var/log/auth.log" > evidence/linux/auth.log
echo "Linux evidence collected: evidence/linux/auth.log"
