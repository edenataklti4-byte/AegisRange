@echo off
whoami > C:\Users\Public\dropped_artifact.txt
powershell -c "Test-NetConnection -ComputerName 172.16.134.1 -Port 4444"
timeout /t 5
