$payloadPath = "$env:TEMP\update_service.bat"
Copy-Item "C:\AegisRange\fake_payload.bat" $payloadPath
Start-Process $payloadPath
