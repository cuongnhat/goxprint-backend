@echo off
echo ====================================
echo Deploying to VPS 103.82.193.18
echo ====================================
echo.

cd /d "%~dp0"

echo [1/3] Uploading server.js...
echo.

scp -o StrictHostKeyChecking=no server.js root@103.82.193.18:/root/goxprint-driver-manager/server.js

if %errorlevel% neq 0 (
    echo ERROR: Upload failed!
    pause
    exit /b 1
)

echo.
echo SUCCESS: File uploaded!
echo.
echo [2/3] Restarting service...
echo.

ssh -o StrictHostKeyChecking=no root@103.82.193.18 "cd /root/goxprint-driver-manager && pm2 restart goxprint-driver-manager"

if %errorlevel% neq 0 (
    echo WARNING: Restart command may have failed, but continuing...
)

echo.
echo [3/3] Verifying deployment...
timeout /t 3 /nobreak > nul

powershell -Command "try { $r = Invoke-RestMethod 'http://103.82.193.18/api/health'; Write-Host 'SUCCESS: Server is Running!' -ForegroundColor Green; Write-Host 'Status:' $r.status; Write-Host 'Version:' $r.version } catch { Write-Host 'WARNING: Health check failed' -ForegroundColor Yellow }"

echo.
echo ====================================
echo Deployment Complete!
echo ====================================
pause
