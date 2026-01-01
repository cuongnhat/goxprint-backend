# Deploy script for goxprint-driver-manager to VPS
# VPS: 103.82.193.18

$VPS_HOST = "103.82.193.18"
$VPS_USER = "root"
$VPS_PASSWORD = "0Wa70Ud6DERwZgfh"
$VPS_PATH = "/root/goxprint-driver-manager"  # Adjust this path if needed

Write-Host "🚀 Deploying goxprint-driver-manager to VPS..." -ForegroundColor Cyan

# Check if plink/pscp exists (PuTTY tools)
$hasPuTTY = (Get-Command plink -ErrorAction SilentlyContinue) -and (Get-Command pscp -ErrorAction SilentlyContinue)

if (-not $hasPuTTY) {
    Write-Host "⚠️  PuTTY tools not found. Using manual commands instead." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Please run these commands manually:" -ForegroundColor Green
    Write-Host ""
    Write-Host "1. Upload server.js:" -ForegroundColor Yellow
    Write-Host "   scp server.js root@103.82.193.18:/root/goxprint-driver-manager/" -ForegroundColor White
    Write-Host ""
    Write-Host "2. SSH and restart:" -ForegroundColor Yellow
    Write-Host "   ssh root@103.82.193.18" -ForegroundColor White
    Write-Host "   Password: 0Wa70Ud6DERwZgfh" -ForegroundColor White
    Write-Host "   cd /root/goxprint-driver-manager" -ForegroundColor White
    Write-Host "   pm2 restart goxprint-driver-manager" -ForegroundColor White
    Write-Host ""
    exit
}

# Step 1: Backup database on VPS
Write-Host "📦 Step 1: Backing up database..." -ForegroundColor Green
$backupCmd = "cd $VPS_PATH && cp data/goxprint.db data/goxprint.db.backup-`$(date +%Y%m%d_%H%M%S) 2>/dev/null || echo 'No DB to backup'"
echo y | plink -pw $VPS_PASSWORD $VPS_USER@$VPS_HOST $backupCmd

# Step 2: Upload server.js
Write-Host "📤 Step 2: Uploading server.js..." -ForegroundColor Green
pscp -pw $VPS_PASSWORD server.js ${VPS_USER}@${VPS_HOST}:${VPS_PATH}/

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Upload failed!" -ForegroundColor Red
    exit 1
}

# Step 3: Restart service
Write-Host "🔄 Step 3: Restarting service..." -ForegroundColor Green
$restartCmd = @"
cd $VPS_PATH
pm2 restart goxprint-driver-manager 2>/dev/null || systemctl restart goxprint-driver-manager 2>/dev/null || (pkill node && nohup npm start > server.log 2>&1 &)
sleep 2
"@
echo y | plink -pw $VPS_PASSWORD $VPS_USER@$VPS_HOST $restartCmd

# Step 4: Verify
Write-Host "✅ Step 4: Verifying deployment..." -ForegroundColor Green
Start-Sleep -Seconds 3

$healthCheck = Invoke-RestMethod -Uri "http://103.82.193.18/api/health" -ErrorAction SilentlyContinue
if ($healthCheck.status -eq "ok") {
    Write-Host "✅ Server is running! Version: $($healthCheck.version)" -ForegroundColor Green
} else {
    Write-Host "⚠️  Health check failed. Please check server logs." -ForegroundColor Yellow
}

# Test pagination
Write-Host ""
Write-Host "🧪 Testing pagination..." -ForegroundColor Cyan
try {
    $testResult = Invoke-RestMethod -Uri "http://103.82.193.18/api/drivers?page=1&per_page=5"
    Write-Host "✅ Pagination works! Total drivers: $($testResult.pagination.total)" -ForegroundColor Green
    Write-Host "✅ Returned: $($testResult.data.Count) drivers" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Pagination test failed: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Deployment complete!" -ForegroundColor Green
