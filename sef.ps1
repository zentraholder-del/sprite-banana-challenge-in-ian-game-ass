cd "C:\Users\ducky6163\Downloads\ian obliterator"

$folders = Get-ChildItem -Path "games" -Directory

foreach ($folder in $folders) {
    $folderPath = "games/$($folder.Name)"
    Write-Host "`n=== Adding $folderPath ===" -ForegroundColor Cyan

    git add $folderPath
    git commit -m "add $($folder.Name)"
    
    $pushSuccess = $false
    $attempts = 0
    while (-not $pushSuccess -and $attempts -lt 3) {
        $attempts++
        Write-Host "Pushing $folderPath (attempt $attempts)..." -ForegroundColor Yellow
        git push origin main
        if ($LASTEXITCODE -eq 0) {
            $pushSuccess = $true
            Write-Host "SUCCESS: $folderPath" -ForegroundColor Green
        } else {
            Write-Host "FAILED: $folderPath, retrying..." -ForegroundColor Red
            Start-Sleep -Seconds 5
        }
    }

    if (-not $pushSuccess) {
        Write-Host "GAVE UP on $folderPath after 3 attempts. Check manually." -ForegroundColor Red
    }
}

# Grab any remaining loose files (ads.txt, CNAME, sw.js, etc.)
git add games/*.txt games/*.html games/*.js games/CNAME games/google*.html
git commit -m "add remaining root game files"
git push origin main

Write-Host "`n=== ALL DONE ===" -ForegroundColor Green