# Test Rate Limiting - PowerShell Script
# This script demonstrates the rate limiting functionality implemented in Task 5

Write-Host "`n=== TASK 5: Rate Limiting Test ===" -ForegroundColor Green
Write-Host "This script tests rate limiting on sensitive endpoints`n" -ForegroundColor Yellow

# Test 1: Login Rate Limit (5 requests/minute)
Write-Host "`n--- Test 1: Login Rate Limit (5 attempts/minute) ---" -ForegroundColor Cyan
Write-Host "Attempting 7 login requests (should succeed 5 times, then rate limit)`n"

for ($i = 1; $i -le 7; $i++) {
    Write-Host "Attempt $i..." -NoNewline
    
    $body = @{
        username = "alice"
        password = "wrong$i"
    } | ConvertTo-Json
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/api/auth/login" `
            -Method POST `
            -Headers @{"Content-Type"="application/json"} `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        
        if ($response.StatusCode -eq 401) {
            Write-Host " Failed authentication (expected)" -ForegroundColor Yellow
        } else {
            Write-Host " Response: $($response.StatusCode)" -ForegroundColor Green
        }
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            Write-Host " RATE LIMITED (429 Too Many Requests)" -ForegroundColor Red
        } else {
            Write-Host " Error: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
        }
    }
    
    Start-Sleep -Milliseconds 500
}

# Test 2: Signup Rate Limit (3 requests/minute)
Write-Host "`n--- Test 2: Signup Rate Limit (3 attempts/minute) ---" -ForegroundColor Cyan
Write-Host "Attempting 5 signup requests (should succeed 3 times, then rate limit)`n"

for ($i = 1; $i -le 5; $i++) {
    Write-Host "Attempt $i..." -NoNewline
    
    $body = @{
        username = "testuser$i"
        password = "testpass123"
        email = "test$i@example.com"
    } | ConvertTo-Json
    
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080/api/auth/signup" `
            -Method POST `
            -Headers @{"Content-Type"="application/json"} `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction SilentlyContinue
        
        Write-Host " Created (200 OK)" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 429) {
            Write-Host " RATE LIMITED (429 Too Many Requests)" -ForegroundColor Red
        } elseif ($_.Exception.Response.StatusCode.value__ -eq 400) {
            Write-Host " Already exists (400 Bad Request)" -ForegroundColor Yellow
        } else {
            Write-Host " Error: $($_.Exception.Response.StatusCode)" -ForegroundColor Yellow
        }
    }
    
    Start-Sleep -Milliseconds 500
}

# Test 3: Verify rate limit resets after time
Write-Host "`n--- Test 3: Rate Limit Reset ---" -ForegroundColor Cyan
Write-Host "Waiting 60 seconds for rate limit to reset..." -ForegroundColor Yellow
Write-Host "(Press Ctrl+C to skip)" -ForegroundColor Gray

# Countdown timer
for ($i = 60; $i -ge 1; $i--) {
    Write-Host "`rTime remaining: $i seconds " -NoNewline -ForegroundColor Yellow
    Start-Sleep -Seconds 1
}

Write-Host "`n`nAttempting login after reset..." -NoNewline

$body = @{
    username = "alice"
    password = "alice123"
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Uri "http://localhost:8080/api/auth/login" `
        -Method POST `
        -Headers @{"Content-Type"="application/json"} `
        -Body $body `
        -UseBasicParsing
    
    Write-Host " SUCCESS (200 OK)" -ForegroundColor Green
    Write-Host "Rate limit successfully reset!" -ForegroundColor Green
} catch {
    Write-Host " Failed: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
}

Write-Host "`n=== Rate Limiting Tests Completed ===" -ForegroundColor Green
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "- Login endpoint: Limited to 5 requests/minute" -ForegroundColor White
Write-Host "- Signup endpoint: Limited to 3 requests/minute" -ForegroundColor White
Write-Host "- Rate limits reset after 60 seconds" -ForegroundColor White
Write-Host "- Returns HTTP 429 (Too Many Requests) when exceeded`n" -ForegroundColor White
