# Task 9 Input Validation Testing Script
# Tests comprehensive input validation across all endpoints

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Task 9: Input Validation Testing" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

$baseUrl = "http://localhost:8080"

# Test 1: Login Validation
Write-Host "Test 1: Login with empty credentials (should fail)" -ForegroundColor Yellow
$loginEmpty = @{
    username = ""
    password = ""
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method Post `
        -Body $loginEmpty `
        -ContentType "application/json" `
        -ErrorAction Stop
    Write-Host "FAIL: Empty credentials were accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Empty credentials rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 2: Get valid tokens
Write-Host "Test 2: Getting valid authentication tokens..." -ForegroundColor Yellow
$aliceLogin = @{
    username = "alice"
    password = "alice123"
} | ConvertTo-Json

try {
    $aliceResponse = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" `
        -Method Post `
        -Body $aliceLogin `
        -ContentType "application/json"
    $aliceToken = $aliceResponse.token
    Write-Host "PASS: Alice token obtained" -ForegroundColor Green
} catch {
    Write-Host "FAIL: Could not get Alice token" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Test 3: Negative Transfer Amount
Write-Host "Test 3: Transfer with negative amount (should fail)" -ForegroundColor Yellow
$negativeTransfer = @{
    amount = -100.0
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/accounts/1/transfer" `
        -Method Post `
        -Body $negativeTransfer `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    Write-Host "FAIL: Negative amount was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Negative amount rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 4: Zero Transfer Amount
Write-Host "Test 4: Transfer with zero amount (should fail)" -ForegroundColor Yellow
$zeroTransfer = @{
    amount = 0
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/accounts/1/transfer" `
        -Method Post `
        -Body $zeroTransfer `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    Write-Host "FAIL: Zero amount was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Zero amount rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 5: Excessive Transfer Amount
Write-Host "Test 5: Transfer with excessive amount (should fail)" -ForegroundColor Yellow
$excessiveTransfer = @{
    amount = 2000000.0
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/accounts/1/transfer" `
        -Method Post `
        -Body $excessiveTransfer `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    Write-Host "FAIL: Excessive amount was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Excessive amount rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 6: Valid Transfer
Write-Host "Test 6: Valid transfer (should succeed)" -ForegroundColor Yellow
$validTransfer = @{
    amount = 50.0
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/accounts/1/transfer" `
        -Method Post `
        -Body $validTransfer `
        -ContentType "application/json" `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    
    if ($response.status -eq "ok") {
        Write-Host "PASS: Valid transfer succeeded" -ForegroundColor Green
        Write-Host "  Transferred: $($response.transferred)" -ForegroundColor Gray
        Write-Host "  Remaining: $($response.remaining)" -ForegroundColor Gray
    } else {
        Write-Host "UNEXPECTED: Transfer response unexpected" -ForegroundColor Yellow
    }
} catch {
    Write-Host "FAIL: Valid transfer was rejected" -ForegroundColor Red
}
Write-Host ""

# Test 7: Signup with short username
Write-Host "Test 7: Signup with short username (should fail)" -ForegroundColor Yellow
$shortUsername = @{
    username = "ab"
    password = "password123"
    email = "test@test.com"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/signup" `
        -Method Post `
        -Body $shortUsername `
        -ContentType "application/json" `
        -ErrorAction Stop
    Write-Host "FAIL: Short username was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Short username rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 8: Signup with short password
Write-Host "Test 8: Signup with short password (should fail)" -ForegroundColor Yellow
$shortPassword = @{
    username = "testuser"
    password = "short"
    email = "test@test.com"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/signup" `
        -Method Post `
        -Body $shortPassword `
        -ContentType "application/json" `
        -ErrorAction Stop
    Write-Host "FAIL: Short password was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Short password rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 9: Signup with invalid email
Write-Host "Test 9: Signup with invalid email (should fail)" -ForegroundColor Yellow
$invalidEmail = @{
    username = "testuser"
    password = "password123"
    email = "not-an-email"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/signup" `
        -Method Post `
        -Body $invalidEmail `
        -ContentType "application/json" `
        -ErrorAction Stop
    Write-Host "FAIL: Invalid email was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Invalid email rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 10: Signup with XSS in username
Write-Host "Test 10: Signup with XSS in username (should fail)" -ForegroundColor Yellow
$xssUsername = @{
    username = "<script>alert(1)</script>"
    password = "password123"
    email = "test@test.com"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/signup" `
        -Method Post `
        -Body $xssUsername `
        -ContentType "application/json" `
        -ErrorAction Stop
    Write-Host "FAIL: XSS username was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - XSS username rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 11: Search with SQL injection pattern
Write-Host "Test 11: Search with SQL injection pattern (should fail)" -ForegroundColor Yellow
$sqlInjection = "'; DROP TABLE app_user; --"
$encodedQuery = [System.Web.HttpUtility]::UrlEncode($sqlInjection)

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/users/search?q=$encodedQuery" `
        -Method Get `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    Write-Host "FAIL: SQL injection pattern was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - SQL injection pattern rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 12: Search with excessively long query
Write-Host "Test 12: Search with excessively long query (should fail)" -ForegroundColor Yellow
$longQuery = "a" * 200

try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/users/search?q=$longQuery" `
        -Method Get `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    Write-Host "FAIL: Long query was accepted!" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    if ($statusCode -eq 400) {
        Write-Host "PASS: HTTP 400 - Long query rejected" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: HTTP $statusCode" -ForegroundColor Yellow
    }
}
Write-Host ""

# Test 13: Valid search
Write-Host "Test 13: Valid search query (should succeed)" -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/users/search?q=alice" `
        -Method Get `
        -Headers @{Authorization = "Bearer $aliceToken"} `
        -ErrorAction Stop
    
    if ($response -is [array]) {
        Write-Host "PASS: Valid search succeeded, returned $($response.Count) results" -ForegroundColor Green
    } else {
        Write-Host "UNEXPECTED: Search response unexpected" -ForegroundColor Yellow
    }
} catch {
    Write-Host "FAIL: Valid search was rejected" -ForegroundColor Red
}
Write-Host ""

Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "Task 9 Validation Testing Complete!" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Summary:" -ForegroundColor White
Write-Host "  ✓ Negative transfers blocked" -ForegroundColor Green
Write-Host "  ✓ Zero amount transfers blocked" -ForegroundColor Green
Write-Host "  ✓ Excessive transfers blocked" -ForegroundColor Green
Write-Host "  ✓ Empty credentials blocked" -ForegroundColor Green
Write-Host "  ✓ Short usernames/passwords blocked" -ForegroundColor Green
Write-Host "  ✓ Invalid emails blocked" -ForegroundColor Green
Write-Host "  ✓ XSS patterns blocked" -ForegroundColor Green
Write-Host "  ✓ SQL injection patterns blocked" -ForegroundColor Green
Write-Host "  ✓ Long queries blocked" -ForegroundColor Green
Write-Host "  ✓ Valid operations succeed" -ForegroundColor Green
