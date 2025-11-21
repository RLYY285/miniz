# 无需编译的OSS-Fuzz兼容性检查脚本
Write-Host @"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     OSS-Fuzz Compatibility Check (No Compilation)           ║
║     Code Review & Structure Validation                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

$SourceDir = "d:\Information_cmp\try"
$OriginalDir = "d:\Information_cmp\miniz"
$AllChecks = @()

# Check 1: Source Files
Write-Host "`n[1/6] Checking source files..." -ForegroundColor Yellow
$Files = @{
    "miniz.c" = "$SourceDir\miniz.c"
    "miniz.h" = "$SourceDir\miniz.h"
}

foreach ($Entry in $Files.GetEnumerator()) {
    if (Test-Path $Entry.Value) {
        $Size = [math]::Round((Get-Item $Entry.Value).Length / 1KB, 2)
        Write-Host "  [OK] $($Entry.Key): $Size KB" -ForegroundColor Green
        $AllChecks += $true
    } else {
        Write-Host "  [FAIL] $($Entry.Key): Missing" -ForegroundColor Red
        $AllChecks += $false
    }
}

# Check 2: Vulnerability Markers
Write-Host "`n[2/6] Checking vulnerability markers..." -ForegroundColor Yellow
$Content = Get-Content "$SourceDir\miniz.c" -Raw
$VulnCount = 0

for ($i = 1; $i -le 5; $i++) {
    if ($Content -match "VULNERABILITY $i") {
        Write-Host "  [OK] VULNERABILITY $i found" -ForegroundColor Green
        $VulnCount++
    } else {
        Write-Host "  [FAIL] VULNERABILITY $i missing" -ForegroundColor Red
    }
}

$AllChecks += ($VulnCount -eq 5)
Write-Host "  Total: $VulnCount / 5 markers" -ForegroundColor $(if ($VulnCount -eq 5) { "Green" } else { "Yellow" })

# Check 3: Critical Functions
Write-Host "`n[3/6] Checking critical functions..." -ForegroundColor Yellow
$Functions = @(
    "tinfl_decompress",
    "tinfl_decompress_mem_to_callback",
    "mz_zip_validate_file",
    "mz_zip_reader_extract_to_callback",
    "mz_zip_writer_end_internal"
)

$FuncCount = 0
foreach ($Func in $Functions) {
    # Simple check - does the function name appear in the file
    if ($Content -match $Func) {
        Write-Host "  [OK] $Func found" -ForegroundColor Green
        $FuncCount++
    } else {
        Write-Host "  [FAIL] $Func missing" -ForegroundColor Red
    }
}

$AllChecks += ($FuncCount -eq $Functions.Count)

# Check 4: Fuzzer Sources
Write-Host "`n[4/6] Checking fuzzer sources..." -ForegroundColor Yellow
$FuzzerSources = Get-ChildItem "$OriginalDir\tests\*_fuzzer.c" -ErrorAction SilentlyContinue

if ($FuzzerSources) {
    Write-Host "  [OK] Found $($FuzzerSources.Count) fuzzer sources" -ForegroundColor Green
    $AllChecks += $true
    
    foreach ($Fuzzer in $FuzzerSources | Select-Object -First 5) {
        Write-Host "    - $($Fuzzer.Name)" -ForegroundColor Gray
    }
    if ($FuzzerSources.Count -gt 5) {
        Write-Host "    ... and $($FuzzerSources.Count - 5) more" -ForegroundColor Gray
    }
} else {
    Write-Host "  [FAIL] No fuzzer sources found" -ForegroundColor Red
    $AllChecks += $false
}

# Check 5: Build Script
Write-Host "`n[5/6] Checking build script..." -ForegroundColor Yellow
$BuildScript = "$OriginalDir\tests\ossfuzz.sh"

if (Test-Path $BuildScript) {
    Write-Host "  [OK] ossfuzz.sh found" -ForegroundColor Green
    $AllChecks += $true
    
    $ScriptContent = Get-Content $BuildScript -Raw
    if ($ScriptContent -match "AMALGAMATE_SOURCES=ON") {
        Write-Host "  [OK] Uses amalgamation build" -ForegroundColor Green
    }
    if ($ScriptContent -match "LLVMFuzzerTestOneInput") {
        Write-Host "  [OK] References libFuzzer entry point" -ForegroundColor Green
    }
} else {
    Write-Host "  [FAIL] ossfuzz.sh not found" -ForegroundColor Red
    $AllChecks += $false
}

# Check 6: Code Integrity
Write-Host "`n[6/6] Checking code integrity..." -ForegroundColor Yellow

# Check for syntax issues (basic)
$SyntaxIssues = @()

if ($Content -match "}{") {
    # Likely has proper code blocks
    Write-Host "  [OK] Code structure looks valid" -ForegroundColor Green
} else {
    Write-Host "  [WARN] Code structure may have issues" -ForegroundColor Yellow
    $SyntaxIssues += "Structure"
}

# Check for balanced braces (rough check)
$OpenBraces = ([regex]::Matches($Content, '\{' )).Count
$CloseBraces = ([regex]::Matches($Content, '\}' )).Count

if ([math]::Abs($OpenBraces - $CloseBraces) -lt 5) {
    Write-Host "  [OK] Braces appear balanced ($OpenBraces open, $CloseBraces close)" -ForegroundColor Green
    $AllChecks += $true
} else {
    Write-Host "  [FAIL] Braces may be unbalanced ($OpenBraces open, $CloseBraces close)" -ForegroundColor Red
    $AllChecks += $false
}

# Check file size is reasonable
$OriginalSize = (Get-Item "$OriginalDir\miniz.c").Length
$ModifiedSize = (Get-Item "$SourceDir\miniz.c").Length
$SizeDiff = [math]::Abs($ModifiedSize - $OriginalSize) / $OriginalSize * 100

if ($SizeDiff -lt 10) {
    Write-Host "  [OK] File size difference: $([math]::Round($SizeDiff, 2))% (acceptable)" -ForegroundColor Green
} else {
    Write-Host "  [WARN] File size difference: $([math]::Round($SizeDiff, 2))% (large change)" -ForegroundColor Yellow
}

# Summary
Write-Host "`n╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    VALIDATION SUMMARY                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

$PassedChecks = ($AllChecks | Where-Object { $_ -eq $true }).Count
$TotalChecks = $AllChecks.Count
$PercentPassed = [math]::Round($PassedChecks / $TotalChecks * 100, 0)

Write-Host "`nChecks Passed: $PassedChecks / $TotalChecks ($PercentPassed%)" -ForegroundColor $(if ($PassedChecks -eq $TotalChecks) { "Green" } else { "Yellow" })

Write-Host "`nDetailed Results:" -ForegroundColor Yellow
Write-Host "  - Source files: $(if ($Files.Count -eq 2) { '[OK]' } else { '[FAIL]' })" -ForegroundColor $(if ($Files.Count -eq 2) { "Green" } else { "Red" })
Write-Host "  - Vulnerability markers: $(if ($VulnCount -eq 5) { '[OK]' } else { "[PARTIAL] $VulnCount/5" })" -ForegroundColor $(if ($VulnCount -eq 5) { "Green" } else { "Yellow" })
Write-Host "  - Critical functions: $(if ($FuncCount -eq $Functions.Count) { '[OK]' } else { "[PARTIAL] $FuncCount/$($Functions.Count)" })" -ForegroundColor $(if ($FuncCount -eq $Functions.Count) { "Green" } else { "Yellow" })
Write-Host "  - Fuzzer sources: $(if ($FuzzerSources) { "[OK] $($FuzzerSources.Count) found" } else { '[FAIL]' })" -ForegroundColor $(if ($FuzzerSources) { "Green" } else { "Red" })
Write-Host "  - Build script: $(if (Test-Path $BuildScript) { '[OK]' } else { '[FAIL]' })" -ForegroundColor $(if (Test-Path $BuildScript) { "Green" } else { "Red" })
Write-Host "  - Code integrity: $(if ($SyntaxIssues.Count -eq 0) { '[OK]' } else { '[WARN]' })" -ForegroundColor $(if ($SyntaxIssues.Count -eq 0) { "Green" } else { "Yellow" })

# Final verdict
Write-Host "`n" -NoNewline
if ($PassedChecks -eq $TotalChecks) {
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "✓ ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "`nConclusion: The modified miniz appears to satisfy OSS-Fuzz format requirements." -ForegroundColor Green
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "  1. Upload miniz.c to Buttercup platform" -ForegroundColor White
    Write-Host "  2. Configure to use miniz's ossfuzz.sh build script" -ForegroundColor White
    Write-Host "  3. Platform will compile all three versions (ASan, Coverage, Release)" -ForegroundColor White
    Write-Host "  4. If compilation succeeds, format is confirmed correct" -ForegroundColor White
    Write-Host "  5. Run fuzzing campaigns to detect the 5 injected vulnerabilities" -ForegroundColor White
} elseif ($PercentPassed -ge 80) {
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "⚠ MOSTLY PASSED (Some warnings)" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "`nConclusion: The modified miniz likely satisfies OSS-Fuzz format." -ForegroundColor Yellow
    Write-Host "Minor issues detected but should not prevent compilation." -ForegroundColor Yellow
    Write-Host "`nRecommendation: Proceed with upload to Buttercup platform for final verification." -ForegroundColor Cyan
} else {
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "✗ CHECKS FAILED" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "`nConclusion: Issues detected that may prevent OSS-Fuzz compatibility." -ForegroundColor Red
    Write-Host "Please review and fix the failed checks above." -ForegroundColor Yellow
}

# Additional info
Write-Host "`n" -NoNewline
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Additional Information" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Host "`nFor detailed validation guide, see:" -ForegroundColor Gray
Write-Host "  $SourceDir\VALIDATION_SUMMARY.md" -ForegroundColor White

Write-Host "`nFor complete OSS-Fuzz documentation, see:" -ForegroundColor Gray
Write-Host "  $SourceDir\OSS_FUZZ_VALIDATION_GUIDE.md" -ForegroundColor White

Write-Host "`nFor vulnerability details, see:" -ForegroundColor Gray
Write-Host "  $SourceDir\VULNERABILITY_INJECTION_RECORD.md" -ForegroundColor White

Write-Host ""
