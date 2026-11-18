# Assertion helpers that work the same under Pester 3.4 (shipped with Windows)
# and Pester 5. Each helper throws on failure, which fails the enclosing It.

function Assert-HvLabTrue {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "Expected true: $Message" }
}

function Assert-HvLabEqual {
    param([AllowNull()][object]$Expected, [AllowNull()][object]$Actual, [string]$Message)
    if ($Expected -cne $Actual) { throw "Expected '$Expected', got '$Actual': $Message" }
}

function Assert-HvLabThrow {
    param([scriptblock]$Script, [string]$Message)
    $threw = $false
    try { $null = & $Script } catch { $threw = $true }
    if (-not $threw) { throw "Expected an error: $Message" }
}
