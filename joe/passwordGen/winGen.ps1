param(
    [string]$Wordlist = "$PSScriptRoot/wordlist.txt",
    [int]$NumWords = 3
)

# Helper function for cryptographically secure random numbers
function Get-SecureRandomFixed([int]$Max) {
    if ($Max -le 0) { return 0 }
    $bytes = New-Object Byte[] 4
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $val = [BitConverter]::ToUInt32($bytes, 0)
    return $val % $Max
}

# Helper for random number 0-999
function Get-999 {
    return Get-SecureRandomFixed 1000
}

# Check if wordlist exists
if (-not (Test-Path $Wordlist)) {
    Write-Error "Wordlist not found at $Wordlist"
    exit 1
}

# 1. Select random words and capitalize the first letter
$allWords = Get-Content $Wordlist
$selectedWords = $allWords | Get-Random -Count $NumWords | ForEach-Object {
    if ($_.Length -gt 0) {
        $_.Substring(0,1).ToUpper() + $_.Substring(1)
    } else { $_ }
}

$separators = "!", "@", "#", "$", "%", "^", "&", "*", "-", "_", "+", "=", ":"
# 2. Pick separator using secure random
$sepIdx = Get-SecureRandomFixed $separators.Count
$sep = $separators[$sepIdx]

# 3. Start with random number
$finalPassword = "$(Get-999)"

foreach ($word in $selectedWords) {
    $randNum = Get-999
    # 4. Flip a coin using secure random for placement
    if ((Get-SecureRandomFixed 2) -eq 0) {
        $finalPassword += "${word}${randNum}${sep}"
    }
    else {
        $finalPassword += "${word}${sep}${randNum}"
    }
}

# 5. End with random number
$finalPassword += "$(Get-999)"

Write-Output $finalPassword