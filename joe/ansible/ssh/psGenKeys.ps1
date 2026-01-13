# 1. Get the directory where the script is located
# $PSScriptRoot is a built-in variable that points to the script's folder
$ScriptDir = $PSScriptRoot

# If running line-by-line in a console, $PSScriptRoot might be empty
if (-not $ScriptDir) {
    $ScriptDir = Get-Location
}

# 2. Define the target path for the private key
$TargetFile = Join-Path -Path $ScriptDir -ChildPath "id_rsa"

# 3. Check if the key already exists
if (Test-Path $TargetFile) {
    Write-Error "Error: $TargetFile already exists. Aborting to prevent overwrite."
    exit 1
}

# 4. Generate the RSA key pair
# -t rsa: Key type
# -b 4096: Bit length
# -f: Output file path
# -N '""': Set an empty passphrase
# Note: We use -N '""' to ensure the empty string is passed correctly to the executable
ssh-keygen -t rsa -b 4096 -f $TargetFile -N '""'

# 5. Confirm completion
if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully generated keys in: $ScriptDir" -ForegroundColor Green
    Write-Host "Private key: $TargetFile"
    Write-Host "Public key:  $TargetFile.pub"
} else {
    Write-Error "An error occurred during key generation."
    exit 1
}