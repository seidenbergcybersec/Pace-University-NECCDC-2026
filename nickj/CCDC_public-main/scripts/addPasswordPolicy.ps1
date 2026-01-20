Import-Module ActiveDirectory

# Function to set password policy
function Set-ADPasswordPolicy {
    param (
        [string]$DomainController = (Get-ADDomain).DNSRoot,
        [int]$MinPasswordLength = 10,
        [int]$PasswordHistoryCount = 6,
        [int]$MaxPasswordAge = 60,
        [int]$MinPasswordAge = 15
        )
    try {
        # Get the default domain policy
        $DefaultDomainPolicy = Get-ADDefaultDomainPasswordPolicy -Server $DomainController

        # Set the password policy parameters
        Set-ADDefaultDomainPasswordPolicy -Identity $DefaultDomainPolicy -Server $DomainController `
            -MinPasswordLength $MinPasswordLength `
            -PasswordHistoryCount $PasswordHistoryCount `
            -MaxPasswordAge (New-TimeSpan -Days $MaxPasswordAge) `
            -MinPasswordAge (New-TimeSpan -Days $MinPasswordAge) `
            -ComplexityEnabled $true `
            -ReversibleEncryptionEnabled $false

        Write-Host "Password policy updated successfully:" -ForegroundColor Green
        Write-Host "- Minimum Password Length: $MinPasswordLength characters" -ForegroundColor Cyan
        Write-Host "- Password History: Last $PasswordHistoryCount passwords remembered" -ForegroundColor Cyan
        Write-Host "- Maximum Password Age: $MaxPasswordAge days" -ForegroundColor Cyan
        Write-Host "- Minimum Password Age: $MinPasswordAge days" -ForegroundColor Cyan
    }
    catch {
        Write-Host "Error updating password policy: $_" -ForegroundColor Red
    }
}

# Execute the password policy configuration
Set-ADPasswordPolicy
