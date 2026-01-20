Import Active Directory module
Import-Module ActiveDirectory

# Retrieve all users in the domain
$users = Get-ADUser -Filter * -Property *

# Loop through each user
foreach ($user in $users) {
    try {
        # Prompt user to change their password
        Write-Host "Changing password for user: $($user.SamAccountName)"
        
        # Prompt for a new password (this is just an example, customize as needed)
        $newPassword = Read-Host -AsSecureString "Enter new password for $($user.SamAccountName)"
              
        # Set "Do not require Kerberos preauthentication" to false (this will enable Kerberos preauthentication)
        Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $false
        
        # Set "User Cannot Change Password" to True
        Set-ADUser -Identity $user.SamAccountName -CannotChangePassword $true

        #Disable store password using reversible encryption
        Set-ADAccountControl -Identity $user -AllowReversiblePasswordEncryption $false

        # Change the user's password
        Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $newPassword -Reset
        
        Write-Host "Password changed and attributes updated for $($user.SamAccountName)"
    }
    catch {
        Write-Host "Error processing user $($user.SamAccountName): $_"
        # Script will continue to the next user even after an error
    }