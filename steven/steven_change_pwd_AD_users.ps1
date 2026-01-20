Import-Module ActiveDirectory
$password = ConvertTo-SecureString -AsPlainText “Over&Caffeinated1Under8Stimulated” -Force 
# List the user names one per line
$users = Get-Content -Path “c:\MyScripts\UserList.txt”
 
ForEach ($user in $users) 
{
    # Set the default password for the current account
    Get-ADUser $user | Set-ADAccountPassword -NewPassword $password -Reset
    
    Get-ADUser $user | Set-AdUser -ChangePasswordAtLogon $false
    
    Write-Host “Password has been reset for the user: $user”
}