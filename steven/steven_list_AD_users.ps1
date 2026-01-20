Import-Module ActiveDirectory
$outputFilePath = “c:\MyScripts\UserList.txt”

# Get all Active Directory users and select their usernames
$usernames = Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName

$usernames | Out-File -FilePath $outputFilePath -Encoding UTF8
Write-Host "Usernames have been successfully exported to: $outputFilePath"