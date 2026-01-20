$fileLocation = "$env:USERPROFILE\Desktop\localGroupsAudit.txt"

net localgroup Administrators | Out-File $fileLocation -Append
Add-Content -Path $fileLocation -Value "`r`n"
net localgroup "Remote Desktop Users" | Out-File $fileLocation -Append
Add-Content -Path $fileLocation -Value "`r`n"
net localgroup "Remote Management Users" | Out-File $fileLocation -Append