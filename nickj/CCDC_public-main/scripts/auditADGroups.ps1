function Check-GroupExists{
    param($groupName)
    try{
        Get-ADGroup $groupName
        return $true
    } catch {
        return $false
    }
}

Write-Host "AD Group Membership Checker"
Write-Host "Type 'exit' to quit the program"
Write-Host "--------------------------"

$fileLocation = "$env:USERPROFILE\Desktop\aDGroupsAudit.txt"
while ($true) {
    $groupName = Read-Host "`nEnter group name to check membership"

    if($groupName -eq "exit") {
    Write-Host "`nExiting program..."
    break
    }

    if (Check-GroupExists $groupName) {
    Write-Host "`nChecking membership for: $groupName"
    Write-Host "--------------------"
    try{
        Get-ADGroupMember $groupName -Recursive |
            Select-Object name,objectClass,distinguishedName |
            Out-File $fileLocation -Append
    } catch {
        Write-Host "Error getting group members: $_" -ForegroundColor Red
    } 
  } else {
    Write-Host "Group '$groupName' not found!"
    }
}

