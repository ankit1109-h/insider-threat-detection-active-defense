# setup_rbac_simulation.ps1
# Script to setup local users, folders, NTFS permissions, and audit policies for the Insider Threat simulation

# 1. Create Local Users
$users = @(
    @{ Name = "HR_User"; FullName = "HR Employee"; Description = "Human Resources User" },
    @{ Name = "Finance_User"; FullName = "Finance Employee"; Description = "Finance User" },
    @{ Name = "Engineer_User"; FullName = "Engineering Employee"; Description = "Engineering User" }
)

$Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

foreach ($user in $users) {
    if (-not (Get-LocalUser -Name $user.Name -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $user.Name -Password $Password -FullName $user.FullName -Description $user.Description
        Add-LocalGroupMember -Group "Users" -Member $user.Name
        Write-Host "Created user: $($user.Name)"
    } else {
        Write-Host "User $($user.Name) already exists."
    }
}

# 2. Create Folders
$folders = @(
    "C:\Finance_Data",
    "C:\HR_Records",
    "C:\Engineering_Code",
    "C:\Public_Share"
)

foreach ($folder in $folders) {
    if (-not (Test-Path $folder)) {
        New-Item -ItemType Directory -Path $folder | Out-Null
        Write-Host "Created folder: $folder"
    }
}

# 3. Set basic NTFS Permissions (Simulation of RBAC)
# Disable inheritance (removes default Users access) and explicitly allow specific roles

# Finance Data - only Finance_User
$acl = Get-Acl "C:\Finance_Data"
$acl.SetAccessRuleProtection($true, $false) # Disable inheritance and remove existing inherited rules
$rule_allow = New-Object System.Security.AccessControl.FileSystemAccessRule("Finance_User", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule_allow)
Set-Acl -Path "C:\Finance_Data" -AclObject $acl

# HR Records - only HR_User
$acl = Get-Acl "C:\HR_Records"
$acl.SetAccessRuleProtection($true, $false)
$rule_allow = New-Object System.Security.AccessControl.FileSystemAccessRule("HR_User", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule_allow)
Set-Acl -Path "C:\HR_Records" -AclObject $acl

# Engineering Code - only Engineer_User
$acl = Get-Acl "C:\Engineering_Code"
$acl.SetAccessRuleProtection($true, $false)
$rule_allow = New-Object System.Security.AccessControl.FileSystemAccessRule("Engineer_User", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
$acl.AddAccessRule($rule_allow)
Set-Acl -Path "C:\Engineering_Code" -AclObject $acl

Write-Host "NTFS permissions configured."

# 4. Enable Audit Policies (To generate Event Log 4624, 4656, 4663)
# Enable logon auditing
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
# Enable file system object access auditing
auditpol /set /subcategory:"File System" /success:enable /failure:enable

Write-Host "Audit policies enabled."

# 5. Disable USB Mass Storage (Policy simulation)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name "Start" -Value 4
Write-Host "USB Mass Storage disabled (Start=4)."

# 6. Apply Comprehensive Auditing (SACL) to all folders
$auditFolders = @("C:\Finance_Data", "C:\HR_Records", "C:\Engineering_Code", "C:\Public_Share")
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Success, Failure")

foreach ($folder in $auditFolders) {
    if (Test-Path $folder) {
        $acl = Get-Acl $folder -Audit
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $folder -AclObject $acl
        Write-Host "Applied SACL Auditing (Success/Failure) to $folder"
    }
}

Write-Host "Setup complete."
