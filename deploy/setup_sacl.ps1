# setup_sacl.ps1
# Creates restricted folders and applies SACL (Audit Rules) so Event 4663 is generated.
param (
    [string]$InstallDir
)

$policyPath = Join-Path $InstallDir "config\access_policy.json"

if (-not (Test-Path $policyPath)) {
    Write-Host "access_policy.json not found at $policyPath. Skipping SACL setup."
    exit 0
}

$policyData = Get-Content $policyPath | ConvertFrom-Json
$auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Success, Failure")

foreach ($property in $policyData.psobject.properties) {
    # Skip meta keys if any, though our config doesn't have them
    $folderName = $property.Name
    $folderPath = "C:\$folderName"
    
    # 1. Create folder if it doesn't exist
    if (-not (Test-Path $folderPath)) {
        New-Item -ItemType Directory -Path $folderPath -Force | Out-Null
        Write-Host "Created missing folder: $folderPath"
    }

    # 2. Apply SACL
    try {
        $acl = Get-Acl $folderPath -Audit
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $folderPath -AclObject $acl
        Write-Host "Applied SACL to $folderPath"
    } catch {
        Write-Host "Failed to apply SACL to $folderPath : $_"
    }
}
