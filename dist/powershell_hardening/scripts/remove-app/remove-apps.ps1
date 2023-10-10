$appsToRemove = $args[0] -split ','

foreach ($App in $AppsToRemove) {
    Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue
}

Write-Output "success"


