# Function to check registry value
function CheckRegistryValue($regPath, $regValueName) {
    $regValue = Get-ItemProperty -Path $regPath -Name $regValueName -ErrorAction SilentlyContinue
    if ($regValue -ne $null) {
        return $regValue.$regValueName
    } else {
        return "Not Found"
    }
}

# Define an array of registry paths and value names
$registryItems = @(
    @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search"; Value = "BingSearchEnabled"; Name = "WebSearch"},
    @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; Value = "AllowTelemetry"; Name = "FeedbackService"},
    @{Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"; Value = "Enabled"; Name = "AdvertisingId"}
)

# Create an array to store the status of each feature
$statusArray = @()

# Check and add the status of each feature to the array
foreach ($item in $registryItems) {
    $status = CheckRegistryValue $item.Path $item.Value
    if ($status -ne 0 -or $status -eq 'Not Found') {
        $statusArray += $item.Name
    }
}

if ($statusArray.Count -eq 0) {
    Write-Output 0
} else {
    Write-Output $statusArray | ConvertTo-Json
}