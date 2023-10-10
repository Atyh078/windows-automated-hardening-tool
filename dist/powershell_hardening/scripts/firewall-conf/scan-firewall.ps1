$rulesToScan = @()
$missingRules = @()
$programs = @(
    @{Name = "ContactSupport"; Path = "%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe"},
    @{Name = "Cortana"; Path = "%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"},
    @{Name = "FeedbackHub"; Path = "%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x648wekyb3d8bbwe\PilotshubApp.exe"},
    @{Name = "OneNote"; Path = "%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x648wekyb3d8bbwe\onenoteim.exe"},
    @{Name = "Photos"; Path = "%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe"}
)

foreach ($program in $programs) {
    if (Test-Path $program.Path -PathType Leaf) {
        $rulesToScan += $program.Name + "_in"
        $rulesToScan += $program.Name + "_out"
    }
}

$services = @(
    "DiagTrack",
    "RemoteRegistry",
    "RetailDemo",
    "WMPNetworkSvc",
    "WSearch"
)

foreach ($service in $services) {
    $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($serviceStatus -ne $null) {
        $rulesToScan += $service + "_in"
        $rulesToScan += $service + "_out"
    }
}

# Write-Output $rulesToScan | ConvertTo-Json
foreach ($ruleName in $rulesToScan) {
    $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($rule -eq $null -or $rule.Action -ne "Block") {
        $missingRules += $ruleName
    }
}

if ($missingRules.Count -eq 0) {
    Write-Output 0
} else {
    Write-Output $missingRules | ConvertTo-Json
}