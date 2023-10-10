# Function to check if a specific registry value exists and has the expected value
function CheckRegistryValue {

    $actualValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue

    if ($actualValue -ne $null -and $actualValue -eq $ExpectedValue) {
        return $true
    } else {
        return $false
    }
}

# Function to check if a specific SMB server configuration is disabled
function CheckSMBServerDisabled {
    $smb1Config = Get-SmbServerConfiguration | Select EnableSMB1Protocol
    $smb2Config = Get-SmbServerConfiguration | Select EnableSMB2Protocol

    if ($smb1Config -eq $false -and $smb2Config -eq $false) {
        return $true
    } else {
        return $false
    }
}

# Function to check if a specific registry value is disabled
function CheckRegistryValueDisabled {
    $actualValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -ErrorAction SilentlyContinue

    if ($actualValue -eq 0) {
        return $true
    } else {
        return $false
    }
}

# Function to check if specific network adapter bindings are disabled
function CheckAdapterBindingsDisabled {
    $bindings = @(
        "ms_lldp",
        "ms_implat",
        "ms_lltdio",
        "ms_server",
        "ms_rspndr",
        "ms_msclient",
        "ms_pacer"
    )

    $disabledBindings = $bindings | Where-Object {
        $binding = $_
        $disabled = $false
        Get-NetAdapterBinding -ComponentID $binding | ForEach-Object {
            if ($_.Enabled -eq $true) {
                $disabled = $false
                return
            }
        }
        if ($disabled) {
            return $binding
        }
    }

    if ($disabledBindings.Count -eq 0) {
        return $true
    } else {
        return $false
    }
}

# Function to check if IPv6 is disabled
function CheckIPv6Disabled {
    $ipv6Disabled = CheckRegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -ExpectedType "Dword" -ExpectedValue 0xFF
    $ipv6Bindings = Get-NetAdapterBinding -ComponentID "ms_tcpip6"

    if ($ipv6Disabled -eq $true -and $ipv6Bindings.Count -eq 0) {
        return $true
    } else {
        return $false
    }
}

# Function to check RDP hardening settings
function CheckRDPHardening {
    $rdpSettings = @(
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fDenyTSConnections"; Value=1 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowToGetHelp"; Value=0 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="fAllowUnsolicited"; Value=0 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Conferencing"; Name="NoRDS"; Value=1 },
        @{ Path="HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Value=1 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="DisablePasswordSaving"; Value=1 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"; Name="CreateEncryptedOnlyTickets"; Value=1 },
        @{ Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS"; Name="AllowRemoteShellAccess"; Value=0 }
    )

    $incorrectSettings = $rdpSettings | Where-Object {
        $setting = $_
        $actualValue = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction SilentlyContinue

        if ($actualValue -eq $null -or $actualValue -ne $setting.Value) {
            return $setting
        }
    }

    if ($incorrectSettings.Count -eq 0) {
        return $true
    } else {
        return $false
    }
}

# Function to check if NetBios is disabled
function CheckNetBiosDisabled {
    $netBiosDisabled = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" | ForEach-Object {
        $netBiosOptions = Get-ItemProperty -Path "$($_.pschildname)" -Name "NetBiosOptions" -ErrorAction SilentlyContinue
        if ($netBiosOptions -ne $null -and $netBiosOptions -eq 2) {
            return $false
        } else {
            return $true
        }
    }

    if ($netBiosDisabled -contains $false) {
        return $false
    } else {
        return $true
    }
}

# Define an array of checks
$checks = @(
    @{ Name = "LLMNR"; Check = { CheckRegistryValueDisabled } },
    @{ Name = "SMB"; Check = { CheckSMBServerDisabled } },
    @{ Name = "AdminShares"; Check = { CheckRegistryValueDisabled } },
    @{ Name = "NetworkAdapters"; Check = { CheckAdapterBindingsDisabled } },
    @{ Name = "IPv6"; Check = { CheckIPv6Disabled } },
    @{ Name = "RDP"; Check = { CheckRDPHardening } },
    @{ Name = "NetBios"; Check = { CheckNetBiosDisabled } }
)

$resultsArray = @()

foreach ($check in $checks) {
    if ($check.Check -eq $false) {
        $resultsArray += "$($check.Name)"
    }
}

if ($resultsArray.Count -eq 0) {
    Write-Output 0
} else {
    Write-Output $resultsArray | ConvertTo-Json
}