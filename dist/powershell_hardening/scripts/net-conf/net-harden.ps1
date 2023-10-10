$registryItems = $args[0] -split ','

foreach($registry in $registryItems){
    switch($registry){
        "LLMNR"{
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type DWord -Value 0
        }
        "AdminShares"{
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Type DWord -Value 0
        }
        "NetworkAdapters"{
            Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lldp" # Microsoft LLDP Protocol Driver
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_implat" # Microsoft Network Adapter Multiplexor Protocol
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_lltdio" # Link-Layer Topology Discovery Mapper I/O Driver
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_server" # File and Printer Sharing for Micorsoft Networks
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_rspndr" # Link-Layer Topology Discovery Responder
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_msclient" # Client for Microsft Networks
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_pacer" # QoS a Scheduler
        }
		"IPv6"{
			Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "0xFF" -Type "Dword" # Disables IPv6 completely
			Disable-NetAdapterBinding -Name "*" -ComponentID "ms_tcpip6" # Internet Protocol Version 6 (TCP/IPv6)
		}
		"RDP"{
			# Disable Remote Desktop
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDenyTSConnections" -Type Dword -Value 1

			# Disable Remote Assistance and don't allow unsolicited remote assistance offers
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Type Dword -Value 0
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Type Dword -Value 0
			
			# Disable Remote Desktop Sharing
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Conferencing" -Name "NoRDS" -Type Dword -Value 1
			
			# Disable password saving 
			Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type Dword -Value 1
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "DisablePasswordSaving" -Type Dword -Value 1
			
			# Only connect to same version or higher
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "CreateEncryptedOnlyTickets" -Type Dword -Value 1
			
			# Do not allow Remote Shell Access
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\WinRS" -Name "AllowRemoteShellAccess" -Type Dword -Value 0
		}
		"NetBios"{
			$key = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
			Get-ChildItem $key | ForEach-Object {
				Set-ItemProperty -Path "$key\$($_.pschildname)" -Name NetBiosOptions -Value 2
			}
		}
		"SMB"{
			Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
			Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
			Set-SmbServerConfiguration -EnableSMB2Protocol $false -Force
			Set-ItemProperty -Path "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\" -Name SMBDeviceEnabled -Value 0 -Type Dword
		}
    }
}

Write-Output "success"
