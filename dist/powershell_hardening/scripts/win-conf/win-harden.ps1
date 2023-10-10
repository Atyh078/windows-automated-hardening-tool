$hardenServices = $args[0] -split ','

$automaticUpdatesSettings = Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'"
	foreach ($Service in $hardenServices) {
		if($Service -eq 'Windows Auto Updates'){
			Set-Service -Name 'wuauserv' -StartupType 'Automatic'
		}else{
			Set-Service -Name $Service -StartupType 'Disabled'
			Stop-Service -Name $Service -Force
		}
	}

Write-Output 'success';