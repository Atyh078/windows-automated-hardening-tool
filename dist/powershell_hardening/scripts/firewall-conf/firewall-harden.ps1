$rulesToAdd = $args[0] -split ','

foreach ($ruleName in $rulesToAdd) {
    $program = ""
    $action = "block"
    $enable = "yes"

	# Determine the direction ("in" or "out") from the rule name
    $dir = if ($ruleName -match "_in$") { "in" } else { "out" }

	switch ($ruleName) {
		"ContactSupport*"{
			$program = "%WINDIR%\SystemApps\ContactSupport_cw5n1h2txyewy\ContactSupport.exe"
		}
		"Cortana*"{
			$program = "%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe"
		}
        "FeedbackHub*"{
            $program = "%ProgramFiles%\WindowsApps\Microsoft.WindowsFeedbackHub_1.1708.2831.0_x64__8wekyb3d8bbwe\PilotshubApp.exe"
        }
        "OneNote*"{
            $program = "%ProgramFiles%\WindowsApps\Microsoft.Office.OneNote_17.8625.21151.0_x64__8wekyb3d8bbwe\onenoteim.exe"
        }
        "Photos*"{
            $program = "%ProgramFiles%\WindowsApps\Microsoft.Windows.Photos_2017.39091.16340.0_x64__8wekyb3d8bbwe\Microsoft.Photos.exe"
        }
        { @("DiagTrack_in","DiagTrack_out","dmwappushservice_in","dmwappushservice_out","RemoteRegistry_in","RemoteRegistry_out","WMPNetworkSvc_in","WMPNetworkSvc_out","WSearch_in","WSearch_out") -contains $_ }{
            $service = $ruleName -replace "_in$|_out$"
        }
    }
	$netshCommand = "netsh advfirewall firewall add rule name='$ruleName' dir=$dir action=$action enable=$enable"

	if ($program) {
        $netshCommand += " program='$program'"
    }
	if ($service) {
        $netshCommand += " service='$service'"
    }

	Invoke-Expression $netshCommand > $null
}

Write-Output "success"