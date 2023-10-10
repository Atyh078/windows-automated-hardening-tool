[Array]$Services =
    'lmhosts', 'SEMgrSvc', 'tzautoupdate', 'AppVClient', 'RemoteAccess', 'shpamsvc',
    'UevAgentService', 'WdiServiceHost', 'WdiSystemHost', 'ALG', 'PeerDistSvc', 'Eaphost', 'fdPHost',
    'LxpSvc', 'lltdsvc', 'diagnosticshub.standardcollector.service', 'MSiSCSI', 'WpcMonSvc', 'PNRPsvc',
    'p2psvc', 'p2pimsvc', 'PerfHost', 'pla', 'PNRPAutoReg', 'PrintNotify', 'wercplsupport', 'TroubleshootingSvc',
    'SessionEnv', 'TermService', 'UmRdpService', 'RpcLocator', 'SCPolicySvc', 'SNMPTRAP',
    'SharedRealitySvc', 'WiaRpc', 'VacSvc', 'WalletService', 'wcncsvc', 'Wecsvc', 'perceptionsimulation',
    'WinRM', 'wmiApSrv', 'WwanSvc', 'XblAuthManager', 'XboxNetApiSvc', 'RasAuto', 'XblGameSave',
    'XboxGipSvc', 'PushToInstall', 'spectrum', 'icssvc', 'wisvc', 'WerSvc', 'dmwappushservice', 'FrameServer',
    'WFDSConMgrSvc', 'ScDeviceEnum', 'SCardSvr', 'PhoneSvc', 'IpxlatCfgSvc', 'SharedAccess', 'vmicvss',
    'vmictimesync', 'vmicrdv', 'vmicvmsession', 'vmicheartbeat', 'vmicshutdown', 'vmicguestinterface',
    'vmickvpexchange', 'HvHost', 'FDResPub', 'diagsvc', 'autotimesvc', 'bthserv', 'BTAGService',
    'AssignedAccessManagerSvc', 'AJRouter', 'lfsvc', 'CDPSvc', 'DPS', 'iphlpsvc', 'RasMan',
    'SstpSvc', 'ShellHWDetection', 'SSDPSRV', 'WbioSrvc', 'stisvc', 'MessagingService', 'PcaSvc'

$scannedServices = @()

foreach ($Service in $Services) {
    $status = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($status -and $status.Status -eq "Running") {
        $scannedServices += @{Name = $Service; DisplayName = $status.DisplayName}
    }
}

$automaticUpdatesSettings = Get-WmiObject -Class Win32_Service -Filter "Name='wuauserv'"
if ($automaticUpdatesSettings) {
    if ($automaticUpdatesSettings.StartMode -ne "Auto") {
        $scannedServices += @{Name = "Windows Auto Updates"; DisplayName = "Windows Auto Updates"}
    }
}

if ($scannedServices.Count -eq 0) {
    Write-Output 0
} else {
    Write-Output $scannedServices | ConvertTo-Json
}