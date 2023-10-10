$MBSAInstallPath = "C:\MBSA"  # Path to install MBSA if not already installed
$ScanReportPath = "C:\Reports\ScanReport.xml"  # Path to save the scan report

# Check if MBSA is already installed
$MBSAInstalled = Test-Path "$env:ProgramFiles\Microsoft Baseline Security Analyzer"

if (-not $MBSAInstalled) {
    # MBSA not installed, so download and install it
    $DownloadUrl = "https://download.microsoft.com/download/A/4/7/A47B7B0E-976D-4F42-A12A-49743EDF6D00/mbsasetup-x64.msi"
    $InstallerPath = "$MBSAInstallPath\MBSAInstaller.msi"

    # Create the MBSA installation directory
    New-Item -ItemType Directory -Path $MBSAInstallPath -ErrorAction Stop | Out-Null

    # Download the MBSA installer
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $InstallerPath

    # Install MBSA silently
    Start-Process -FilePath msiexec.exe -ArgumentList "/i `"$InstallerPath`" /quiet" -Wait
}

# Run MBSA scan and save report to file
Start-Process -FilePath "$env:ProgramFiles\Microsoft Baseline Security Analyzer\mbsacli.exe" -ArgumentList "/xmlout `"$ScanReportPath`" /wi" -Wait

Write-Host "Scan report saved to: $ScanReportPath"
