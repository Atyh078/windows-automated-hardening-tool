$portRangeStart = 1
$portRangeEnd = 5

$openPorts = 1..$portRangeEnd | ForEach-Object {
    $port = $_
    $result = Test-NetConnection -ComputerName localhost -Port $port -WarningAction SilentlyContinue
    if ($result.TcpTestSucceeded) {
        $port
    }
}

if ($openPorts) {
    Write-Output "Open ports on localhost:"
    $openPorts | ForEach-Object {
        Write-Output $_
    }
} else {
    Write-Output "No open ports found on localhost."
}