$registryItems = $args[0] -split ','

foreach($registry in $registryItems){
    switch($registry){
        "WebSearch"{
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -ErrorAction Stop
        }
        "FeedbackService"{
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0 -ErrorAction Stop
        }
        "AdvertisingId"{
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Value 0 -ErrorAction Stop
        }
    }
}

Write-Output "success"