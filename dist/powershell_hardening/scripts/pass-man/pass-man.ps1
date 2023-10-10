# Install the CredentialManager module if not already installed
Install-PackageProvider -Name NuGet -Force | Out-Null
Install-Module -Name NuGet -Force
Install-Module -Name CredentialManager -Scope CurrentUser -Force

# Import the CredentialManager module
Import-Module CredentialManager


function Test-PasswordStrength {
    param(
        [Parameter(Mandatory = $true)]
        [String]$Password
    )

    # Define password complexity requirements
    $minimumLength = 8
    $minimumLowercase = 1
    $minimumUppercase = 1
    $minimumNumeric = 1
    $minimumSpecial = 1

    $lengthRequirement = $Password.Length -ge $minimumLength
    $lowercaseRequirement = ($Password -cmatch "[a-z]") -ge $minimumLowercase
    $uppercaseRequirement = ($Password -cmatch "[A-Z]") -ge $minimumUppercase
    $numericRequirement = ($Password -cmatch "[0-9]") -ge $minimumNumeric
    $specialRequirement = ($Password -match "[^!@#$%&*]") -ge $minimumSpecial

    $requirementsMet = $lengthRequirement -and $lowercaseRequirement -and $uppercaseRequirement -and $numericRequirement -and $specialRequirement

    return $requirementsMet
}

# Prompt user for username and password
$target = $args[0]
$username = $args[1]
$password = $args[2]
$saveCredential = $args[3]

# Convert secure string password to plaintext
# $password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Test password strength
$passwordStrength = Test-PasswordStrength -Password $password

if ($passwordStrength) {
    if ($saveCredential -eq $true) {
        # Save the credentials to Windows Credential Manager
        cmdkey /generic:$target /user:$username /pass:$password > $null
    }
    Write-Output "success"
} else {
    Write-Output "failed"
}