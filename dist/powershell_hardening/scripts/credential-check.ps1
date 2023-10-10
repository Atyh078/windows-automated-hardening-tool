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
    $specialRequirement = ($Password -cmatch "[^a-zA-Z0-9]") -ge $minimumSpecial

    $requirementsMet = $lengthRequirement -and $lowercaseRequirement -and $uppercaseRequirement -and $numericRequirement -and $specialRequirement

    return $requirementsMet
}

# Prompt for credentials
$currentPassword = $null
while ($currentPassword -eq $null) {
    $credential = Get-Credential -Message "Enter your current password" -UserName $env:USERNAME
    $currentPassword = $credential.GetNetworkCredential().Password
}

$passwordStrength = Test-PasswordStrength -Password $currentPassword

if ($passwordStrength) {
    Write-Output "Current password meets the complexity requirements."
} else {
    Write-Output "Password is weak. Ensure it meets the minimum requirements:`n"
    Write-Output "- At least 8 characters"
    Write-Output "- At least 1 lowercase letter"
    Write-Output "- At least 1 uppercase letter"
    Write-Output "- At least 1 numeric digit"
    Write-Output "- At least 1 special character`n"
	Write-Output "You may change your password by entering CTRL + ALT + DEL."
}
