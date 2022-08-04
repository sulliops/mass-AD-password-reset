# Dependencies
Import-Module ActiveDirectory
Add-Type -AssemblyName System.Windows.Forms

# Function to generate AD-safe passwords, pulled from https://www.powershellgallery.com/packages/SMBBlueprint/8.1.0.2/Content/functions%5Cprivate%5CNew-SWRandomPassword.ps1
function New-SWRandomPassword {
    <#
    .Synopsis
    Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .DESCRIPTION
    Generates one or more complex passwords designed to fulfill the requirements for Active Directory
    .EXAMPLE
    New-SWRandomPassword
    C&3SX6Kn
 
    Will generate one password with a length between 8 and 12 chars.
    .EXAMPLE
    New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
    7d&5cnaB
    !Bh776T"Fw
    9"C"RxKcY
    %mtM7#9LQ9h
 
    Will generate four passwords, each with a length of between 8 and 12 chars.
    .EXAMPLE
    New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4
    3ABa
 
    Generates a password with a length of 4 containing atleast one char from each InputString
    .EXAMPLE
    New-SWRandomPassword -InputStrings abc, ABC, 123 -PasswordLength 4 -FirstChar abcdefghijkmnpqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ
    3ABa
 
    Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from
    the string specified with the parameter FirstChar
    .OUTPUTS
    [String]
    .NOTES
    Written by Simon Wåhlin, blog.simonw.se
    I take no responsibility for any issues caused by this script.
    .FUNCTIONALITY
    Generates random passwords
    .LINK
    http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
 
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 8,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 12,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 8,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!#%&'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1
    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}

# Function for prompting for file input (account names)
$fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{

    Multiselect = $false
    Filter = 'Text file (*.txt)|*.txt'

}

# Call file browser window to select accounts file
Write-Host "Using system file browser to prompt for file with usernames..."
$fileBrowserValid = $fileBrowser.ShowDialog()

# Check to make sure user has not canceled the system file browser
if ($fileBrowserValid -eq [System.Windows.Forms.DialogResult]::OK) { # If a file was selected, continue

    # Store file browser selection as accountsFile
    $accountsFile = $fileBrowser.FileName
    Write-Host "Selected input file:"$accountsFile"`n"

    # Get parent directory of input file
    $workingPath = Split-Path -Parent $accountsFile

    # Get current date and time to be appended to output file name
    $currentDateTime = Get-Date -Format "yyyyMMdd_HHmmss"

    # Create output file with date and time for passwords
    $passwordsFile = "generated-passwords-$currentDateTime.txt"
    New-Item -Path $workingPath -Name $passwordsFile -ItemType File

    # Print output file path
    Write-Host "Generated output file:"$workingPath\$passwordsFile"`n"

    # Get the contents of accountsFile as usernames by line
    $users = Get-Content -Path $accountsFile

    # For each line with username in accountsFile, generate a new password, set that new password, force user to reset on login, and print unencrypted password to PowerShell
    ForEach ($user in $users) {

        # Trim whitespace from username being read
        $user = $user.Trim()
        
        # Check if the user exists
        $userExists = Get-ADUser -Filter {sAMAccountName -eq $user}

        if (!$userExists) { # If user does not exist
            
            # Write to terminal that user doesn't exist
            Write-Host "User"$user "does not exist, skipping."
            
            # Write error message to output file so that continuity isn't broken
            Add-Content -Path $workingPath\$passwordsFile -Value "ERROR: USER DOES NOT EXIST"

        } else { # If user exists
            
            # Generate random password and store as plainTextPassword (since PowerShell Write-Host can't print encrypted text)
            $plainTextPassword = New-SWRandomPassword -PasswordLength 10

            # Encrypt plainTextPassword and store as newADPassword
            $newADPassword = ConvertTo-SecureString -AsPlainText $plainTextPassword -Force
    
            # Set password for given user to newADPassword
            Get-ADUser $user | Set-ADAccountPassword -NewPassword $newADPassword -Reset
    
            # Force given user to change password on login (uncomment to enable)
            # Get-ADUser $user | Set-ADUser -ChangePasswordAtLogon $true
    
            # Check if user is enabled in AD
            $enabledCheck = Get-ADUser -Identity $user -Properties enabled | select -ExpandProperty enabled

            if ($enabledCheck -eq "True") { # If user is enabled

                # Append details for password to output passwords file
                Add-Content -Path $workingPath\$passwordsFile -Value $plainTextPassword

            } else { # If user is disabled

                # Print warning message in terminal
                Write-Host "WARNING: User"$user "is DISABLED."

                # Add the password to output file with DISABLED prefix
                Add-Content -Path $workingPath\$passwordsFile -Value "DISABLED - $plainTextPassword"

            }

            # Write details for user and password to PowerShell terminal
            Write-Host "User"$user "password reset to:"$plainTextPassword

        }

    }

    # Output message to terminal when finished
    Write-Host "`nPasswords written to output file in input directory for bulk copy-pasting."

} else { # If user did not select an input file

    Write-Host "System file browser exited without selection. Aborting script."

}
