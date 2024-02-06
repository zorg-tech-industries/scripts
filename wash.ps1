# this powershell script will be used to stand up a windows server
# created Dec 18-20, 2023 by Tiki-Tech-Network-Solutions



Write-Host "__        ___    ____  _   _ "
Write-Host "\ \      / / \  / ___|| | | |"
Write-Host " \ \ /\ / / _ \ \___ \| |_| |"
Write-Host "  \ V  V / ___ \ ___) |  _  |"
Write-Host "   \_/\_/_/   \_\____/|_| |_|"
Write-Host " Windows     Automated       `n"
Write-Host "       Server       Handling`n`n`n"

Start-Sleep -Seconds 1.5

                             
##################################

##################################
function Download-Install-PowerShell7.4 {
    ## Update to PowerShell 7.4.0 (Windows Server 2019 normally has 5.1.x)
    $url1 = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.0/PowerShell-7.4.0-win-x64.msi"
    $output1 = "C:\Users\Administrator\Downloads\PowershellUpgrade.msi"

    ### Retrieve the update file
    Write-Host "Downloading updated PowerShell file.`n"
    if (Test-Path -Path $output1) {
        Write-Host "PowerShell update file already exists. Skipping download.`n`n"
    } else {
        try {
            Write-Host "A previous download of the PowerShell update was not found. Downloading the file from GitHub.`n"
            Invoke-WebRequest -Uri $url1 -OutFile $output1 -ErrorAction Stop
            Write-Host "Download successful.`n`n"
        }
        catch {
            Write-Host "Error downloading the PowerShell update file: $_`n`n"
            exit 1
        }
    }

    ### Implement the update (normally from 5.1)
    $minPSVer = [version]'7.4.0'
    $curPSVer = $PSVersionTable.PSVersion

    # Check if the current PowerShell version is less than 7.4
    if ($curPSVer -lt $minPSVer) {
        Write-Host "Your PowerShell version is less than 7.4.0 - updating PowerShell.`n"
        try {
            Start-Process -Wait -FilePath "msiexec.exe" -ArgumentList "/i $output1 /qn" -ErrorAction Stop
            Write-Host "PowerShell installation successful.`nOne note - if you're running this in a 5.1 session, the version won't show as 7.4 but it probably did install.`n"
            
            ### Show status
            $PSVer = $PSVersionTable.PSVersion
            Write-Host "PowerShell version after update (in this session): $($PSVer.Major).$($PSVer.Minor).$($PSVer.Build)`n`n"
        }
        catch {
            Write-Host "Error installing PowerShell: $_`n`n"
            exit 1
        }
    } else {
        Write-Host "PowerShell is already up-to-date. Skipping installation.`n"
        $PSVer = $PSVersionTable.PSVersion
        Write-Host "Current PowerShell version (in this session): $($PSVer.Major).$($PSVer.Minor).$($PSVer.Build)`n`n"
    }
}

##################################

function Install-AD-Domain-Services {
    ## Install AD tools
    if (Get-WindowsFeature -Name AD-Domain-Services | Where-Object { $_.Installed }) {
        Write-Host "AD-Domain-Services feature is already installed. Skipping installation.`n"
    } else {
        try {
            Write-Host "Previous download of ADDS was not found. Downloading..."
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -ErrorAction Stop
            Write-Host "Installed AD-Domain-Services.`n"
        }
        catch {
            Write-Host "Error installing Domain Services: $_ `n"
            exit 1
        }
    }
}

##################################

function Create-Domain-Controller {
    ## Become domain controller
    ### Check if the server is already a domain controller

    Write-Host "If you are not yet a member of a domain (like during initial configuration) then you'll get a red font error right here when the variable you can't see tries to check your current domain. It's no big deal."
    $Dname = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name -split '\.')[0]

    if ($env:USERDOMAIN -eq $Dname) {
        Write-Host "The server is already a domain controller for the domain $Dname. Skipping domain setup.`n"
    } else {
        try {
            # take user input for domain
            $inpDomain = Read-Host -Prompt "Enter your desired Domain:`n"
            Write-Host "Okay, making this server the Domain Controller for $inpDomain`n Server will prompt for password and reboot during this process.`n`n"

            Install-ADDSForest -DomainName $inpDomain -DomainMode Win2012R2 -ForestMode Win2012R2 -InstallDNS -Force -ErrorAction Stop
        }
        catch {
            Write-Host "Error with DSForest: $_ `n"
            exit 1
        }
    }
}

##################################

function Provision-ADUser {
    ######## THE BULK OF THIS SECTION WAS ORIGINALLY WRITTEN IN DECEMBER 2023 BY MARCUS NOGUEIRA, BUT IT HAS BEEN UPDATED TO SUIT OUR NEEDS

    # Import the Active Directory module
    Import-Module ActiveDirectory

    # Function accepts a prompt, presents it to the user, checks if the input is empty or not. Returns empty or input. Useful for skipping questions.
    function Get-Input {
        param ([string]$prompt)
        $user_input = Read-Host -Prompt $prompt
        if (-not [string]::IsNullOrWhiteSpace($user_input)) {
            return $user_input
        }
        return $null
    }

    $thisorthat = Read-Host "Press 1 to enter a new AD user and 2 to enter a new OU. Press Q to quit."
    $Dname = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name -split '\.')[0]

    if ($thisorthat -eq '1') {
        do {
            Write-Host "The following prompts are used to create a user email (first 5 of last name, first 2 of first name).`nIf the department is not found, it will create an AD-OU with that name.`n"
            $firstName = Get-Input -prompt "ENTER FIRST NAME "
            $lastName = Get-Input -prompt "ENTER LAST NAME "
            $title = Get-Input -prompt "ENTER TITLE "
            $department = Get-Input -prompt "ENTER DEPARTMENT "
            $company = Get-Input -prompt "ENTER COMPANY "
            $securePassword = Read-Host -AsSecureString -Prompt "ENTER PASSWORD "

            # Convert the secure string password to plain text (BSTR)
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
            try {
                $password = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
            }
            finally {
                # Free the BSTR pointer
                [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
            }

        
            # make the email address
            $emailLastName = $lastName.Substring(0, [Math]::Min(5, $lastName.Length))
            $emailFirstName = $firstName.Substring(0, [Math]::Min(2, $firstName.Length))
            $email = "$emailLastName$emailFirstName@$Dname.com"
        

            # Check for the OU based on the Department
            $OUPath = "OU=$department,DC=$Dname,DC=com"
            if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$department'" -ErrorAction SilentlyContinue)) {
                New-ADOrganizationalUnit -Name $department -Path "DC=$Dname,DC=com"
            }

            # User creation
            New-ADUser -Name "$firstName $lastName" `
                -GivenName $firstName `
                -Surname $lastName `
                -SamAccountName ($firstName[0] + $lastName).ToLower() `
                -UserPrincipalName "$email" `
                -Path $OUPath `
                -Title $title `
                -Department $department `
                -Company $company `
                -EmailAddress $email `
                -Enabled $true `
                -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force)
#                -ChangePasswordAtLogon $true
            
            # clear password from memory
            $password = $null

            Write-Host "A user account has been created in the Active Directory for $firstName $lastName with email address $email. Welcome to $company!"
            $addAnother = Get-Input -prompt "Would you like to add another user? (Y/N)"
        } while ($addAnother -eq "Y")
    }

    elseif ($thisorthat -eq '2') {
        do{

            $newOU = Read-Host "Enter the name of the Organizational Unit you'd like to create."
            New-ADOrganizationalUnit -Name $newOU -Path "DC=$Dname,DC=com"
            Write-Host "The OU $newOU has been created.`n"

            Write-Host "Here is a list of current OUs:"
            Get-ADOrganizationalUnit -Filter * | Select-Object Name | Format-List
            Write-Host "`n`n"

            $addAnother = Get-Input -prompt "Would you like to add another OU? (Y/N)"
        } while ($addAnother -eq "Y")
    }

    elseif ($thisorthat -eq 'Q') {
        break
    }

    else {
        Write-Host "Invalid input."
        return
    }
}

##################################

function Server-Maintenance {
    # Prompt user if they want to rename the server
    $renameServer = Read-Host "Would you like to rename the server? (y/n)"

    if ($renameServer -eq "y") {
        # Get user input for the new server name
        $newServerName = Read-Host "Enter the new server name"

        # Print user input for confirmation
        Write-Host "You entered the new server name: $newServerName"

        # Change server name to user input without immediate restart
        Rename-Computer -NewName $newServerName -Force

        # Display message about the change taking effect on reboot
        Write-Host "The server name has been changed to $newServerName. The change will take effect on the next reboot.`n"

        $turnoff = Read-Host "Would you like to restart now? y/n"
        if ($turnoff -eq 'y') {
            # Prompt the user for a comment
            $comment = Read-Host "Enter a comment explaining the reason for the server reboot"

            # Display the entered comment
            Write-Host "You entered: $comment"

            # Restart the computer with the provided comment
            ####### ERROR - word "comment" - maybe fixed
            shutdown /f /t 0 /r /c "$comment"
        }

        elseif ($turnoff -eq 'n') {
            break
        }

        else {
            Write-Host "Invalid input"
            return
        }
    }

    elseif ($renameServer -eq "n") {
        Write-Host "Skipping server rename.`n"
    }

    else {
        Write-Host "Invalid input. Please enter y or n.`n"
        return
    }

    # Prompt user if they want to set a static LAN IP for the server
    $setStaticIP = Read-Host "Would you like to set a static LAN IP and configure DNS for this server? (Y/N)"

    if ($setStaticIP -eq "Y") {

        # Get the active network adapter
        $networkAdapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        $interfaceAlias = $networkAdapter.InterfaceAlias

        # Get the static IP address from ipconfig
        $ipConfigResult = ipconfig | Select-String -Pattern 'IPv4 Address.*: (\d+\.\d+\.\d+\.\d+)' -AllMatches
        $staticIP = $ipConfigResult.Matches.Groups[1].Value
        Write-Host "Your current IP address (ipconfig) is $staticIP`n"

        # Validate if a valid IP address was found
        if (-not ($staticIP -as [System.Net.IPAddress])) {
            Write-Host "Unable to retrieve a valid static IP address from ipconfig. Please enter it manually.`n"
            return
        }

        # Get default gateway from ipconfig
        $ipConfigResult = ipconfig | Select-String -Pattern 'Default Gateway.*: (\d+\.\d+\.\d+\.\d+)' -AllMatches
        $defaultGateway = $ipConfigResult.Matches.Groups[1].Value
        Write-Host "Your current Gateway address (ipconfig) is $defaultGateway`n"

        # Validate default gateway
        if (-not ($defaultGateway -as [System.Net.IPAddress])) {
            Write-Host "Unable to retrieve a valid default gateway from ipconfig. Please enter it manually.`n"
            return
        }
        ####

        # Check if the IP address already exists
        $existingIPAddress = Get-NetIPAddress -InterfaceAlias $interfaceAlias | Where-Object { $_.IPAddress -eq $staticIP -and $_.AddressFamily -eq 'IPv4' }

        if ($existingIPAddress) {
            # If it exists, remove the existing IP address
            Remove-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $staticIP
            Write-Host "Removed existing IP address $staticIP."
        }

        # Set static IP address for the server
        New-NetIPAddress -InterfaceAlias $interfaceAlias -IPAddress $staticIP -PrefixLength 24 -DefaultGateway $defaultGateway -Type Unicast -AddressFamily IPv4
        Write-Host "Static IP address set to $staticIP."

        # Import the DNS Server module
        Write-Host "Importing DNS Server Module"
        Import-Module DnsServer

        # Define DNS settings
        $IPAddress = $staticIP
        $Forwarders = "8.8.8.8", "8.8.4.4"
        Write-Host "Checking for Windows DNS Management features."

        # Configure DNS server settings
        if (-not (Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue)) {
            # Install DNS server feature
            Write-Host "Installing Windows DNS Management features."
            Install-WindowsFeature -Name DNS -IncludeManagementTools
        }

        # Set the DNS server address on the network adapter
        Write-Host "Setting DNS Server on the active network adapter (typically LAN)"
        $NIC = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
        Set-DnsClientServerAddress -InterfaceIndex $NIC.IfIndex -ServerAddresses $IPAddress

        # Configure DNS forwarders
        Write-Host "Setting DNS Forwarding to $forwarders"
        Set-DnsServerForwarder -IPAddress $Forwarders

        # Get the current domain name
        $domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name

        # Check if the DNS zone already exists
        $zoneExists = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue

        if ($zoneExists) {
            Write-Host "DNS zone for $domain already exists. Skipping creation."
        } else {
            # Create a forward lookup zone
            Write-Host "Attempting to create forward lookup zone for $domain on LAN"
            try {
                Add-DnsServerPrimaryZone -Name $domain -ZoneFile "$domain.dns" -PassThru -ErrorAction Stop
                Write-Host "Forward lookup zone created successfully."
            } catch {
                Write-Host "Failed to create forward lookup zone. Error: $_"
            }
        }



        # Restart DNS service to apply changes
        Write-Host "Restarting DNS Service"
        Restart-Service -Name DNS

        # Display message after DNS is configured
        Write-Host "DNS configuration completed. Exiting maintenance.`n"
    }
    elseif ($setStaticIP -eq "N") {
        Write-Host "Skipping static IP configuration. Exiting maintenance.`n"
    }
    else {
        Write-Host "Invalid input. Please enter Y or N.`n"
        return
    }
}

##################################

function Create-Network-Folders {

    #read the domain
    $Dname = ([System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name -split '\.')[0]

    # Prompt user for folder name - THIS WORKS
    $folderName = Read-Host "Enter the name of the shared folder"

    # Validate folder name - THIS WORKS
    if (-not $folderName -or $folderName -notmatch '^[a-zA-Z0-9_\-]+$') {
        Write-Host "Invalid folder name. Please use alphanumeric characters, underscores, or hyphens."
        return
    }

    # Check if folder already exists - THIS WORKS
    $folderPath = "C:\SharedFolders\$folderName"
    $sharePath = "C:\SharedFolders\$folderName"
    if (Test-Path $folderPath) {
        Write-Host "The folder '$folderName' already exists. Proceeding."
    }
    else {
        # Create the folder - THIS WORKS
        New-Item -Path $folderPath -ItemType Directory -ErrorAction Stop
    }

    do {
        # Print list of OUs - THIS WORKS
        Write-Host "`n`nHere's a list of OUs in this AD:"
        Get-ADOrganizationalUnit -Filter * | Select-Object Name | Format-List
    
        # Prompt for OU Selection: - THIS WORKS
        $authorizedOU = Read-Host "Enter one OU name to authorize access to the shared folder (at $folderName)"
    
        # THIS WORKS
        $existOU = Get-ADOrganizationalUnit -Filter {Name -eq $authorizedOU}
        if ($existOU -eq $null) {
            Write-Host "That OU doesn't exist. Option 4 in the Main Menu allows creation of OUs."
            break
        } else {
            # show users in OU
            Write-Host "`nYou will see a red Windows warning here if there are no AD-Users in your OU. No problem.`n"
            Write-Host "Here is a list of users in your selected OU:"
            Get-ADUser -SearchBase "OU=$authorizedOU,DC=$Dname,DC=com" -Filter * | Select-Object Name | Format-List
        }
    
        # confirm selection - THIS WORKS
        $confirmAuth = Read-Host "`nConfirm you want $authorizedOU users to have access to $folderName (y/n)`n"
        if ($confirmAuth -eq 'y') {
            $authSG = "SecGroup$authorizedOU"
    
            # check for existence of group
            $existSG = Get-ADGroup -Filter {Name -eq $authSG}
            if ($existSG -eq $null) {
                # if it doesn't exist
                New-ADGroup -Name "$authSG" -GroupScope Global -GroupCategory Security 
            } else {
                # if it does exist
                Write-Host "`nGood news, this OU has a Security Group already! Mirroring current OU users to respective SG.`n"
            }               
    
            #copy the users and report
            Get-ADUser -SearchBase "OU=$authorizedOU,DC=$Dname,DC=com" -Filter * | ForEach-Object {Add-ADGroupMember -Identity "$authSG" -Members $_ }
            Write-Host "`nAdded users from $authorizedOU to $authSG.`n"
    
            # Share the folder and assign access based on SGs
            try {
                $netshare = $folderName
                net share $netshare=$sharePath /GRANT:$authSG,FULL
                Write-Host "`nShared folder '$folderName' shared successfully with $authSG`n"
            }   
            catch {
                Write-Host "`n`n ***** Error sharing folder: $_"
                break
            }
    
            $addAnother = Read-Host -Prompt "Would you like to allow another OU to access $folderName? (Y/N)"
        }
        elseif ($confirmAuth -eq 'n') {
            $addAlt = Read-Host -Prompt "Would you like to allow a different OU to access $folderName? (Y/N)"
            if ($addAlt -eq 'y') {
                return
            }
            elseif ($addAlt -eq 'n') {
                break
            }
            else {
                Write-Host "Invalid input"
                return
            }
        }
        else {
            Write-Host "Invalid input"
            return
        }
    } while ($addAnother -eq 'Y')
    
}

##################################


function ConfigureEmail {

    # Install SMTP Server feature
    Write-Host "Installing Windows Feature SMTP-Server"
    Install-WindowsFeature -Name SMTP-Server -IncludeManagementTools

    # Import the WebAdministration module
    Write-Host "Importing Module WebAdministration"
    Import-Module WebAdministration

    # Set the SMTP server configuration
    Set-ItemProperty -Path "IIS:\SmtpServer\Default SMTP Server" -Name "SmtpMaxMessagesPerConnection" -Value 20
    Set-ItemProperty -Path "IIS:\SmtpServer\Default SMTP Server" -Name "SmtpMaxMessageSize" -Value 10485760  # 10 MB limit
    Set-ItemProperty -Path "IIS:\SmtpServer\Default SMTP Server" -Name "SmtpMaxRecipientsPerMessage" -Value 100  

    # Disable Anonymous Authentication and enable Windows Authentication
    Set-ItemProperty -Path "IIS:\SmtpServer\Default SMTP Server" -Name "SmtpAnonymousAuthenticationEnabled" -Value $false
    Set-ItemProperty -Path "IIS:\SmtpServer\Default SMTP Server" -Name "SmtpWindowsAuthenticationEnabled" -Value $true

    # Restart the SMTP server to apply changes
    Restart-Service -Name "SimpleMailTransferProtocol"

    Write-Host "SMTP Server configured successfully."
}

##################################

# Display the menu
while ($true) {
    Clear-Host
    Write-Host "Select an option:"
    Write-Host "1. Download and install PowerShell 7.4 update"
    Write-Host "2. Install Active Directory Domain Services"
    Write-Host "3. Promote this server to a Domain Controller"
    Write-Host "4. Add AD Users or OUs to the Domain"
    Write-Host "5. Server Maintenance - Rename, Static IP, DNS"
    Write-Host "6. Create Shared Network Folders"
    # Write-Host "7. Configure Intranet Email Server"
    Write-Host "Q. Quit"

    # Get user input
    $choice = Read-Host "Enter the 'Q' to quit"

    # Process user choice
    switch ($choice) {
        '1' { Download-Install-PowerShell7.4; break }
        '2' { Install-AD-Domain-Services; break }
        '3' { Create-Domain-Controller; break }
        '4' { Provision-ADUser; break }
        '5' { Server-Maintenance; break }
        '6' { Create-Network-Folders; break }
    #    '7' { ConfigureEmail; break }
        'Q' { exit }
        default { Write-Host "Invalid choice. Please try again." }
    }

    # Pause to display the output
    Read-Host "Press Enter to continue..."
}
