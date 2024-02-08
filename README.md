# scripts
This is where the automation and attack scripts for Zorg Tech live.

>[autowebservices](autowebservices.py) is a python3 script intended to be run locally with aws cli permissions for three purposes:
> - `survey` is an argument that will allow for the investigation of a user-selected aws region to identify the status of availability zones and info about VPCs, subnets, security groups, and instances located in that region.
> - `backup` is an argument that uses the same region selection function to list instances in a given user-selected region, and then automatically copies the aws ebs volume for that instance, creating a full backup at that moment - an action that should be auditable through aws.
> - `instance`, the third possible argument, is a completely interactive mechanism for creating a given instance (only set up for windows 2019 or linux ubuntu 22.04 amis right now) - with a user-selected (from list) type, storage size, vpc, subnet, security group, with/without public IP, etc. Can also generate new keys and user-input the file name and output directory.

>[wash](wash.ps1) is PowerShell-based 'Windows Automated Server Handling'. There is a somewhat dated but extremely thorough documentation available [right here](https://github.com/subtropicalhorseback/scratchpad/blob/main/WASH_Documentation.md), but the general idea is that this script should be used to install ADDS, promote a server to Domain Controller, configure the domain, add AD users and OUs, and configure AD file sharing by AD security group through an interactive menu.
