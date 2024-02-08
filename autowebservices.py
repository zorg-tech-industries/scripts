#!/usr/bin/python3

## Made Feb 2024 by Ian Bennett with OpenAI GPT4 as a stretch goal for 
## Code Fellows Cybersecurity Ops-401 Midterm project.


############################
######### imports ##########
############################

import boto3  # this is how the script works with aws
import click  # this is how the script takes arguments
import os # walks to check where to output a private key file
from botocore.exceptions import ClientError
from datetime import datetime
global_instances = []  # Global list to store instances
selected_region = None  # Global variable to store the selected region


############################
######## functions #########
############################

# this function makes it easier to search in specific (ie other than default) aws regions
# and availability zones when iterating through the click survey()
def choose_region():
    
    global selected_region

    regions = { # could add more regions later but 'Murica
        '1': 'us-east-1',  # US East (Northern Virginia)
        '2': 'us-east-2',  # US East (Ohio)
        '3': 'us-west-1',  # US West (Northern California)
        '4': 'us-west-2',  # US West (Oregon)
    }

    print("Please choose a region by entering the corresponding number:")

    # print the region options
    for key, value in sorted(regions.items()):
        print(f"{key}. {value} - {get_region_description(value)}")
    
    # take user input
    region_choice = input("Your choice: ")

    # error handling
    if region_choice not in regions:
        print("Invalid region choice. Please run the command again and select a valid option.")
        return None

    # send it out for use
    selected_region = regions[region_choice]
    return selected_region

# straightforward...
def get_region_description(region_code):
    descriptions = {
        'us-east-1': "US East (Northern Virginia) Region, Availability Zones: 6, Local Zones: 10",
        'us-east-2': "US East (Ohio) Region, Availability Zones: 3",
        'us-west-1': "US West (Northern California) Region, Availability Zones: 3",
        'us-west-2': "US West (Oregon) Region, Availability Zones: 4, Local Zones: 7",
    }
    return descriptions.get(region_code, "Region description not available")

def get_name_tag(tags):
    """Extract 'Name' tag from a list of tags."""
    for tag in tags or []:
        if tag['Key'] == 'Name':
            return tag['Value']
    return "N/A"

def print_availability_zones(ec2):
    response = ec2.describe_availability_zones()
    zones = sorted(response['AvailabilityZones'], key=lambda x: x['ZoneName'])
    print("\nAvailability Zones:")
    for az in zones:
        print(f"- {az['ZoneName']} (State: {az['State']})")

def print_vpcs(ec2):
    vpcs = ec2.describe_vpcs()
    print("\nVPCs:")
    for vpc in sorted(vpcs['Vpcs'], key=lambda x: get_name_tag(x.get('Tags', []))):
        name = get_name_tag(vpc.get('Tags', []))
        print(f"- Availability Zone: N/A | Name: {name} | VPC ID: {vpc['VpcId']} | CIDR: {vpc['CidrBlock']}")

def print_subnets(ec2):
    subnets = ec2.describe_subnets()
    print("\nSubnets:")
    for subnet in sorted(subnets['Subnets'], key=lambda x: (x['AvailabilityZone'], get_name_tag(x.get('Tags', [])))):
        name = get_name_tag(subnet.get('Tags', []))
        print(f"- Availability Zone: {subnet['AvailabilityZone']} | Name: {name} | Subnet ID: {subnet['SubnetId']} | CIDR: {subnet['CidrBlock']}")

def print_security_groups(ec2):
    security_groups = ec2.describe_security_groups()
    print("\nSecurity Groups:")
    for sg in sorted(security_groups['SecurityGroups'], key=lambda x: get_name_tag(x.get('Tags', []))):
        name = get_name_tag(sg.get('Tags', []))
        print(f"- Availability Zone: N/A | Name: {name} | SG ID: {sg['GroupId']} | VPC ID: {sg['VpcId']}")

def list_instances():
    global selected_region
    ec2 = boto3.client('ec2', region_name=selected_region)
    reservations = ec2.describe_instances()['Reservations']
    instances = [instance for reservation in reservations for instance in reservation['Instances']]

    if not instances:
        print("No instances found in this region.")
        return []

    sorted_instances = sorted(instances, key=lambda x: (x['Placement']['AvailabilityZone'], get_name_tag(x.get('Tags', []))))
    for i, instance in enumerate(sorted_instances, start=1):
        instance_name = get_name_tag(instance.get('Tags', []))
        local_ip = instance.get('PrivateIpAddress', 'N/A')
        public_ip = instance.get('PublicIpAddress', 'N/A')
        print(f"{i}. Availability Zone: {instance['Placement']['AvailabilityZone']} | Name: {instance_name} | ID: {instance['InstanceId']} | Local IP: {local_ip} | Public IP: {public_ip}")

    return sorted_instances

def select_instance_for_backup(instances):
    instance_number = input("Enter the number of the instance to backup: ")
    try:
        instance_number = int(instance_number) - 1
        if 0 <= instance_number < len(instances):
            return instances[instance_number]['InstanceId']
        else:
            print("Invalid selection.")
            return None
    except ValueError:
        print("Invalid input. Please enter a number.")
        return None

def validate_and_backup_instance(instance_id):
    global selected_region  # Use the global variable
    ec2 = boto3.resource('ec2', region_name=selected_region)
    instance = ec2.Instance(instance_id)

    if not instance:
        print("Instance not found.")
        return

    try:
        volume_ids = [vol['Ebs']['VolumeId'] for vol in instance.block_device_mappings if 'Ebs' in vol]
        for volume_id in volume_ids:
            snapshot = ec2.create_snapshot(VolumeId=volume_id, Description=f"Backup of {instance_id} on {datetime.now().isoformat()}")
            print(f"Snapshot created for Volume {volume_id}: {snapshot.id}")
    except Exception as e:
        print(f"Error during backup: {e}")

def generate_key_pair(ec2_resource):
    """Generates a new EC2 key pair and saves the private key to a user-specified directory and filename."""
    default_key_pair_name = f"ec2-keypair-{datetime.now().strftime('%Y%m%d%H%M%S')}"
    
    # Prompt user for directory path
    directory = input("Enter the directory path to save the key pair (leave blank to use current directory): ").strip()
    if directory and not os.path.isdir(directory):
        print(f"Directory does not exist: {directory}")
        return None
    
    # Prompt user for a filename
    filename = input(f"Enter the filename (without extension, leave blank to use default name '{default_key_pair_name}'): ").strip()
    if not filename:
        filename = default_key_pair_name
    file_path = os.path.join(directory, f"{filename}.pem")
    
    try:
        key_pair = ec2_resource.create_key_pair(KeyName=filename)
        private_key = key_pair.key_material
        with open(file_path, 'w') as file:
            file.write(private_key)
        print(f"New key pair created: {filename}. Private key saved to {file_path}")
        return filename
    except ClientError as e:
        print(f"Failed to create key pair: {e}")
        return None

def list_resources(resources, resource_type):
    for i, resource in enumerate(resources, start=1):
        name = get_name_tag(resource.get('Tags', [])) if 'Tags' in resource else "N/A"
        resource_id = resource['VpcId'] if resource_type == 'VPC' else (
            resource['SubnetId'] if resource_type == 'Subnet' else resource['GroupId'])
        print(f"{i}. {resource_type} ID: {resource_id} | Name: {name}")

    choice = input(f"Select a {resource_type} by number: ")
    if choice.isdigit():
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(resources):
            return resources[choice_index][resource_id]  # Return the selected resource ID
    print("Invalid selection.")
    return None

def select_resource(resources, prompt, resource_type=None):
    for i, resource in enumerate(resources, start=1):
        # Dynamically identify the correct ID key based on resource type
        if resource_type == 'VPC':
            resource_id_key = 'VpcId'
        elif resource_type == 'Subnet':
            resource_id_key = 'SubnetId'
        elif resource_type == 'Security Group':
            resource_id_key = 'GroupId'
        else:
            raise ValueError("Unsupported resource type")

        resource_id = resource[resource_id_key]
        name = get_name_tag(resource.get('Tags', [])) if 'Tags' in resource else "N/A"
        print(f"{i}. {resource_type} ID: {resource_id} | Name: {name}")

    choice = input(prompt)
    if choice.isdigit():
        choice_index = int(choice) - 1
        if 0 <= choice_index < len(resources):
            return resources[choice_index][resource_id_key]
    print("Invalid selection.")
    return None

############################
########## click ###########
############################
@click.group()
def cli():
    """AWS Management Script from y'boi STHB"""
    pass

@cli.command(help='Check AWS CLI availability zone and list existing VPCs, subnets, and security groups with boto3')
def survey():
    """Allows the user to select a region and provides information on AWS resources."""
    region = choose_region()
    if not region:
        return  # Exit if the region selection was invalid

    print(f"You have selected the region: {region}.")
    
    # Pass the selected region to the ec2 client
    ec2 = boto3.client('ec2', region_name=region)
    
    while True:
        print("\n\nWhat information would you like to retrieve?")
        print("1. Availability Zones")
        print("2. VPCs")
        print("3. Subnets")
        print("4. Security Groups")
        print("5. Instances")
        print("6. Quit")
        choice = input("Enter your choice (1-6): ")

        if choice == '1':
            print_availability_zones(ec2)
        
        elif choice == '2':
            print_vpcs(ec2)
        
        elif choice == '3':
            print_subnets(ec2)
        
        elif choice == '4':
            print_security_groups(ec2)
        
        elif choice == '5':
            if selected_region:
                list_instances()  # Call without expecting a return value
            else:
                print("Region not selected. Please select a region first.")

        elif choice == '6':
            return
        else:
            print("Invalid choice. Please run the command again and select a valid option.")

@cli.command(help='Backup an instance')
@click.option('--method', type=click.Choice(['1', '2'], case_sensitive=False), prompt="Choose from region (1) and list or input your own instance ID (2)?")
def backup(method):
    global selected_region
    if not selected_region:
        selected_region = choose_region()
        if not selected_region:
            return  # Exit if no region is selected
    
    if method == '1':
        instances = list_instances()  # List instances without prompting for selection
        if instances:
            instance_id = select_instance_for_backup(instances)  # Prompt user to select an instance for backup
            if instance_id:
                validate_and_backup_instance(instance_id)  # Backup the selected instance
            else:
                print("Backup operation aborted.")
        else:
            print("No instances available for backup.")
    elif method == '2':
        instance_id = input("Enter the instance ID: ")
        validate_and_backup_instance(instance_id)  # Directly backup the specified instance

@cli.command(help='Spin up a new server')
def instance():
    print("Would you like to stand up an instance? (y/n): ")
    proceed = input().lower()
    if proceed != 'y':
        print("okay bye")
        return

    selected_region = choose_region()
    if not selected_region:
        print("Region selection is required.")
        return

    ec2_resource = boto3.resource('ec2', region_name=selected_region)
    ec2_client = boto3.client('ec2', region_name=selected_region)

    name_tag = input("\nEnter Name tag (press Enter to skip): ")

    os_choice = input("\nChoose an operating system - Windows 2019 (1) or Ubuntu Server 22.04 (2): ")
    ami_id = "ami-01baa2562e8727c9d" if os_choice == '1' else "ami-008fe2fc65df48dac"

    instance_type = input("\nChoose instance type (default t2.micro): ")
    instance_type = instance_type if instance_type else "t2.micro"

    storage_size = input("\nChoose storage size (GiB, press Enter for default 8GiB): ")
    storage_size = int(storage_size) if storage_size else 8

    print("\nChoose key pair:")
    existing_keys = ec2_client.describe_key_pairs()
    for i, key in enumerate(existing_keys['KeyPairs'], start=1):
        print(f"{i}. {key['KeyName']}")
    key_choice = input("\nEnter key number to use or 'n' to create a new one (press Enter to skip): ")
    if key_choice.lower() == 'n':
        key_pair_name = generate_key_pair(ec2_resource)
    elif key_choice.isdigit():
        key_pair_name = existing_keys['KeyPairs'][int(key_choice) - 1]['KeyName']
    else:
        key_pair_name = None  # Handle no key pair scenario

    # Fetch VPCs
    vpcs = ec2_client.describe_vpcs()['Vpcs']
    # Use select_resource() for VPC selection
    vpc_id = select_resource(vpcs, "\nSelect a VPC by number: ", "VPC")

    # Fetch Subnets
    subnets = ec2_client.describe_subnets()['Subnets']
    # Use select_resource() for Subnet selection
    subnet_id = select_resource(subnets, "\nSelect a subnet by number: ", "Subnet")

    # Fetch Security Groups
    security_groups = ec2_client.describe_security_groups()['SecurityGroups']
    # Use select_resource() for Security Group selection
    sg_id = select_resource(security_groups, "\nSelect a security group by number: ", "Security Group")

#    ebs_encrypted = input("\nChoose EBS encryption y/n (default y): ")
#    ebs_encrypted = True if ebs_encrypted.lower() != 'n' else False

    auto_public_ip = input("\nChoose auto public IP y/n (default y): ")
    auto_public_ip = auto_public_ip.lower() != 'n'

    # Confirm selections and create instance
    print("\nCreating instance with the following configuration:")
    print(f"Region: {selected_region}, OS: {'Windows 2019' if os_choice == '1' else 'Ubuntu Server 22.04'}, "
          f"Instance Type: {instance_type}, Storage Size: {storage_size}GiB, Key Pair: {key_pair_name}, "
          f"VPC ID: {vpc_id}, Subnet ID: {subnet_id}, Security Group ID: {sg_id}" #, EBS Encrypted: {ebs_encrypted}, "
          f"Auto Public IP: {auto_public_ip}")
    
    confirmation = input("\nConfirm creation? y/n: ")
    if confirmation.lower() == 'y':
        try:
            network_interfaces = [{
                'SubnetId': subnet_id,
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': auto_public_ip,
                'Groups': [sg_id] if sg_id else None
            }] if subnet_id else None

            instance = ec2_resource.create_instances(
                ImageId=ami_id,
                InstanceType=instance_type,
                KeyName=key_pair_name,
                MinCount=1,
                MaxCount=1,
                TagSpecifications=[{'ResourceType': 'instance', 'Tags': [{'Key': 'Name', 'Value': name_tag}]}] if name_tag else None,
#                EbsOptimized=ebs_encrypted,
                NetworkInterfaces=network_interfaces,
            )[0]
            print(f"\nInstance created successfully: {instance.id}")

        except Exception as e:
            print(f"\nFailed to create instance: {e}")

    else:
        print("\nInstance creation aborted.\n\n")

if __name__ == '__main__':
    cli()
