#!/usr/bin/python3

## Made Feb 2024 by Ian Bennett with OpenAI GPT4 as a stretch goal for 
## Code Fellows Cybersecurity Ops-401 Midterm project.
############################
######### imports ##########
############################
import sys
import click  # this is how the script takes arguments
import boto3  # this is how the script works with aws
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
    """Helper function to extract 'Name' tag from AWS resource tags."""
    if tags is None:
        return "N/A"
    for tag in tags:
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
        choice = input("Enter your choice (1-5): ")

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
                instance_id = list_instances(selected_region)
                if instance_id:
                    print(f"Selected instance ID: {instance_id}")
                else:
                    print("No instance selected or found.")
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



if __name__ == '__main__':
    cli()





@cli.command(help='Spin up a new server')
@click.option('--type', type=click.Choice(['windows', 'ubuntu'], case_sensitive=False), prompt=True, help='Server type (Windows or Ubuntu)')
def instance(type):
    """Offer options to spin up a new Windows or Ubuntu server"""
    # Placeholder for actual logic to choose AMI based on server type
    ami_id = '<ami-id>'  # Replace with dynamic selection logic
    key_pair_name = '<key-pair-name>'  # Consider user input or existing key pair
    subnet_id = '<subnet-id>'  # Could be selected based on VPC/subnet listing

    ec2 = boto3.resource('ec2')
    instances = ec2.create_instances(
        ImageId=ami_id,
        InstanceType='t2.micro',
        KeyName=key_pair_name,
        SubnetId=subnet_id,
        MaxCount=1,
        MinCount=1
    )
    print("New instance created:", instances[0].id)