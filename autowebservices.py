#!/usr/bin/python3

## Made Feb 2024 by Ian Bennett with OpenAI GPT4 as a stretch goal for 
## Code Fellows Cybersecurity Ops-401 Midterm project.
############################
######### imports ##########
############################
import sys
import click
import boto3

############################
######## functions #########
############################

def choose_region():
    regions = {
        '1': 'us-east-1',  # US East (Northern Virginia)
        '2': 'us-east-2',  # US East (Ohio)
        '3': 'us-west-1',  # US West (Northern California)
        '4': 'us-west-2',  # US West (Oregon)
    }

    print("Please choose a region by entering the corresponding number:")
    for key, value in sorted(regions.items()):
        print(f"{key}. {value} - {get_region_description(value)}")
    region_choice = input("Your choice: ")

    if region_choice not in regions:
        print("Invalid region choice. Please run the command again and select a valid option.")
        return None

    return regions[region_choice]

def get_region_description(region_code):
    descriptions = {
        'us-east-1': "US East (Northern Virginia) Region, Availability Zones: 6, Local Zones: 10",
        'us-east-2': "US East (Ohio) Region, Availability Zones: 3",
        'us-west-1': "US West (Northern California) Region, Availability Zones: 3",
        'us-west-2': "US West (Oregon) Region, Availability Zones: 4, Local Zones: 7",
    }
    return descriptions.get(region_code, "Region description not available")

def print_availability_zones(ec2):
    response = ec2.describe_availability_zones()
    print("\nAvailability Zones:")
    for az in response['AvailabilityZones']:
        print(f"- {az['ZoneName']} (State: {az['State']})")

def print_vpcs(ec2):
    vpcs = ec2.describe_vpcs()
    print("\nVPCs:")
    for vpc in vpcs['Vpcs']:
        print(f"- VPC ID: {vpc['VpcId']} (CIDR: {vpc['CidrBlock']})")

def print_subnets(ec2):
    subnets = ec2.describe_subnets()
    print("\nSubnets:")
    for subnet in subnets['Subnets']:
        print(f"- Subnet ID: {subnet['SubnetId']} (CIDR: {subnet['CidrBlock']}, Availability Zone: {subnet['AvailabilityZone']})")

def print_security_groups(ec2):
    security_groups = ec2.describe_security_groups()
    print("\nSecurity Groups:")
    for sg in security_groups['SecurityGroups']:
        print(f"- SG ID: {sg['GroupId']} (Name: {sg['GroupName']}, VPC ID: {sg['VpcId']})")


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
        print("5. Quit")
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
            return
        else:
            print("Invalid choice. Please run the command again and select a valid option.")

@cli.command(help='Spin up a new server')
@click.option('--type', type=click.Choice(['windows', 'ubuntu'], case_sensitive=False), prompt=True, help='Server type (Windows or Ubuntu)')
def spin_up_server(type):
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

@cli.command(help='Backup an instance or volume')
@click.option('--method', type=click.Choice(['instance', 'volume'], case_sensitive=False), prompt=True, help='Backup method (instance or volume)')
def backup_instance_or_volume(method):
    """Placeholder for backup logic"""
    # Implement backup logic based on method

if __name__ == '__main__':
    cli()
