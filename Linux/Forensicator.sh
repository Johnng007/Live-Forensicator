#!/bin/bash

# Live Forensicator Powershell Script
# Part of the Black Widow Tools
# Coded by Ebuka John Onyejegbu

# Usage

# Defining parameters
usage() {
    echo "Usage: $0 [-p|--pcap] [-r|--ram] [-s|--ransom] [-w|--weblogs] [-b|--browser] [-t|--timeline] [-e|--encrypt] [-d|--decrypt] [-u|--usage] [-z|--update]"
    echo "  -p, --pcap            Record network traffic for 60 seconds and save as a pcap file"
    echo "  -r, --ram             Extract the system RAM"
    echo "  -s, --ransom          Check filesystem for ransomeware encrypted files"
    echo "  -w, --weblogs         Collect Webserver logs"
    echo "  -b, --browser         Collects browsing history"
    echo "  -t, --timeline        Incident timeline helpful when extracting logs"
    echo "  -log --logfiles        Log filenames to search through"
    echo "  -logdir --logdir      Log directory to search through"
    echo "  -e, --encrypt         Encrypts the Forensicator extracted artifacts"
    echo "  -d, --decrypt         Decrypts and encrypted Forensicator artifact"
    echo "  -u, --usage           Shows the tool usage"
    echo "  -z, --update          Updates your copy of Forensicator"
    echo "  -name, --name         Supply Investigator name as a flag"
    echo "  -case, --case         Supply case reference as a flag"
    echo "  -title, --title       Supply Investigation title as a flag"
    echo "  -loc, --location      Supply Examination location as a flag"
    echo "  -device, --device     Supply Examination location as a flag"
    exit 1
}

# create working directory
mkdir $(hostname)

# define working hostname
Hostname=$(hostname)

# print messages in green color
green() {
    echo -e "\e[32m$@\e[0m"
}

# print messages in dark cyan color
cyan() {
    echo -e "\e[36m$@\e[0m"
}

# Assigning functions to parameters

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
    -t | --timeline)
        TIMELINE=1
        START_DATE="$2"
        END_DATE="$3"
        validate_date "$START_DATE"
        validate_date "$END_DATE"
        shift # past argument
        shift # past value
        shift # past value
        ;;
    -logdir | --logdir)
        LOG_DIR="$2"
        shift # past argument
        shift # past value
        ;;
    -log | --logfiles)
        IFS=',' read -r -a LOG_FILES <<<"$2"
        shift # past argument
        shift # past value
        ;;
    -name | --name)
        NAME="$2"
        shift # past argument
        shift # past value
        ;;
    -case | --case)
        CASE="$2"
        shift # past argument
        shift # past value
        ;;
    -title | --title)
        TITLE="$2"
        shift # past argument
        shift # past value
        ;;
    -loc | --location)
        LOCATION="$2"
        shift # past argument
        shift # past value
        ;;
    -device | --device)
        DEVICE="$2"
        shift # past argument
        shift # past value
        ;;
    -p | --pcap)
        pcap
        ;;
    -z | --update)
        update
        ;;
    -u | --usage)
        usage
        ;;
    -r | --ram)
        ram
        ;;
    -w | --weblogs)
        weblogs
        ;;
    -b | --browser)
        browser
        ;;
    -s | --ransom)
        ransom
        ;;
    *)
        # Unknown option
        echo "Error: Unknown option: $key"
        usage
        ;;
    esac
    shift
done

# Getting version info
MyVersion=$(<version.txt)
#MyVersion="1.0"
t=$(
    cat <<-"EOF"
___________                                .__               __                
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________ 
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|   
     \/                    \/     \/     \/        \/     \/                    

                                                                        
EOF
    echo ""
    echo "                                                                          $MyVersion"

)

len=${#t}

for ((i = 0; i < len; i++)); do
    if ((i % 2)); then
        c="31" # red
    elif ((i % 5)); then
        c="33" # yellow
    elif ((i % 7)); then
        c="32" # green
    else
        c="39" # default white
    fi
    echo -ne "\033[1;${c}m${t:$i:1}"
done

echo -e "\033[0m" # reset color

# changing directory to the created
cd $(hostname)

# Setting Operator Details
NAME=""
CASE=""
TITLE=""
LOCATION=""
DEVICE=""

# Prompt for investigator details if not provided
if [[ -z "$NAME" || -z "$CASE" || -z "$TITLE" || -z "$LOCATION" || -z "$DEVICE" ]]; then
    read -p "Enter investigator name: " NAME
    read -p "Enter case number: " CASE
    read -p "Enter case title: " TITLE
    read -p "Enter examination location: " LOCATION
    read -p "Enter device description: " DEVICE
fi

# Save investigator details
#echo "Case reference: $CASE" >
#cho "Examiner Name: $NAME" >
#echo "Investigation Title: $TITLE" >
#echo "Device: $DEVICE" >
#echo "Examination Location: $LOCATION" >

# Setting our html files

# Setting index output file
ForensicatorIndexFile="index.html"

# Setting Network Information Output
NetworkFile="network.html"

# Setting Users Information Output
UserFile="users.html"

# Setting System Information Output
SystemFile="system.html"

# Setting Processes Output
ProcessFile="processes.html"

# Setting Other Checks Output
OthersFile="others.html"

# Setting Extras Output file
ForensicatorExtrasFile="extras.html"

# Recording start time
startdate=$(date)

# Function to Auto check update the script from GitHub
# GitHub repository details
repoOwner="johnng007"
repoName="Live-Forensicator"
branch="main"
versionFile="version.txt"
rawUrl="https://raw.githubusercontent.com/$repoOwner/$repoName/$branch/Linux/$versionFile"

# Function to check for updates
CheckForUpdates() {
    # Fetch the version from GitHub
    remoteVersion=$(curl -s $rawUrl | tr -d '[:space:]')

    # Compare local and remote versions
    if [[ $MyVersion < $remoteVersion ]]; then
        cyan "[!] A new version $remoteVersion is available on GitHub. Please upgrade your copy of Forensicator."
    else
        green "[!] You are using the latest version $localVersion. No updates available."
    fi
}

# Call the function to check for updates
CheckForUpdates

# Function to record network traffic for 60 seconds and save as a pcap file
pcap() {
    mkdir $(hostname)/PCAP
    cyan "Recording network traffic for 60 seconds..."
    sudo tcpdump -i any -w ./$(hostname)/PCAP/network_traffic.pcap -G 60 -W 1 &>/dev/null
    green "Network traffic recorded and saved"
}

# Function to Extract RAM
ram() {
    mkdir $(hostname)/RAM
    cyan "Extracting RAM"
    ./Forensicator-Share/avml --compress "./$(hostname)/RAM/$(hostname).lime.compressed"
    green "RAM extracted, compressed and saved"

}

# Function to collect webserver logs
weblogs() {
    mkdir $(hostname)/WEBLOGS
    cyan "Checking the existance of Apache logs..."
    apache_logs_dir=$(apachectl -V | grep SERVER_CONFIG_FILE | sed 's/.*"\(.*httpd.conf\)".*/\1/' | xargs dirname)
    if [[ -z "$apache_logs_dir" ]]; then
        cyan "Looks like there are no Apache webservers"
        #exit 1
    fi

    # Copy Apache logs to destination directory
    find "$apache_logs_dir" -type f -name "*.log" -mtime -$timeline -exec cp {} "$(hostname)/WEBLOGS" \;
    green "Apache logs extracted and copied"

    cyan "Checking the existance of NGINX logs..."
    nginx_logs_dir=$(nginx -V 2>&1 | grep -oP '(?<=--error-log-path=)\S+' | xargs dirname)
    if [[ -z "$nginx_logs_dir" ]]; then
        cyan "Looks like there are no NGINX webservers"
        #exit 1
    fi

    # Copy Nginx logs to destination directory
    find "$nginx_logs_dir" -type f -name "*.log" -mtime -$timeline -exec cp {} "$(hostname)/WEBLOGS" \;
    green "Nginx logs extracted and copied"
}

# Function to get browsing history
browser() {
    {
        cyan "[*] Getting Browsing History"
        mkdir -p "$(hostname)/BROWSING_HISTORY"
        path="/"
        for database in $(find "$path" -name 'places.sqlite'); do
            profilename=$(basename "$(dirname "$database")")
            outname="history-firefox_$(date +%F_%H-%M-%S)_$profilename"
            {
                echo ".headers on"
                echo ".mode csv"
                echo ".output $(hostname)/BROWSING_HISTORY/$outname.csv"
                echo "SELECT moz_historyvisits.visit_date, moz_places.url, moz_places.title
            FROM moz_places, moz_historyvisits
                WHERE moz_places.id = moz_historyvisits.place_id;"
            } | ./Forensicator-Share/sqlite3 "$database"
        done
    } &>/dev/null

    {
        path="/"
        for database in $(find "$path" -name 'History'); do
            profilename=$(basename "$(dirname "$database")")
            if [[ "$profilename" == 'System Profile' ]]; then
                continue
            fi
            detoxprofilename=$(echo "$profilename" | detox --inline)
            outname="history-chrome_$(date +%F_%H-%M-%S)_$detoxprofilename"
            {
                echo ".headers on"
                echo ".mode csv"
                echo ".output $(hostname)/BROWSING_HISTORY/$outname.csv"
                echo "SELECT visits.visit_time-11644473600000000, urls.url, urls.title
            FROM visits, urls
                WHERE urls.id = visits.url;"
            } | ./Forensicator-Share/sqlite3 "$database"
        done
    } &>/dev/null

    green "[!] Done"
}

# Function to check for Ransomware encrypted files
ransom() {

    mkdir -p $(hostname)/RANSOM_MALICIOUS

    cyan "[*] checking Ramsomware encrypted files.."
    cyan "[*] This may take a while.."
    # Function to search for files with given extensions
    search_files() {
        local Ransomeware_Extensions=("$@")
        for ext in "${Ransomeware_Extensions[@]}"; do
            find / -type f -name "*$ext" 2>/dev/null
        done
    }

    # Check if the JSON file exists
    json_file="./config.json"
    if [ ! -f "$json_file" ]; then
        echo "Error: JSON file '$json_file' not found."
        exit 1
    fi

    # Read the file extensions from the JSON file
    Ransomeware_Extensions=($(grep -o '"\.[^"]*"' "$json_file" | tr -d '"'))

    # Define the output directory and file

    # Search for files with the specified extensions and output to a text file
    # echo "Searching for files with extensions similar to ransomware encrypted files..."
    search_files "${Ransomeware_Extensions[@]}" >"$(hostname)/RANSOM_MALICIOUS/$(hostname)_ransom.txt"
    green "[!] Done"

}

# Function to extract system logs within a timeline.
timeline() {

    cyan "[*] Collecting timeline logs"

    # Default values
    LOG_DIR="/var/log"
    OUTPUT_DIR="./$(hostname)/timeline_logs"
    LOG_FILES=("auth.log" "syslog" "kern.log" "messages")
    TIMELINE=0

    # Validate date format function
    validate_date() {
        date -d "$1" "+%Y-%m-%d %H:%M:%S" &>/dev/null
        if [[ $? -ne 0 ]]; then
            echo "Invalid date format: $1"
            usage
        fi
    }

    # Create output directory for extracted logs
    mkdir -p "$OUTPUT_DIR"

    # Function to extract logs
    extract_logs() {
        local file=$1
        local start_date=$2
        local end_date=$3

        if [[ $TIMELINE -eq 1 ]]; then
            awk -v start="$start_date" -v end="$end_date" \
                '$0 >= start && $0 <= end' "$file" >"${OUTPUT_DIR}/$(basename $file)"
        else
            cp "$file" "$OUTPUT_DIR"
        fi
    }

    # Extract logs from log directories
    for log_file in "${LOG_FILES[@]}"; do
        if [[ -f "${LOG_DIR}/${log_file}" ]]; then
            echo "Extracting logs from ${LOG_DIR}/${log_file}..."
            extract_logs "${LOG_DIR}/${log_file}" "$START_DATE" "$END_DATE"
        else
            echo "Log file ${log_file} does not exist in ${LOG_DIR}"
        fi
    done

    green "[!] Done"

}

###############################################
# BASIC INFORMATION COLLECTION
###############################################

###############################################
# Networks
###############################################
cyan "[*] Collecting Network Information"

# network infterface
F_ip=$(ip a)

#routing table
F_route=$(ip route show)

# Processes and Networking
F_ps=$(ps auxfww)

# IP only connections
F_lsof=$(lsof -i -n)
mkdir -p $(hostname)/OTHER
echo "IP Only Connection" >./$(hostname)/OTHER/IP_Connections.txt
echo "$F_lsof" >>./$(hostname)/OTHER/IP_Connections.txt

# IP only connections2
F_ss=$(ss -anp)
echo "IP Only Connection2" >./$(hostname)/OTHER/IP_Connections2.txt
echo "$F_ss" >>./$(hostname)/OTHER/IP_Connections2.txt

# TCP Only connection
#F_netstat3=$(netstat -antp)
F_ss2=$(ss -antp)

# List firewall rules
F_iptables=$(iptables --list-rules)

# DNS files
F_hosts=$(cat /etc/hosts)
F_hosts2=$(cat /etc/hosts.allow)
F_resolv=$(cat /etc/resolv.conf)

#F_hosts3=$(cat /etc/hosts.deny)

green "[!] Done"

###############################################
# System Info
###############################################

cyan "[*] Collecting System Information"

# OS Info
F_uname=$(uname -a)

# Kernal info
F_lshw=$(lshw)
echo "Kernel Information" >./$(hostname)/OTHER/Kernel_Info.txt
echo "$F_lshw" >>./$(hostname)/OTHER/Kernel_Info.txt

#CPU information
F_lscpu=$(lscpu)

#Block devices
F_lsblk=$(lsblk -a)

# USB controllers
F_lsusb=$(lsusb -v)

# PCI devices
F_lspci=$(lspci -v)
echo "PCI Devices" >./$(hostname)/OTHER/PCI_Devices.txt
echo "$F_lspci" >>./$(hostname)/OTHER/PCI_Devices.txt

# SATA devices
F_hdparm=$(hdparm /dev/sda1)

green "[!] Done"

###############################################
# User(s) Info
###############################################

cyan "[*] Collecting User(s) Information"

# who is connected
F_w=$(w)

# Users with login shells
F_shell=$(cat /etc/passwd | grep sh$)

# users with SSH Auth keys
F_keys=$(find / -type f -name authorized_keys 2>/dev/null)

F_passwd=$(cat /etc/passwd)
F_sudoers=$(grep '^sudo:' /etc/group)
F_bashrc=$(cat /etc/bash.bashrc)
echo "Current User Bash Profile" >./$(hostname)/OTHER/bash_bashrc.txt
echo "$F_bashrc" >>./$(hostname)/OTHER/bash_bashrc.txt

green "[!] Done"

###############################################
# Process Info
###############################################

cyan "[*] Collecting Process Information"

# List all services
F_services=$(service --status-all)
F_systemctl=$(systemctl list-unit-files --state=enabled)

# List all timers
F_systemctl2=$(systemctl list-timers --all)

F_cron2=$(cat /etc/passwd | cut -d: -f1 | sudo xargs -I{} sh -c 'crontab -l -u {} 2>/dev/null || echo "No crontab for {}"')

green "[!] Done"

###############################################
# Other Info
###############################################

cyan "[*] Collecting Other Information"

# Open Files
F_lsof=$(lsof -V 2>/dev/null)
echo "Open Files" >./$(hostname)/OTHER/open_files.txt
echo "$F_lsof" >>./$(hostname)/OTHER/open_files.txt

# Get lastlog
#F_lastlog=$(lastlog)
F_last2=$(last -Faiwx)

# what is loaded
F_lsmod=$(lsmod)

# Look for cap_setuid+ep in binary capabilities
F_getcap=$(getcap -r /usr/bin/)
F_getcap2=$(getcap -r /bin/)
F_getcap3=$(getcap -r / 2>/dev/null)

# SUID
F_suid=$(find / -type f -perm -u=s 2>/dev/null)

# Persistence areas
F_p1=$(ls -la /etc/cron*/ 2>/dev/null)
F_p2=$(ls -la /etc/incron.d/* 2>/dev/null)
F_p3=$(ls -la /etc/init.d/* 2>/dev/null)
F_p4=$(ls -la /etc/rc*.d/* 2>/dev/null)
F_p5=$(ls -la /etc/systemd/system/* 2>/dev/null)
F_p6=$(ls -la /etc/update.d/* 2>/dev/null)
F_p7=$(ls -la /var/spool/cron/* 2>/dev/null)
F_p8=$(ls -la /var/spool/incron/* 2>/dev/null)
F_p9=$(ls -la /var/run/motd.d/* 2>/dev/null)

#Authlogs
F_authlogs=$(grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log)
echo "session opened for|accepted password|new session|not in sudoers" >./$(hostname)/OTHER/AuthLogs.txt
echo "$F_authlogs" >./$(hostname)/OTHER/AuthLogs.txt

green "[!] Done"

# Recording end time
enddate=$(date)

#########################################################
# Creating and formating out HTML Index File
#########################################################

cyan "[*] Creating & Formatting Index file"
cyan "[*] This will take a while"

cat <<EOL >$ForensicatorIndexFile
<!DOCTYPE html>
<html>
<head>
<!-- Basic Page Info -->
<meta charset="utf-8" />
<title>Live Forensicator - Results for $Hostname</title>

<!-- Mobile Specific Metas -->
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
<!-- Google Font -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
rel="stylesheet" />
<!-- CSS -->
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
<link rel="stylesheet" type="text/css"
href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
<div class="pre-loader">
<div class="pre-loader-box">
<div class="loader-logo">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="loader-progress" id="progress_div">
<div class="bar" id="bar1"></div>
</div>
<div class="percent" id="percent1">0%</div>
<div class="loading-text">Loading...</div>
</div>
</div>
<div class="header">
<div class="header-left">
<div class="menu-icon bi bi-list"></div>
<div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
<div class="header-search">
<form>
<div class="form-group mb-0">
<i class="dw dw-search2 search-icon"></i>
<input type="text" class="form-control search-input" placeholder="Search Here" />
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<i class="ion-arrow-down-c"></i>
</a>
<div class="dropdown-menu dropdown-menu-right">
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">From</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">To</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="form-group row">
<label class="col-sm-12 col-md-2 col-form-label">Subject</label>
<div class="col-sm-12 col-md-10">
<input class="form-control form-control-sm form-control-line" type="text" />
</div>
</div>
<div class="text-right">
<button class="btn btn-primary">Search</button>
</div>
</div>
</div>
</div>
</form>
</div>
</div>
<div class="header-right">
<div class="user-info-dropdown">
<div class="dropdown">
<a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
<span class="bi bi-laptop" style="font-size: 1.50em;">
</span>
<span class="user-name">$Hostname</span>
</a>
</div>
</div>
<div class="github-link">
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
alt="" /></a>
</div>
</div>
</div>
<div class="right-sidebar">
<div class="right-sidebar-body customscroll">
<div class="right-sidebar-body-content">
<h4 class="weight-600 font-18 pb-10">Header Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
</div>
<h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
<div class="sidebar-btn-group pb-30 mb-10">
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
<a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
</div>
</div>
</div>
</div>
<div class="left-side-bar header-white active">
<div class="brand-logo">
<a href="index.html">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
</a>
<div class="close-sidebar" data-toggle="left-sidebar-close">
<i class="ion-close-round"></i>
</div>
</div>
<div class="menu-block customscroll">
<div class="sidebar-menu">
<ul id="accordion-menu">
<li class="dropdown">
<a href="index.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-house"></span><span class="mtext">Home</span>
</a>
</li>
<li class="dropdown">
<a href="users.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
</a>
</li>
<li class="dropdown">
<a href="system.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
</a>
</li>
<li class="dropdown">
<a href="network.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
</a>
</li>
<li class="dropdown">
<a href="processes.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
</a>
</li>
<li class="dropdown">
<a href="others.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
</a>
</li>
<li class="dropdown">

<ul class="submenu">



</ul>

<li>
<div class="dropdown-divider"></div>
</li>
<li>
<div class="sidebar-small-cap">Extra</div>
</li>
<li class="dropdown">
<a href="extras.html" class="dropdown-toggle no-arrow">
<span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
</a>
</li>
</ul>
</div>
</div>
</div>
<div class="mobile-menu-overlay"></div>
<div class="main-container">
<div class="pd-ltr-20 xs-pd-20-10">
<div class="min-height-200px">
<div class="page-header">
<div class="row">
<div class="col-md-6 col-sm-12">
<div class="title">
<h4>Home</h4>
</div>
<nav aria-label="breadcrumb" role="navigation">
<ol class="breadcrumb">
<li class="breadcrumb-item">
<a href="index.html">Home</a>
</li>
<li class="breadcrumb-item active" aria-current="page">
Index
</li>
</ol>
</nav>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<div class="card-box pd-20 height-100-p mb-30">
<div class="row align-items-center">
<div class="col-md-4">
<img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
</div>
<div class="col-md-8">
<h4 class="font-20 weight-500 mb-10 text-capitalize">
Live Forensics Results for
<div class="weight-600 font-30 text-blue">$Hostname</div>
</h4>
<p class="font-18 max-width-600">
This HTML File and its associated files were generated by the
Live Forensicator script, we believe the contents will aid
the investigator to understand if the system has been compromised, the
final conclusion is up to the investigator.
</p>
</div>
</div>
</div>
</div>
</div>
<div class="main-container">
<div class="pd-ltr-20">
<!-- Bordered table  start -->
<div class="pd-20 card-box mb-30">
<div class="clearfix mb-20">
<div class="pull-left">
<h4 class="text-blue h4">Key Information</h4>
<p>
This space contains information about the examiner, case and exhibit details
Analysis Start and end time is also recorded.
</p>
</div>
</div>
<table class="table table-bordered">
<thead>
<tr>
<th scope="col">#</th>
<th scope="col">Details</th>
<th scope="col">Values</th>
</tr>
</thead>
<tbody>

<tr>
<th scope="row">1</th>
<td>Case reference:</td>
<td>$CASE</td>
</tr>
<tr>
<th scope="row">2</th>
<td>Examiner Name:</td>
<td>$NAME</td>
</tr>
<tr>
<th scope="row">3</th>
<td>Exhibit reference:</td>
<td>$TITLE</td>
</tr>
</tr>
<tr>
<th scope="row">4</th>
<td>Device:</td>
<td>$DEVICE</td>
</tr>
</tr>
<tr>
<th scope="row">5</th>
<td>Examination Location:</td>
<td>$LOCATION</td>
</tr>
</tr>
<tr>
<th scope="row">6</th>
<td>Start Time and Date:</td>
<td>$startdate</td>
</tr>
</tr>
<tr>
<th scope="row">7</th>
<td>End Time and Date:</td>
<td>$enddate</td>
</tr>
</tbody>
</table>
</div>
<!--Bordered table End -->
</div>
</div>
<!-- Export Datatable End -->
</div>
<div class="footer-wrap pd-20 mb-20 card-box">
Live Forensicator - Coded By
<a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
</div>
</div>
</div>
<!-- js -->
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
<script type="text/javascript"
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
<!-- buttons for Export datatable -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
<!-- Datatable Setting js -->
<script
src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
<script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
</body>
</html>

EOL

cat <<EOL >$NetworkFile


<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
         
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Networks
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Routing Table</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Destination</th>
                  <th>Gateway</th>
                  <th>Genmask</th>
                  <th>Flags</th>
                  <th>Metric</th>
                  <th>Ref</th>
                  <th>Use</th>
                  <th>Iface</th>
                </tr>
              </thead>
              <tbody>
EOL
# Process the routing table and convert it to HTML table rows
echo "$F_route" | while read line; do
    destination=$(echo $line | awk '{print $1}')
    gateway=$(echo $line | awk '{print $3}')
    iface=$(echo $line | awk '{print $5}')
    echo "<tr><td>$destination</td><td>$gateway</td><td>-</td><td>-</td><td>-</td><td>-</td><td>-</td><td>$iface</td></tr>" >>$NetworkFile
done

cat <<EOL >>$NetworkFile

            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Processes & Networking</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">User</th>
                  <th>PID</th>
                  <th>%CPU</th>
                  <th>%MEM</th>
                  <th>VSZ</th>
                  <th>RSS</th>
                  <th>TTY</th>
                  <th>Stat</th>
                  <th>Start</th>
                  <th>Time</th>
                  <th>Command</th>
                </tr>
              </thead>
              <tbody>          
EOL
# Process the ps command output and convert it to HTML table rows
echo "$F_ps" | awk 'NR>1 {printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' >>$NetworkFile

cat <<EOL >>$NetworkFile

            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">TCP only connection</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">State</th>
                  <th>Recv-Q</th>
                  <th>Send-Q</th>
                  <th>Local Address:Port</th>
                  <th>Peer Address:Port</th>
                  <th>Process</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ss command output and convert it to HTML table rows
echo "$F_ss2" | awk 'NR>1 {print "<tr><td>" $1 "</td><td>" $2 "</td><td>" $3 "</td><td>" $4 "</td><td>" $5 "</td><td><pre>" $6 "</pre></td></tr>"}' >>$NetworkFile

cat <<EOL >>$NetworkFile


              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Firewall Rules</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Chain</th>
                  <th>Rule</th>
                </tr>
              </thead>
              <tbody>
EOL

echo "$F_iptables" | awk '{
    chain = $1;
    sub($1, "");
    rule = $0;
    print "<tr><td><pre>" chain "</pre></td><td><pre>" rule "</pre></td></tr>"
}' >>$NetworkFile

cat <<EOL >>$NetworkFile


              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Hosts File</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">IP Address</th>
                  <th>Hostname(s)</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the hosts content and convert it to HTML table rows
echo "$F_hosts" | awk '{print "<tr><td><pre>" $1 "</pre></td><td><pre>" $2 "</pre></td></tr>"}' >>$NetworkFile

cat <<EOL >>$NetworkFile

              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Hosts Allow</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                 <th>Content</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the hosts.allow content and convert it to HTML table rows
echo "$F_hosts2" | awk '{print "<tr><td><pre>" $0 "</pre></td></tr>"}' >>$NetworkFile

cat <<EOL >>$NetworkFile

              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Hosts Resolv</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>Content</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the resolv.conf content and convert it to HTML table rows
echo "$F_resolv" | awk '{print "<tr><td><pre>" $0 "</pre></td></tr>"}' >>$NetworkFile

cat <<EOL >>$NetworkFile

               
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">IP Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ip command output and convert it to HTML table rows
#echo "$F_ip" | awk '/^[0-9]/ {print "<tr><td><pre>" $2 "</pre></td><td><pre>" $4 "</pre></td><td><pre>" $8 "</pre></td><td><pre>" $9 "</pre></td></tr>"}' >>$NetworkFile
echo "$F_ip" | while IFS= read -r line; do
    echo "<tr><td><pre>$line</pre></td></tr>" >>$NetworkFile
done

cat <<EOL >>$NetworkFile

               
              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

EOL

# User Detail HTML

cat <<EOL >$UserFile

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Current User Sessions</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">USER</th>
                  <th>TTY</th>
                  <th>FROM</th>
                  <th>LOGIN@</th>
                  <th>IDLE</th>
                  <th>JCPU</th>
                  <th>PCPU</th>
                  <th>WHAT</th>
                </tr>
              </thead>
              <tbody>
EOL
# Process the w command output and convert it to HTML table rows
echo "$F_w" | awk 'NR>2 {print "<tr><td><pre>" $1 "</pre></td><td><pre>" $2 "</pre></td><td><pre>" $3 "</pre></td><td><pre>" $4 " " $5 "</pre></td><td><pre>" $6 "</pre></td><td><pre>" $7 "</pre></td><td><pre>" $8 "</pre></td><td><pre>" $9 "</pre></td></tr>"}' >>$UserFile

cat <<EOL >>$UserFile

            </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Users with Login Shell</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Username</th>
                  <th>Password</th>
                  <th>UID</th>
                  <th>GID</th>
                  <th>Full Name</th>
                  <th>Home Directory</th>
                  <th>Shell</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the passwd output and convert it to HTML table rows
echo "$F_shell" | awk -F: '{print "<tr><td><pre>" $1 "</pre></td><td><pre>" $2 "</pre></td><td><pre>" $3 "</pre></td><td><pre>" $4 "</pre></td><td><pre>" $5 "</pre></td><td><pre>" $6 "</pre></td><td><pre>" $7 "</pre></td></tr>"}' >>$UserFile

cat <<EOL >>$UserFile


             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Users with SSH Auth keys</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>File Path</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the find command output and convert it to HTML table rows
echo "$F_keys" | awk '{print "<tr><td><pre>" $0 "</pre></td></tr>"}' >>$UserFile

cat <<EOL >>$UserFile

              </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Passwd File</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap ">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Username</th>
                  <th>Password</th>
                  <th>UID</th>
                  <th>GID</th>
                  <th>Full Name</th>
                  <th>Home Directory</th>
                  <th>Shell</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the passwd output and convert it to HTML table rows
echo "$F_passwd" | awk -F: '{print "<tr><td><pre>" $1 "</pre></td><td><pre>" $2 "</pre></td><td><pre>" $3 "</pre></td><td><pre>" $4 "</pre></td><td><pre>" $5 "</pre></td><td><pre>" $6 "</pre></td><td><pre>" $7 "</pre></td></tr>"}' >>$UserFile

cat <<EOL >>$UserFile

             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->
        
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Sudoers File</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>Content</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the sudoers output and convert it to HTML table rows
echo "$F_sudoers" | while IFS= read -r line; do
    echo "<tr><td><pre>$line</pre></td></tr>" >>$UserFile
done

cat <<EOL >>$UserFile

             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

EOL

cat <<EOL >$SystemFile

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
         
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">System Info</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Command</th>
                  <th>Output</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the uname output and convert it to an HTML table row
echo "<tr><td><pre>uname -a</pre></td><td><pre>$F_uname</pre></td></tr>" >>$SystemFile

cat <<EOL >>$SystemFile

               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Kernel Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Kernel Info</th>
                </tr>
              </thead>
              <tbody>
EOL

# Function to determine indentation level based on leading whitespace
indentation_level() {
    local line="$1"
    local indent_count=$(echo "$line" | sed -e 's/[^ ].*//')
    echo $((${#indent_count} / 2))
}

# Process the lshw output and convert it to HTML table rows
while IFS= read -r line; do
    indent=$(indentation_level "$line")
    sanitized_line=$(echo "$line" | sed 's/[&<>]/\\&/g')
    echo "<tr><td class=\"indent-$indent\"><pre>$sanitized_line</pre></td></tr>" >>$SystemFile
done <<<"$F_lshw"

cat <<EOL >>$SystemFile

             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">CPU Information</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Property</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the lscpu output and convert it to HTML table rows
echo "$F_lscpu" | while IFS= read -r line; do
    property=$(echo "$line" | cut -d ':' -f 1 | xargs)
    value=$(echo "$line" | cut -d ':' -f 2- | xargs)
    echo "<tr><td><pre>$property</pre></td><td><pre>$value</pre></td></tr>" >>$SystemFile
done

cat <<EOL >>$SystemFile

               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Block Devices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Name</th>
                  <th>Maj:Min</th>
                  <th>RM</th>
                  <th>Size</th>
                  <th>RO</th>
                  <th>Type</th>
                  <th>MOUNTPOINT</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the lsblk output and convert it to HTML table rows
echo "$F_lsblk" | while IFS= read -r line; do
    echo "<tr>" >>$SystemFile
    # Split the line by whitespace and iterate over each field
    for field in $line; do
        echo "<td><pre>$field</pre></td>" >>$SystemFile
    done
    echo "</tr>" >>$SystemFile
done

cat <<EOL >>$SystemFile
              
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">USB Controllers</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Bus</th>
                  <th>Device</th>
                  <th>ID</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the lsusb -v output and convert it to HTML table rows
echo "$F_lsusb" | while IFS= read -r line; do
    if [[ $line == *"Bus"* ]]; then
        bus=$(echo "$line" | awk '{print $2}')
        device=$(echo "$line" | awk '{print $4}')
        id=$(echo "$line" | awk '{print $6}')
        description=$(echo "$line" | cut -d':' -f2- | xargs)
        echo "<tr><td><pre>$bus</pre></td><td><pre>$device</pre></td><td><pre>$id</pre></td><td><pre>$description</pre></td></tr>" >>$SystemFile
    fi
done

cat <<EOL >>$SystemFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">SATA Devices</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>Property</th>
                  <th>Value</th>
                </tr>
              </thead>
            <tbody>
EOL

# Process the hdparm output and convert it to HTML table rows
echo "$F_hdparm" | while IFS= read -r line; do
    property=$(echo "$line" | cut -d':' -f1 | xargs)
    value=$(echo "$line" | cut -d':' -f2- | xargs)
    echo "<tr><td><pre>$property</pre></td><td><pre>$value</pre></td></tr>" >>$SystemFile
done

cat <<EOL >>$SystemFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

EOL

cat <<EOL >$ProcessFile

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Processes</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">User</th>
                  <th>PID</th>
                  <th>%CPU</th>
                  <th>%MEM</th>
                  <th>VSZ</th>
                  <th>RSS</th>
                  <th>TTY</th>
                  <th>Stat</th>
                  <th>Start</th>
                  <th>Time</th>
                  <th>Command</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ps command output and convert it to HTML table rows
echo "$F_ps" | awk 'NR>1 {printf "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11}' >>$ProcessFile

cat <<EOL >>$ProcessFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Services</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>Services</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the service --status-all output and convert it to HTML table rows
echo "$F_services" | while IFS= read -r line; do
    echo "<tr><td><pre>$line</pre></td></tr>" >>$ProcessFile
done

cat <<EOL >>$ProcessFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Enabled services</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Unit File</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the systemctl output and convert it to HTML table rows
echo "$F_systemctl" | while IFS= read -r line; do
    unit_file=$(echo "$line" | awk '{print $1}')
    state=$(echo "$line" | awk '{print $2}')
    echo "<tr><td><pre>$unit_file</pre></td><td><pre>$state</pre></td></tr>" >>$ProcessFile
done

cat <<EOL >>$ProcessFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">All Timers</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Next Trigger</th>
                  <th>Left</th>
                  <th>Last Trigger</th>
                  <th>Unit</th>
                  <th>Timer</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the systemctl output and convert it to HTML table rows
echo "$F_systemctl2" | while IFS= read -r line; do
    next_trigger=$(echo "$line" | awk '{print $1 " " $2}')
    left=$(echo "$line" | awk '{print $3}')
    last_trigger=$(echo "$line" | awk '{print $4 " " $5}')
    unit=$(echo "$line" | awk '{print $6}')
    timer=$(echo "$line" | awk '{print $7}')
    echo "<tr><td><pre>$next_trigger</pre></td><td><pre>$left</pre></td><td><pre>$last_trigger</pre></td><td><pre>$unit</pre></td><td><pre>$timer</pre></td></tr>" >>$ProcessFile
done

cat <<EOL >>$ProcessFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Crons</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">User</th>
                  <th>Crontab</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the crontab output and convert it to HTML table rows
echo "$F_cron2" | while IFS= read -r line; do
    user=$(echo "$line" | cut -d: -f1)
    crontab_info=$(echo "$line" | cut -d: -f2-)
    echo "<tr><td><pre>$user</pre></td><td><pre>$crontab_info</pre></td></tr>" >>$ProcessFile
done

cat <<EOL >>$ProcessFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

EOL

cat <<EOL >$OthersFile

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="../../styles/vendors/images/forensicator_logo.png" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img
            src="https://raw.githubusercontent.com/Johnng007/Live-Forensicator/43c2392ad8f54a9e387f9926b9d60e434dd545f2/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="dark-logo" />
        <img
          src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png"
          alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Home</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Users-Accounts
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
       

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Last Logins</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">User</th>
                  <th>TTY</th>
                  <th>From</th>
                  <th>Login Time</th>
                  <th>Logout Time</th>
                  <th>Duration</th>
                  <th>Host</th>
                  <th>IP Address</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the last -Faiwx output and convert it to HTML table rows
echo "$F_last2" | while IFS= read -r line; do
    user=$(echo "$line" | awk '{print $1}')
    tty=$(echo "$line" | awk '{print $2}')
    from=$(echo "$line" | awk '{print $3}')
    login_time=$(echo "$line" | awk '{print $4 " " $5 " " $6 " " $7 " " $8}')
    logout_time=$(echo "$line" | awk '{print $9 " " $10 " " $11 " " $12 " " $13}')
    duration=$(echo "$line" | awk '{print $14}')
    host=$(echo "$line" | awk '{print $15}')
    ip_address=$(echo "$line" | awk '{print $16}')
    echo "<tr><td><pre>$user</pre></td><td><pre>$tty</pre></td><td><pre>$from</pre></td><td><pre>$login_time</pre></td><td><pre>$logout_time</pre></td><td><pre>$duration</pre></td><td><pre>$host</pre></td><td><pre>$ip_address</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Loaded Modules Status</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Module</th>
                  <th>Size</th>
                  <th>Used by</th>
                </tr>
              </thead>
              <tbody>
EOL

# Skip the header line and process the lsmod output
echo "$F_lsmod" | tail -n +2 | while IFS= read -r line; do
    module=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    used_by=$(echo "$line" | awk '{print $3}')
    echo "<tr><td><pre>$module</pre></td><td><pre>$size</pre></td><td><pre>$used_by</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Get Binary File(/usr/bin/) Capabilities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">File</th>
                  <th>Capabilities</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the getcap output and convert it to HTML table rows
echo "$F_getcap" | while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}')
    capabilities=$(echo "$line" | awk '{print $2}')
    echo "<tr><td><pre>$file</pre></td><td><pre>$capabilities</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Get Binary File(/bin/) Capabilities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">File</th>
                  <th>Capabilities</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the getcap output and convert it to HTML table rows
echo "$F_getcap2" | while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}')
    capabilities=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
    echo "<tr><td><pre>$file</pre></td><td><pre>$capabilities</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Get Binary File(/) Capabilities</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">File</th>
                  <th>Capabilities</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the getcap output and convert it to HTML table rows
echo "$F_getcap3" | while IFS= read -r line; do
    file=$(echo "$line" | awk '{print $1}')
    capabilities=$(echo "$line" | awk '{$1=""; print $0}' | sed 's/^ //')
    echo "<tr><td><pre>$file</pre></td><td><pre>$capabilities</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Find files with setuid bit set</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th>File</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the find output and convert it to HTML table rows
echo "$F_suid" | while IFS= read -r line; do
    echo "<tr><td><pre>$line</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in cron (/etc/cron*/)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p1" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in cron (/etc/incron.d/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p2" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/etc/init.d/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p3" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/etc/rc*.d/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p4" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/etc/systemd/system/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p5" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/etc/update.d/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p6" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/var/spool/cron/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p7" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/var/spool/incron/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p8" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->


        <!-- Export Datatable start -->
        <div class="card-box mb-30">
          <div class="pd-20">
            <h4 class="text-blue h4">Looking for persistence in (/var/run/motd.d/*)</h4>
          </div>
          <div class="pb-20">
            <table class="table hover multiple-select-row data-table-export nowrap">
              <thead>
                <tr>
                  <th class="table-plus datatable-nosort">Permissions</th>
                  <th>Links</th>
                  <th>Owner</th>
                  <th>Group</th>
                  <th>Size</th>
                  <th>Date</th>
                  <th>Time</th>
                  <th>Name</th>
                </tr>
              </thead>
              <tbody>
EOL

# Process the ls output and convert it to HTML table rows
echo "$F_p9" | while IFS= read -r line; do
    permissions=$(echo "$line" | awk '{print $1}')
    links=$(echo "$line" | awk '{print $2}')
    owner=$(echo "$line" | awk '{print $3}')
    group=$(echo "$line" | awk '{print $4}')
    size=$(echo "$line" | awk '{print $5}')
    date=$(echo "$line" | awk '{print $6}')
    time=$(echo "$line" | awk '{print $7}')
    name=$(echo "$line" | awk '{print $8}')
    echo "<tr><td><pre>$permissions</pre></td><td><pre>$links</pre></td><td><pre>$owner</pre></td><td><pre>$group</pre></td><td><pre>$size</pre></td><td><pre>$date</pre></td><td><pre>$time</pre></td><td><pre>$name</pre></td></tr>" >>$OthersFile
done

cat <<EOL >>$OthersFile
               
             </tbody>
            </table>
          </div>
        </div>
        <!-- Export Datatable End -->

        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>
  <!-- js -->
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
</body>
</html>

EOL

cat <<EOL >$ForensicatorExtrasFile

<!DOCTYPE html>
<html>
<head>
  <!-- Basic Page Info -->
  <meta charset="utf-8" />
  <title>Live Forensicator - Results for $Hostname</title>
  <!-- Mobile Specific Metas -->
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1" />
  <!-- Google Font -->
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap"
    rel="stylesheet" />
  <!-- CSS -->
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/core.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/core.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/icon-font.min.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/icon-font.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/dataTables.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/css/responsive.bootstrap4.min.css"
    onerror="this.onerror=null;this.href='../../styles/src/plugins/datatables/css/responsive.bootstrap4.min.css';" />
  <link rel="stylesheet" type="text/css"
    href="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/styles/style.css"
    onerror="this.onerror=null;this.href='../../styles/vendors/styles/style.css';" />
</head>
<body>
  <div class="pre-loader">
    <div class="pre-loader-box">
      <div class="loader-logo">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" />
      </div>
      <div class="loader-progress" id="progress_div">
        <div class="bar" id="bar1"></div>
      </div>
      <div class="percent" id="percent1">0%</div>
      <div class="loading-text">Loading...</div>
    </div>
  </div>
  <div class="header">
    <div class="header-left">
      <div class="menu-icon bi bi-list"></div>
      <div class="search-toggle-icon bi bi-search" data-toggle="header_search"></div>
      <div class="header-search">
        <form>
          <div class="form-group mb-0">
            <i class="dw dw-search2 search-icon"></i>
            <input type="text" class="form-control search-input" placeholder="Search Here" />
            <div class="dropdown">
              <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
                <i class="ion-arrow-down-c"></i>
              </a>
              <div class="dropdown-menu dropdown-menu-right">
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">From</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">To</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="form-group row">
                  <label class="col-sm-12 col-md-2 col-form-label">Subject</label>
                  <div class="col-sm-12 col-md-10">
                    <input class="form-control form-control-sm form-control-line" type="text" />
                  </div>
                </div>
                <div class="text-right">
                  <button class="btn btn-primary">Search</button>
                </div>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
    <div class="header-right">
      <div class="user-info-dropdown">
        <div class="dropdown">
          <a class="dropdown-toggle no-arrow" href="#" role="button" data-toggle="dropdown">
            <span class="bi bi-laptop" style="font-size: 1.50em;">
            </span>
            <span class="user-name">$Hostname</span>
          </a>
        </div>
      </div>
      <div class="github-link">
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank"><img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/github.svg"
            alt="" /></a>
      </div>
    </div>
  </div>
  <div class="right-sidebar">
    <div class="right-sidebar-body customscroll">
      <div class="right-sidebar-body-content">
        <h4 class="weight-600 font-18 pb-10">Header Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary header-white active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary header-dark">Dark</a>
        </div>
        <h4 class="weight-600 font-18 pb-10">Sidebar Background</h4>
        <div class="sidebar-btn-group pb-30 mb-10">
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-light active">White</a>
          <a href="javascript:void(0);" class="btn btn-outline-primary sidebar-dark">Dark</a>
        </div>
      </div>
    </div>
  </div>
  <div class="left-side-bar header-white active">
    <div class="brand-logo">
      <a href="index.html">
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="dark-logo" />
        <img src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/images/forensicator_logo.png" alt="" class="light-logo" />
      </a>
      <div class="close-sidebar" data-toggle="left-sidebar-close">
        <i class="ion-close-round"></i>
      </div>
    </div>
    <div class="menu-block customscroll">
      <div class="sidebar-menu">
        <ul id="accordion-menu">
          <li class="dropdown">
            <a href="index.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-house"></span><span class="mtext">Home</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="users.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-people"></span><span class="mtext">Users & Accounts</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="system.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-pc-display"></span><span class="mtext">System Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="network.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-router"></span><span class="mtext">Network Information</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="processes" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-cpu"></span><span class="mtext">System Processes</span>
            </a>
          </li>
          <li class="dropdown">
            <a href="others.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-box-arrow-in-right"></span><span class="mtext">Other Checks</span>
            </a>
          </li>
          
          <li>
            <div class="dropdown-divider"></div>
          </li>
          <li>
            <div class="sidebar-small-cap">Extra</div>
          </li>
          <li class="dropdown">
            <a href="extras.html" class="dropdown-toggle no-arrow">
              <span class="micon bi bi-download"></span><span class="mtext">Forensicator Extras</span>
            </a>
          </li>
        </ul>
      </div>
    </div>
  </div>
  <div class="mobile-menu-overlay"></div>
  <div class="main-container">
    <div class="pd-ltr-20 xs-pd-20-10">
      <div class="min-height-200px">
        <div class="page-header">
          <div class="row">
            <div class="col-md-6 col-sm-12">
              <div class="title">
                <h4>Extras</h4>
              </div>
              <nav aria-label="breadcrumb" role="navigation">
                <ol class="breadcrumb">
                  <li class="breadcrumb-item">
                    <a href="index.html">Home</a>
                  </li>
                  <li class="breadcrumb-item active" aria-current="page">
                    Extras
                  </li>
                </ol>
              </nav>
            </div>
          </div>
        </div>
        <div class="main-container">
          <div class="pd-ltr-20">
            <!-- Bordered table  start -->
            <!-- Simple Datatable start -->
            <div class="card-box mb-30">
              <div class="pd-20">
                <h4 class="text-blue h4">Extra Outputs</h4>
                <p class="mb-0">
                  Note: Not all checks will have a location output because the system might not meet the condition for the check.
                </p>
              </div>
              <div class="pb-20">
                <table class="data-table table nowrap">
                  <thead>
                    <tr>
                      <th class="table-plus">Extra Checks</th>
                      <th class="datatable-nosort">Location</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">RAM CAPTURE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="RAM">/RAM</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">AuthLogs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="OTHER">/OTHER</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">BROWSING HISTORY</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="BROWSING_HISTORY">/BROWSING_HISTORY</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">NETWORK TRACE</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="PCAP">/PCAP</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Open Files</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="OTHER">/OTHER</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Timeline Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="timeline_logs">/timeline_logs</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Web Logs</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue"
                          href="Weblogs">/WEBLOGS</a>
                      </td>
                    </tr>
                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Ransomware Extensions</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="RANSOM_MALICIOUS">/RANSOM_MALICIOUS</a>
                      </td>
                    </tr>

                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">Current User Bash Profile</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="OTHER">/OTHER</a>
                      </td>
                    </tr>

                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">PCI Devices</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="OTHER">/OTHER</a>
                      </td>
                    </tr>

                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">IP only connections</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="OTHER">/OTHER</a>
                      </td>
                    </tr>

                    <tr>
                      <td class="table-plus">
                        <span class="badge badge-pill table-badge">IP only connection2</span>
                      </td>
                      <td>
                        <a target="_blank" class="text-blue" href="OTHER">/OTHER</a>
                      </td>
                    </tr>

                  </tbody>
                </table>
              </div>
            </div>
            <!-- Simple Datatable End -->
            <!-- Bordered table End -->
          </div>
        </div>
        <!-- Export Datatable End -->
      </div>
      <div class="footer-wrap pd-20 mb-20 card-box">
        Live Forensicator - Coded By
        <a href="https://github.com/Johnng007/Live-Forensicator" target="_blank">The Black Widow</a>
      </div>
    </div>
  </div>

  <!-- js -->

  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/core.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/core.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/script.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/script.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/process.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/process.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/layout-settings.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/layout-settings.js"><\/script>')</script>
  <script type="text/javascript"
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/jquery.dataTables.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/jquery.dataTables.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.responsive.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/dataTables.responsive.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatables/js/responsive.bootstrap4.min.js"><\/script>')</script>
  <!-- buttons for Export datatable -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/dataTables.buttons.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatablges/js/dataTables.buttons.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.bootstrap4.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.bootstrap4.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.print.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.print.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.html5.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.html5.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/buttons.flash.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/buttons.flash.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/pdfmake.min.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/pdfmake.min.js"><\/script>')</script>
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/src/plugins/datatables/js/vfs_fonts.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/src/plugins/datatabgles/js/vfs_fonts.js"><\/script>')</script>
  <!-- Datatable Setting js -->
  <script
    src="https://cdn.jsdelivr.net/gh/Johnng007/Live-Forensicator@main/styles/vendors/scripts/datatable-setting.js"></script>
  <script>window.jQuery || document.write('<script src="../../styles/vendors/scripts/datatable-setting.js"><\/script>')</script>


</body>

</html>

EOL

green "[!] All Done"
