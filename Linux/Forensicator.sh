#!/bin/bash

# Live Forensicator Bash Script
# Coded by Ebuka John Onyejegbu

# Make all relative paths (./config.json, ./Forensicator-Share/*, output dirs)
# resolve against the script's own location rather than the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "Error: unable to resolve script directory"; exit 1; }

# Resolve how to run commands that need root once, instead of hardcoding sudo
# at each call site (some distros/containers run as root with no sudo binary
# installed, and interactive sudo would otherwise hang a non-interactive run).
if [[ $EUID -eq 0 ]]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo -n"
else
    SUDO=""
fi

# Paths to prune from any full-filesystem find(1) walk below: pseudo/virtual
# filesystems that are large, meaningless to search, and slow to traverse.
PRUNE_PATHS=(-path /proc -o -path /sys -o -path /dev -o -path /run)

# Defining parameters
usage() {
    echo "Usage: $0 [-p|--pcap] [-r|--ram] [-s|--ransom] [-w|--weblogs] [-b|--browser] [-t|--timeline START_DATE END_DATE] [-log|--logfiles LOG_FILES] [-logdir|--logdir LOG_DIR] [-e|--encrypt] [-d|--decrypt] [-u|--usage] [-z|--update] [-name|--name NAME] [-case|--case CASE] [-title|--title TITLE] [-loc|--location LOCATION] [-device|--device DEVICE]"
    echo "  -p, --pcap            Record network traffic for 60 seconds and save as a pcap file"
    echo "  -r, --ram             Extract the system RAM"
    echo "  -s, --ransom          Check filesystem for ransomware encrypted files"
    echo "  -w, --weblogs         Collect Webserver logs"
    echo "  -b, --browser         Collect browsing history"
    echo "  -t, --timeline        Incident timeline helpful when extracting logs"
    echo "  -log, --logfiles      Log filenames to search through"
    echo "  -logdir, --logdir     Log directory to search through"
    echo "  -H, --hashcheck       Hash check running process executables against known bad hash lists"
    echo "  -e, --encrypt         Encrypts the Forensicator extracted artifacts"
    echo "  -d, --decrypt FILE    Decrypts an encrypted Forensicator artifact"
    echo "  -u, --usage           Shows the tool usage"
    echo "  -z, --update          Updates your copy of Forensicator"
    echo "  -name, --name         Supply Investigator name as a flag"
    echo "  -case, --case         Supply case reference as a flag"
    echo "  -title, --title       Supply Investigation title as a flag"
    echo "  -loc, --location      Supply Examination location as a flag"
    echo "  -device, --device     Supply Examination device as a flag"
    exit 1
}

# create working directory

create_directory(){
    WORKDIR=$(hostname)
    if [ -d "$WORKDIR" ]; then
        echo "Removing $WORKDIR"
        rm -rf "$WORKDIR"
    elif [ -f "$WORKDIR" ]; then
        echo "File with this name already exists, not a directory."
        exit
    fi
    if mkdir "$WORKDIR"; then
        echo "Directory created: $WORKDIR"
        return 0
    else
        echo "Creating directory failed: $WORKDIR"
        return 1
    fi
}

create_directory

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

# print messages in yellow color
yellow() {
    echo -e "\e[33m$@\e[0m"
}

# Read a simple string array from config.json without adding a jq dependency.
read_config_array() {
    local key="$1"
    local json_file="./config.json"

    if [[ ! -f "$json_file" ]]; then
        return 1
    fi

    awk -v key="$key" '
        $0 ~ "\"" key "\"[[:space:]]*:[[:space:]]*\\[" { in_array=1; next }
        in_array && /\]/ { exit }
        in_array {
            while (match($0, /"([^"]+)"/)) {
                print substr($0, RSTART + 1, RLENGTH - 2)
                $0 = substr($0, RSTART + RLENGTH)
            }
        }
    ' "$json_file"
}

# Prefer the first config array key that exists and has values.
read_first_available_config_array() {
    local key
    local values

    for key in "$@"; do
        values=$(read_config_array "$key")
        if [[ -n "$values" ]]; then
            printf '%s\n' "$values"
            return 0
        fi
    done

    return 1
}

# Search captured content for IOC matches and write normalized hits to disk.
write_ioc_matches() {
    local key_spec="$1"
    local output_file="$2"
    shift 2
    local sources=("$@")
    local indicator
    local source_name
    local source_data
    local match_found

    : >"$output_file"

    while IFS= read -r indicator; do
        [[ -z "$indicator" ]] && continue
        for source_name in "${sources[@]}"; do
            source_data="${!source_name}"
            [[ -z "$source_data" ]] && continue
            while IFS= read -r line; do
                printf '%s|%s|%s\n' "$indicator" "$source_name" "$line" >>"$output_file"
                match_found=1
            done < <(printf '%s\n' "$source_data" | grep -iF -- "$indicator")
        done
    done < <(IFS='|' read -r -a keys <<< "$key_spec"; read_first_available_config_array "${keys[@]}")

    if [[ -z "$match_found" ]]; then
        echo "No matches found" >"$output_file"
    else
        sort -u "$output_file" -o "$output_file"
    fi
}


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

echo ""
echo -e "\e[36m[!] https://forensicator.io\e[0m"
echo -e "\e[36m[!] https://github.com/Johnng007/Live-Forensicator\e[0m"
echo ""

yellow "====================================================="
yellow "[!] Heads up: the HTML report renders best on Windows"
yellow "[!] because Windows collectors return structured, tabular"
yellow "[!] data. Most Linux command output (ps, ss, journalctl,"
yellow "[!] etc.) is free-form text, so some HTML report panels may"
yellow "[!] show raw text blocks instead of neatly split columns."
yellow "[!] The underlying JSON findings under investigation/ are"
yellow "[!] collected the same way regardless and remain fully"
yellow "[!] reliable for analysis."
yellow "====================================================="
echo ""

# ── Forensicator AI status check ─────────────────────────────────────────────
# A real reachability probe (not just "enabled in config.json"), printed
# once up front so the operator knows before collection starts whether
# findings will get an AI verdict this run. Never blocks/fails the
# acquisition — any outcome here is purely informational. FAI_ENABLED is
# cached here (not re-derived per finding) so write_finding_json()'s
# per-finding AI call is a single cheap comparison, with zero overhead
# when AI is off. Mirrors the Windows collector's own startup probe.
FAI_ENABLED="false"
FAI_BANNER_SHOWN=0
FAI_FINDING_COUNTER=0
if command -v python3 >/dev/null 2>&1; then
    fai_probe_result=$(python3 "./Forensicator-Share/forensicator_ai_client.py" probe 2>/dev/null)
    case "$fai_probe_result" in
        DISABLED)
            echo -e "\e[90m[•] Forensicator AI : Disabled — set ai.enabled=true in config.json for AI verdicts on findings\e[0m"
            ;;
        ONLINE*)
            FAI_ENABLED="true"
            green "[✓] Forensicator AI : ${fai_probe_result#ONLINE } responded — findings will include AI verdicts this run."
            ;;
        UNREACHABLE*)
            # Deliberately leave FAI_ENABLED false here — a divergence from
            # the Windows collector, which attempts a full-timeout call per
            # finding regardless of probe outcome. On an unattended run
            # with ~90 checks and a default 60s timeout, that's up to 90
            # minutes lost to a config that just failed the same reachability
            # test seconds ago. If the endpoint comes back mid-run there's
            # no way to know, but that's an acceptable tradeoff against a
            # near-hour of dead time on a run that's already unattended.
            yellow "[!] Forensicator AI : Enabled but unreachable — ${fai_probe_result#UNREACHABLE }"
            yellow "[!] Forensicator AI : Findings will NOT include AI verdicts this run."
            ;;
        *)
            echo -e "\e[90m[•] Forensicator AI : Status check produced no result — continuing without it.\e[0m"
            ;;
    esac
else
    echo -e "\e[90m[•] Forensicator AI : python3 not found — AI verdicts unavailable this run\e[0m"
fi
echo ""

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
    if ! command -v curl >/dev/null 2>&1; then
        cyan "[!] curl not found; skipping update check."
        return 0
    fi

    # Fetch the version from GitHub
    remoteVersion=$(curl -s $rawUrl | tr -d '[:space:]')
    if [[ -z "$remoteVersion" ]]; then
        cyan "[!] Could not reach GitHub to check for updates."
        return 0
    fi

    # Compare local and remote versions
    if [[ $MyVersion < $remoteVersion ]]; then
        cyan "[!] A new version $remoteVersion is available on GitHub. Please upgrade your copy of Forensicator."
    else
        green "[!] You are using the latest version $MyVersion. No updates available."
    fi
}

# Call the function to check for updates
CheckForUpdates

    validate_date() {
        date -d "$1" "+%Y-%m-%d %H:%M:%S" &>/dev/null
        if [[ $? -ne 0 ]]; then
            echo "Invalid date format: $1"
            usage
        fi
    }

# Function to record network traffic for 60 seconds and save as a pcap file
pcap() {
    mkdir -p "$(hostname)/PCAP"
    cyan "Recording network traffic for 60 seconds..."
    $SUDO tcpdump -i any -w "./$(hostname)/PCAP/network_traffic.pcap" -G 60 -W 1 &>/dev/null
    green "Network traffic recorded and saved"
}

# Function to Extract RAM
ram() {
    mkdir -p "$(hostname)/RAM"
    cyan "Extracting RAM"
    ./Forensicator-Share/avml --compress "./$(hostname)/RAM/$(hostname).lime.compressed"
    green "RAM extracted, compressed and saved"

}

# Function to collect webserver logs
weblogs() {
    mkdir -p "$(hostname)/WEBLOGS"
    cyan "Checking the existence of Apache logs..."

    # DAYS_DIFF is only meaningful when -t/--timeline supplied a START_DATE;
    # otherwise fall back to a fixed lookback so `-w` alone still collects logs
    # instead of silently matching nothing (-mtime -0).
    if [[ -n "$START_DATE" ]]; then
        TODAY=$(date +%s)
        START_DATE_SECONDS=$(date -d "$START_DATE" +%s)
        DAYS_DIFF=$(( (TODAY - START_DATE_SECONDS) / (60*60*24) ))
    else
        DAYS_DIFF=30
    fi

    apache_logs_dir=$(apachectl -V 2>/dev/null | grep -w "SERVER_CONFIG_FILE" | sed 's/ -D //' | sed 's/.*"\(.*\)".*/\1/' | xargs -r dirname)
    if [[ -n "$apache_logs_dir" && -d "$apache_logs_dir" ]]; then
        find "$apache_logs_dir" -type f -name "*.log" -mtime -"$DAYS_DIFF" -exec cp {} "$(hostname)/WEBLOGS" \;
        green "Apache logs extracted and copied"
    else
        cyan "Looks like there are no Apache webservers"
    fi

    cyan "Checking the existence of NGINX logs..."
    nginx_logs_dir=$(nginx -V 2>&1 | grep -oP '(?<=--error-log-path=)\S+' | xargs -r dirname)
    if [[ -n "$nginx_logs_dir" && -d "$nginx_logs_dir" ]]; then
        find "$nginx_logs_dir" -type f -name "*.log" -mtime -"$DAYS_DIFF" -exec cp {} "$(hostname)/WEBLOGS" \;
        green "Nginx logs extracted and copied"
    else
        cyan "Looks like there are no NGINX webservers"
    fi
}

# Sanitize a string for use in a filename without requiring the external
# `detox` tool (not installed by default on most distros).
sanitize_filename() {
    echo "$1" | tr -cd '[:alnum:]._-'
}

# Function to get browsing history
browser() {
    {
        cyan "[*] Getting Browsing History"
        mkdir -p "$(hostname)/BROWSING_HISTORY"
        for home_root in /root /home/*; do
            [[ -d "$home_root" ]] || continue
            for database in $(find "$home_root" -name 'places.sqlite' 2>/dev/null); do
                profilename=$(basename "$(dirname "$database")")
                outname="history-firefox_$(date +%F_%H-%M-%S)_$(sanitize_filename "$profilename")"
                {
                    echo ".headers on"
                    echo ".mode csv"
                    echo ".output $(hostname)/BROWSING_HISTORY/$outname.csv"
                    echo "SELECT moz_historyvisits.visit_date, moz_places.url, moz_places.title
                FROM moz_places, moz_historyvisits
                    WHERE moz_places.id = moz_historyvisits.place_id;"
                } | ./Forensicator-Share/sqlite3 "$database"
            done
        done
    } &>/dev/null

    {
        for home_root in /root /home/*; do
            [[ -d "$home_root" ]] || continue
            for database in $(find "$home_root" -name 'History' 2>/dev/null); do
                profilename=$(basename "$(dirname "$database")")
                if [[ "$profilename" == 'System Profile' ]]; then
                    continue
                fi
                if command -v detox >/dev/null 2>&1; then
                    detoxprofilename=$(echo "$profilename" | detox --inline)
                else
                    detoxprofilename=$(sanitize_filename "$profilename")
                fi
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
        done
    } &>/dev/null

    green "[!] Done"
}

# Function to check for Ransomware encrypted files
ransom() {

    mkdir -p $(hostname)/RANSOM_MALICIOUS

    cyan "[*] Checking ransomware-encrypted files.."
    cyan "[*] This may take a while.."
    # Function to search for files with given extensions in a single filesystem
    # walk instead of one full "find /" pass per extension.
    search_files() {
        local Ransomware_Extensions=("$@")
        local name_expr=()
        local ext
        for ext in "${Ransomware_Extensions[@]}"; do
            if [[ ${#name_expr[@]} -gt 0 ]]; then
                name_expr+=(-o)
            fi
            name_expr+=(-name "*$ext")
        done
        find / \( "${PRUNE_PATHS[@]}" \) -prune -o -type f \( "${name_expr[@]}" \) -print 2>/dev/null
    }

    # Check if the JSON file exists
    json_file="./config.json"
    if [ ! -f "$json_file" ]; then
        echo "Error: JSON file '$json_file' not found."
        exit 1
    fi

    # Read the file extensions from the JSON file
    Ransomware_Extensions=($(grep -o '"\.[^"]*"' "$json_file" | tr -d '"'))

    # Define the output directory and file

    # Search for files with the specified extensions and output to a text file
    # echo "Searching for files with extensions similar to ransomware encrypted files..."
    search_files "${Ransomware_Extensions[@]}" >"$(hostname)/RANSOM_MALICIOUS/$(hostname)_ransom.txt"
    green "[!] Done"

}

# Function to check for recently created/modified executables — Linux analogue
# of the Windows "Recently Created Executables" (new_files) collector. Scoped
# to config-driven search paths (never a full "/" walk) with a config-driven
# lookback window and excluded directory names.
new_files_check() {
    set +e
    cyan "[*] Checking for recently modified executables"

    local days_back
    days_back=$(read_config_array "new_files_days_back" | head -1)
    [[ -z "$days_back" || ! "$days_back" =~ ^[0-9]+$ ]] && days_back=1

    local search_paths=()
    while IFS= read -r p; do
        [[ -n "$p" ]] && search_paths+=("$p")
    done < <(read_config_array "new_files_search_paths")
    if [[ ${#search_paths[@]} -eq 0 ]]; then
        search_paths=(/tmp /var/tmp /dev/shm /home /root /opt /var/www /srv)
    fi

    local excluded_dirs=()
    while IFS= read -r d; do
        [[ -n "$d" ]] && excluded_dirs+=("$d")
    done < <(read_config_array "new_files_excluded_dir_names")
    if [[ ${#excluded_dirs[@]} -eq 0 ]]; then
        excluded_dirs=(node_modules .git .hg .svn vendor dist build target __pycache__ venv .venv .next .nuxt)
    fi

    local prune_expr=()
    local d
    for d in "${excluded_dirs[@]}"; do
        [[ ${#prune_expr[@]} -gt 0 ]] && prune_expr+=(-o)
        prune_expr+=(-name "$d")
    done

    local existing_paths=()
    local p
    for p in "${search_paths[@]}"; do
        [[ -d "$p" ]] && existing_paths+=("$p")
    done

    F_new_files=""
    if [[ ${#existing_paths[@]} -gt 0 ]]; then
        F_new_files=$(find "${existing_paths[@]}" -type d \( "${prune_expr[@]}" \) -prune -o \
            -type f -executable -newermt "-${days_back} day" -printf '%TY-%Tm-%Td %TH:%TM  %10s bytes  %m  %p\n' \
            2>/dev/null | sort -r | head -200)
    fi

    if [[ -z "$F_new_files" ]]; then
        F_new_files="No recently modified executables found in the last ${days_back} day(s)"
    fi

    green "[!] Done"
    set -e
}

# Function to check config-driven Linux IOCs in collected process and persistence data
ioc_checks() {
    mkdir -p "$(hostname)/OTHER"

    cyan "[*] Checking suspicious executables and shell commands from config.json"

    IOC_EXECUTABLES_FILE="./$(hostname)/OTHER/suspicious_executables.txt"
    IOC_SHELL_COMMANDS_FILE="./$(hostname)/OTHER/suspicious_shell_commands.txt"

    write_ioc_matches \
        "suspicious_executables" \
        "$IOC_EXECUTABLES_FILE" \
        F_ps F_services F_systemctl F_cron2 F_p1 F_p2 F_p3 F_p4 F_p5 F_p6 F_p7 F_p8 F_p9

    write_ioc_matches \
        "suspicious_SH_commands|suspicious_PS_commands" \
        "$IOC_SHELL_COMMANDS_FILE" \
        F_ps F_cron2 F_p1 F_p2 F_p3 F_p4 F_p5 F_p6 F_p7 F_p8 F_p9 F_bashrc

    F_suspicious_exec_hits=$(cat "$IOC_EXECUTABLES_FILE")
    F_suspicious_cmd_hits=$(cat "$IOC_SHELL_COMMANDS_FILE")

    green "[!] Done"
}

# Function to hash check running process executables
hash_check() {
    set +e
    mkdir -p "$(hostname)/DETECTIONS"
    local outfile="$(hostname)/DETECTIONS/hash_matches.txt"
    : >"$outfile"
    local hit_found=0
    cyan "[*] Running hash check on running process executables"

    # Auto-download the known-bad MD5 feed (default: abuse.ch MalwareBazaar
    # recent list), refreshing it when missing or older than 7 days -- same
    # feed and staleness policy as the Windows hash-check collector.
    local hash_source
    hash_source=$(read_config_array "hash_source" | head -1)
    [[ -z "$hash_source" ]] && hash_source="https://bazaar.abuse.ch/export/txt/md5/recent/"

    local hash_file="$SCRIPT_DIR/Forensicator-Share/md5hashes.txt"
    local custom_hash_file="$SCRIPT_DIR/Forensicator-Share/custom_hashes.txt"

    local needs_download=0
    if [[ ! -s "$hash_file" ]]; then
        needs_download=1
    else
        local age_days
        age_days=$(( ( $(date +%s) - $(date -r "$hash_file" +%s 2>/dev/null || echo 0) ) / 86400 ))
        if [[ $age_days -gt 7 ]]; then
            needs_download=1
            echo "[!] Hash feed is ${age_days} days old -- refreshing"
        fi
    fi

    if [[ $needs_download -eq 1 ]]; then
        if command -v curl >/dev/null 2>&1; then
            cyan "[*] Downloading known-bad MD5 hash feed from $hash_source"
            if curl -s --max-time 60 -o "${hash_file}.tmp" "$hash_source" && [[ -s "${hash_file}.tmp" ]]; then
                mv -f "${hash_file}.tmp" "$hash_file"
                green "[!] Hash feed downloaded"
            else
                rm -f "${hash_file}.tmp"
                echo "[!] Hash feed download failed -- using cached copy if available"
            fi
        else
            echo "[!] curl not found -- cannot download hash feed, using cached copy if available"
        fi
    fi

    local hash_files=()
    [[ -f "$hash_file" ]] && hash_files+=("$hash_file")
    [[ -f "$custom_hash_file" ]] && hash_files+=("$custom_hash_file")

    if [[ ${#hash_files[@]} -eq 0 ]]; then
        echo "No hash list files available (feed download failed and no custom hash file found)" >"$outfile"
        green "[!] Hash check done (no hash lists found)"
        set -e
        return 0
    fi

    # Get unique exe paths from /proc
    local exe_paths
    exe_paths=$(ls -la /proc/*/exe 2>/dev/null | awk '{print $NF}' | sort -u)

    while IFS= read -r exe_path; do
        [[ -z "$exe_path" ]] && continue
        [[ ! -f "$exe_path" ]] && continue
        local computed_hash
        computed_hash=$(md5sum "$exe_path" 2>/dev/null | awk '{print $1}')
        [[ -z "$computed_hash" ]] && continue
        for hf in "${hash_files[@]}"; do
            if grep -qiF "$computed_hash" "$hf" 2>/dev/null; then
                echo "HASH_MATCH|${computed_hash}|${exe_path}" >>"$outfile"
                hit_found=1
            fi
        done
    done <<< "$exe_paths"

    if [[ $hit_found -eq 0 ]]; then
        echo "No hash matches found" >"$outfile"
    fi
    green "[!] Hash check done"
    set -e
}

# Function to check browser history CSV files for malicious URLs/IOCs
browser_ioc_check() {
    set +e
    mkdir -p "$(hostname)/DETECTIONS"
    local outfile="$(hostname)/DETECTIONS/browser_ioc_matches.txt"
    : >"$outfile"
    local hit_found=0
    cyan "[*] Running browser IOC check"

    # Auto-download the malicious URL/domain feed (default: abuse.ch URLhaus
    # recent list) if it isn't already present -- same feed and
    # download-if-missing policy as the Windows browser-IOC collector.
    local url_source
    url_source=$(read_config_array "url_source" | head -1)
    [[ -z "$url_source" ]] && url_source="https://urlhaus.abuse.ch/downloads/text_recent/"

    local malicious_urls_file="$SCRIPT_DIR/Forensicator-Share/malicious_URLs.txt"
    local custom_iocs_file="$SCRIPT_DIR/Forensicator-Share/custom_iocs.txt"

    if [[ ! -s "$malicious_urls_file" ]] && command -v curl >/dev/null 2>&1; then
        cyan "[*] Downloading malicious URL feed from $url_source"
        if curl -s --max-time 60 -o "${malicious_urls_file}.tmp" "$url_source" && [[ -s "${malicious_urls_file}.tmp" ]]; then
            mv -f "${malicious_urls_file}.tmp" "$malicious_urls_file"
            green "[!] Malicious URL feed downloaded"
        else
            rm -f "${malicious_urls_file}.tmp"
            echo "[!] Malicious URL feed download failed"
        fi
    fi

    local ioc_files=()
    [[ -f "$malicious_urls_file" ]] && ioc_files+=("$malicious_urls_file")
    [[ -f "$custom_iocs_file" ]] && ioc_files+=("$custom_iocs_file")

    local history_dir="$(hostname)/BROWSING_HISTORY"
    if [[ ! -d "$history_dir" ]]; then
        echo "No browsing history directory found" >"$outfile"
        green "[!] Browser IOC check done (no history directory)"
        set -e
        return 0
    fi

    if [[ ${#ioc_files[@]} -eq 0 ]]; then
        echo "No IOC list files found in Forensicator-Share/ (feed download failed and no custom IOC file found)" >"$outfile"
        green "[!] Browser IOC check done (no IOC lists found)"
        set -e
        return 0
    fi

    while IFS= read -r csv_file; do
        [[ -z "$csv_file" ]] && continue
        for ioc_file in "${ioc_files[@]}"; do
            while IFS= read -r pattern; do
                [[ -z "$pattern" ]] && continue
                while IFS= read -r match_line; do
                    echo "URL_IOC|${pattern}|${match_line}" >>"$outfile"
                    hit_found=1
                done < <(grep -iF "$pattern" "$csv_file" 2>/dev/null)
            done <"$ioc_file"
        done
    done < <(find "$history_dir" -name "*.csv" 2>/dev/null)

    if [[ $hit_found -eq 0 ]]; then
        echo "No browser IOC matches found" >"$outfile"
    fi
    green "[!] Browser IOC check done"
    set -e
}

# Detection engine - 25 rules
run_detections() {
    set +e
    mkdir -p "$(hostname)/DETECTIONS"
    local findings_file="$(hostname)/DETECTIONS/findings.csv"
    echo "severity,mitre_technique,category,description,evidence" >"$findings_file"

    F_DETECTION_CRITICAL=0
    F_DETECTION_HIGH=0
    F_DETECTION_MEDIUM=0
    F_DETECTION_LOW=0

    add_finding() {
        local severity="$1"
        local mitre="$2"
        local category="$3"
        local description="$4"
        local evidence="$5"
        # Escape commas in evidence
        evidence="${evidence//,/;}"
        echo "${severity},${mitre},${category},${description},${evidence}" >>"$findings_file"
        case "$severity" in
            CRITICAL) ((F_DETECTION_CRITICAL++)) ;;
            HIGH)     ((F_DETECTION_HIGH++)) ;;
            MEDIUM)   ((F_DETECTION_MEDIUM++)) ;;
            LOW)      ((F_DETECTION_LOW++)) ;;
        esac
    }

    cyan "[*] Running detection engine"

    # Rule 1: Reverse shell indicators in ps
    local rev_shell_hits
    rev_shell_hits=$(echo "$F_ps" | grep -iE 'bash -i|/dev/tcp/|nc -e|socat tcp-connect|python.*socket' 2>/dev/null | head -5)
    if [[ -n "$rev_shell_hits" ]]; then
        add_finding "CRITICAL" "T1059.004" "Reverse Shell" "Reverse shell pattern detected in running processes" "$(echo "$rev_shell_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 2: Executables running from suspicious temp dirs
    local tmp_exe_hits
    tmp_exe_hits=$(echo "$F_ps" | grep -E ' (/tmp/|/dev/shm/|/var/tmp/)' 2>/dev/null | head -5)
    if [[ -n "$tmp_exe_hits" ]]; then
        add_finding "HIGH" "T1059" "Execution from Temp" "Process executing from suspicious temporary directory" "$(echo "$tmp_exe_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 3: Known attack tools in ps
    local attack_tool_hits
    attack_tool_hits=$(echo "$F_ps" | grep -iE 'mimikatz|linpeas|meterpreter|empire|sliver|cobaltstr|chisel|bloodhound' 2>/dev/null | head -5)
    if [[ -n "$attack_tool_hits" ]]; then
        add_finding "CRITICAL" "T1588" "Attack Tool" "Known attack tool detected in running processes" "$(echo "$attack_tool_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 4: SUID binaries outside standard dirs
    local suid_hits
    suid_hits=$(echo "$F_suid" | grep -vE '^(/usr/bin/|/usr/lib/|/bin/|/sbin/|/usr/sbin/)' 2>/dev/null | head -5)
    if [[ -n "$suid_hits" ]]; then
        add_finding "HIGH" "T1548.001" "SUID Abuse" "SUID binary found outside standard system directories" "$(echo "$suid_hits" | head -1)"
    fi

    # Rule 5: Dangerous capabilities
    local cap_hits
    cap_hits=$(echo "$F_getcap3" | grep -E 'cap_setuid\+ep|cap_sys_admin\+ep' 2>/dev/null | head -5)
    if [[ -n "$cap_hits" ]]; then
        add_finding "HIGH" "T1548.001" "Dangerous Capabilities" "Binary with dangerous capability (cap_setuid+ep or cap_sys_admin+ep) detected" "$(echo "$cap_hits" | head -1)"
    fi

    # Rule 6: Non-root accounts with UID 0
    local uid0_hits
    uid0_hits=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd 2>/dev/null)
    if [[ -n "$uid0_hits" ]]; then
        add_finding "CRITICAL" "T1078.003" "UID 0 Account" "Non-root account with UID 0 found in /etc/passwd" "$uid0_hits"
    fi

    # Rule 7: wget/curl/bash -i/nc in cron entries
    local cron_hits
    cron_hits=$(echo "$F_cron2" | grep -iE 'wget|curl|bash -i|nc ' 2>/dev/null | head -5)
    if [[ -n "$cron_hits" ]]; then
        add_finding "HIGH" "T1053.003" "Malicious Cron" "Suspicious download or shell command detected in cron entry" "$(echo "$cron_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 8: Brute force - >10 failed logins from same IP
    local brute_hits
    brute_hits=$(grep -iE 'failed|failure|invalid' /var/log/auth.log 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort | uniq -c | sort -rn | awk '$1>10 {print $0}' | head -5)
    if [[ -n "$brute_hits" ]]; then
        add_finding "HIGH" "T1110.001" "Brute Force" "More than 10 failed login attempts from same IP detected in auth.log" "$(echo "$brute_hits" | head -1)"
    fi

    # Rule 9: Custom systemd unit files
    local systemd_custom
    systemd_custom=$(find /etc/systemd/system/ -maxdepth 1 -name "*.service" -newer /etc/passwd 2>/dev/null | head -5)
    if [[ -n "$systemd_custom" ]]; then
        add_finding "MEDIUM" "T1543.002" "Systemd Persistence" "Custom systemd unit file(s) detected in /etc/systemd/system/" "$(echo "$systemd_custom" | head -1)"
    fi

    # Rule 10: Log clearing commands in auth logs
    local logclear_hits
    logclear_hits=$(grep -iE 'rm.*\.log|truncate|> /var/log|shred' /var/log/auth.log 2>/dev/null | head -5)
    if [[ -n "$logclear_hits" ]]; then
        add_finding "HIGH" "T1070.002" "Log Clearing" "Log clearing command detected in auth logs" "$(echo "$logclear_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 11: Docker container escape via volume mount
    local docker_escape_hits
    docker_escape_hits=$(echo "$F_ps" | grep -E 'docker run.*-v /:/|docker run.*--privileged' 2>/dev/null | head -5)
    if [[ -n "$docker_escape_hits" ]]; then
        add_finding "CRITICAL" "T1611" "Container Escape" "Docker container escape attempt detected (root filesystem mounted)" "$(echo "$docker_escape_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 12: authorized_keys outside /home/ or /root/
    local authkeys_hits
    authkeys_hits=$(echo "$F_keys" | grep -vE '^(/home/|/root/)' 2>/dev/null | head -5)
    if [[ -n "$authkeys_hits" ]]; then
        add_finding "HIGH" "T1098.004" "SSH Key Implant" "authorized_keys file found in unexpected location (not /home/ or /root/)" "$(echo "$authkeys_hits" | head -1)"
    fi

    # Rule 13: Kernel modules with rootkit-related names
    local rootkit_mod_hits
    rootkit_mod_hits=$(echo "$F_lsmod" | grep -iE 'rootkit|hide|hook|intercept' 2>/dev/null | head -5)
    if [[ -n "$rootkit_mod_hits" ]]; then
        add_finding "CRITICAL" "T1014" "Rootkit Module" "Kernel module with rootkit/hiding-related name detected" "$(echo "$rootkit_mod_hits" | head -1)"
    fi

    # Rule 14: Services on non-standard ports (ports above 1024 that are not common)
    local nonstandard_ports
    nonstandard_ports=$(echo "$F_ss2" | grep LISTEN | grep -oE ':[0-9]+' | grep -oE '[0-9]+' | awk '$1>1024 && $1!=3306 && $1!=5432 && $1!=8080 && $1!=8443 && $1!=27017 {print $1}' | sort -u | head -5)
    if [[ -n "$nonstandard_ports" ]]; then
        add_finding "MEDIUM" "T1049" "Non-Standard Ports" "Services listening on non-standard ports detected" "$(echo "$nonstandard_ports" | tr '\n' ' ')"
    fi

    # Rule 15: /etc/ld.so.preload exists and non-empty
    if [[ -s /etc/ld.so.preload ]]; then
        local preload_content
        preload_content=$(cat /etc/ld.so.preload 2>/dev/null | head -3 | tr '\n' ' ')
        add_finding "CRITICAL" "T1574.006" "LD Preload Hijack" "/etc/ld.so.preload exists and is non-empty (possible library injection)" "$preload_content"
    fi

    # Rule 16: Hidden executables in /home or /root
    local hidden_exe
    hidden_exe=$(find /home /root -maxdepth 4 -name ".*" -type f -executable 2>/dev/null | head -5)
    if [[ -n "$hidden_exe" ]]; then
        add_finding "MEDIUM" "T1564.001" "Hidden Executable" "Hidden executable file(s) found in home directories" "$(echo "$hidden_exe" | head -1)"
    fi

    # Rule 17: LD_PRELOAD/LD_LIBRARY_PATH in /proc/*/environ
    local ldpreload_hits
    ldpreload_hits=$(grep -la 'LD_PRELOAD\|LD_LIBRARY_PATH' /proc/*/environ 2>/dev/null | head -5)
    if [[ -n "$ldpreload_hits" ]]; then
        add_finding "HIGH" "T1574" "LD_PRELOAD in Process" "LD_PRELOAD or LD_LIBRARY_PATH set in running process environment" "$(echo "$ldpreload_hits" | head -1)"
    fi

    # Rule 18: .so files newer than /etc/passwd
    local new_so_files
    new_so_files=$(find / -name "*.so" -newer /etc/passwd -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null | head -5)
    if [[ -n "$new_so_files" ]]; then
        add_finding "LOW" "T1070.006" "New Shared Libraries" "Shared library (.so) files newer than /etc/passwd found" "$(echo "$new_so_files" | head -1)"
    fi

    # Rule 19: SSH port forwarding in process list
    local ssh_tunnel_hits
    ssh_tunnel_hits=$(echo "$F_ps" | grep -E 'ssh .*-[RLD]' 2>/dev/null | head -5)
    if [[ -n "$ssh_tunnel_hits" ]]; then
        add_finding "HIGH" "T1572" "SSH Tunneling" "SSH port forwarding detected in running processes" "$(echo "$ssh_tunnel_hits" | head -1 | tr '\n' ' ')"
    fi

    # Rule 20: tun/tap/wg network interfaces
    local tun_ifaces
    tun_ifaces=$(echo "$F_ip" | grep -oE '^[0-9]+: (tun|tap|wg)[0-9a-zA-Z@.]+' | awk '{print $2}' | head -5)
    if [[ -n "$tun_ifaces" ]]; then
        add_finding "LOW" "T1572" "VPN/Tunnel Interface" "tun/tap/wg network interface detected (possible VPN or tunnel)" "$(echo "$tun_ifaces" | head -1)"
    fi

    # Rule 21: process running from a deleted binary
    if [[ -n "$F_deleted_exe" && "$F_deleted_exe" != "No processes running from deleted binaries" ]]; then
        add_finding "CRITICAL" "T1070.004" "Deleted Binary Execution" "Process is running from a binary that no longer exists on disk (fileless/self-deleting malware indicator)" "$(echo "$F_deleted_exe" | head -1)"
    fi

    # Rule 22: kernel tainted by an out-of-tree or unsigned module
    if [[ "$F_kernel_taint" == *OUT_OF_TREE_MODULE* || "$F_kernel_taint" == *UNSIGNED_MODULE* ]]; then
        add_finding "HIGH" "T1014" "Kernel Taint" "Kernel is tainted by an out-of-tree or unsigned module (possible rootkit)" "$F_kernel_taint"
    fi

    # Rule 23: credential file with a ctime/mtime mismatch (timestomp indicator)
    local timestomp_hits
    timestomp_hits=$(echo "$F_cred_file_timeline" | grep 'POSSIBLE TIMESTOMP' | head -5)
    if [[ -n "$timestomp_hits" ]]; then
        add_finding "HIGH" "T1070.006" "Timestomping" "Credential file's ctime is newer than its mtime (the modification time may have been forged)" "$(echo "$timestomp_hits" | head -1)"
    fi

    # Rule 24: world-writable directory or file on $PATH
    if [[ -n "$F_path_ww" && "$F_path_ww" != "No world-writable directories or files found in \$PATH" ]]; then
        add_finding "HIGH" "T1574.007" "PATH Hijack Risk" "World-writable directory or file found on \$PATH -- any local user could plant a binary a privileged process resolves by name" "$(echo "$F_path_ww" | head -1)"
    fi

    # Rule 25: package-managed file with a checksum mismatch
    if [[ -n "$F_pkg_integrity" ]] && [[ "$F_pkg_integrity" != *"no modified package files detected"* ]] && [[ "$F_pkg_integrity" != *"not available"* ]]; then
        add_finding "HIGH" "T1554" "Package Integrity Violation" "A package-managed file's checksum no longer matches the package database (possible binary replacement/backdoor)" "$(echo "$F_pkg_integrity" | head -1)"
    fi

    F_DETECTION_TOTAL=$((F_DETECTION_CRITICAL + F_DETECTION_HIGH + F_DETECTION_MEDIUM + F_DETECTION_LOW))
    F_DETECTION_FILE="$findings_file"
    green "[!] Detection engine complete: $F_DETECTION_TOTAL findings ($F_DETECTION_CRITICAL critical, $F_DETECTION_HIGH high, $F_DETECTION_MEDIUM medium, $F_DETECTION_LOW low)"
    set -e
}

# Recompute F_DETECTION_* totals from the final findings.csv, since both the
# bash detection engine (run_detections) and the Sigma engine append rows to
# the same file — this is the single source of truth after both have run.
recompute_detection_totals() {
    local findings_file="$(hostname)/DETECTIONS/findings.csv"
    [[ -f "$findings_file" ]] || return 0
    F_DETECTION_CRITICAL=$(awk -F, 'NR>1 && $1=="CRITICAL"' "$findings_file" | wc -l | tr -d ' ')
    F_DETECTION_HIGH=$(awk -F, 'NR>1 && $1=="HIGH"' "$findings_file" | wc -l | tr -d ' ')
    F_DETECTION_MEDIUM=$(awk -F, 'NR>1 && $1=="MEDIUM"' "$findings_file" | wc -l | tr -d ' ')
    F_DETECTION_LOW=$(awk -F, 'NR>1 && $1=="LOW"' "$findings_file" | wc -l | tr -d ' ')
    F_DETECTION_TOTAL=$((F_DETECTION_CRITICAL + F_DETECTION_HIGH + F_DETECTION_MEDIUM + F_DETECTION_LOW))
}

# Real Sigma-rule detection engine for Linux: evaluates a compiled SigmaHQ
# Linux ruleset (Forensicator-Share/rules/linux/sigma_rules.json, compiled
# offline from real community rules) against auditd (if installed and has
# data) and journald (near-universal). Requires python3; skips cleanly and
# loudly if it isn't present — the rest of the collection is unaffected.
run_sigma_detections() {
    set +e
    cyan "[*] Running Sigma detection engine (Linux ruleset)"

    local python_bin=""
    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    fi

    if [[ -z "$python_bin" ]]; then
        echo "[!] Sigma engine skipped: python3 not found on this system"
        set -e
        return 0
    fi

    local rules_file="$SCRIPT_DIR/Forensicator-Share/rules/linux/sigma_rules.json"
    if [[ ! -f "$rules_file" ]]; then
        echo "[!] Sigma engine skipped: rules file not found ($rules_file)"
        set -e
        return 0
    fi

    local days_back min_level max_events
    days_back=$(read_config_array "sigma_days_back" | head -1)
    [[ -z "$days_back" || ! "$days_back" =~ ^[0-9]+$ ]] && days_back=7
    min_level=$(read_config_array "sigma_min_level" | head -1)
    [[ -z "$min_level" ]] && min_level="medium"
    max_events=$(read_config_array "sigma_max_events" | head -1)
    [[ -z "$max_events" || ! "$max_events" =~ ^[0-9]+$ ]] && max_events=25000

    mkdir -p "$(hostname)/DETECTIONS"
    local sigma_summary
    sigma_summary=$("$python_bin" "$SCRIPT_DIR/Forensicator-Share/sigma_runtime.py" \
        --rules "$rules_file" \
        --output "$(hostname)/DETECTIONS/findings.csv" \
        --days-back "$days_back" \
        --min-level "$min_level" \
        --max-events "$max_events" 2>/dev/null)

    if [[ -n "$sigma_summary" ]]; then
        green "[!] Sigma engine: $sigma_summary"
    else
        echo "[!] Sigma engine produced no output (check for python3 errors)"
    fi

    recompute_detection_totals
    set -e
}

# Function to write metadata JSON
write_metadata_json() {
    set +e
    mkdir -p "$(hostname)/investigation"
    local meta_file="$(hostname)/investigation/metadata.json"
    local os_version
    os_version=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')
    local kernel_ver
    kernel_ver=$(uname -r 2>/dev/null)
    local local_ip
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    local inv_id
    inv_id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "$(date +%s)-forensicator")

    cat >"$meta_file" <<METAEOF
{
  "investigation_id": "${inv_id}",
  "title": "${TITLE}",
  "operator": "${NAME}",
  "location": "${LOCATION}",
  "device": "${DEVICE}",
  "case_reference": "${CASE}",
  "hostname": "${Hostname}",
  "collection_start_time": "${startdate}",
  "collection_end_time": "${enddate}",
  "collector_version": "${MyVersion}",
  "collector_type": "Live-Forensicator",
  "os": {
    "platform": "Linux",
    "version": "${os_version}",
    "kernel": "${kernel_ver}"
  },
  "network": {
    "hostname": "${Hostname}",
    "local_ip": "${local_ip}"
  },
  "statistics": {
    "total_detections": ${F_DETECTION_TOTAL:-0},
    "critical": ${F_DETECTION_CRITICAL:-0},
    "high": ${F_DETECTION_HIGH:-0},
    "medium": ${F_DETECTION_MEDIUM:-0},
    "low": ${F_DETECTION_LOW:-0}
  }
}
METAEOF
    green "[!] Metadata JSON written"
    set -e
}

# Function to write structured logs
write_structured_log() {
    set +e
    mkdir -p "$(hostname)/LOGS"
    local log_file="$(hostname)/LOGS/${Hostname}_structured.csv"
    local findings_log="$(hostname)/LOGS/${Hostname}_findings_only.csv"
    local ts
    ts=$(date '+%Y-%m-%dT%H:%M:%S')

    echo "timestamp,level,section,message" >"$log_file"
    echo "timestamp,level,section,message" >"$findings_log"

    echo "${ts},INFO,collection,Collection started at ${startdate}" >>"$log_file"
    echo "${ts},INFO,collection,Collection ended at ${enddate}" >>"$log_file"
    echo "${ts},INFO,collection,Hostname: ${Hostname}" >>"$log_file"
    echo "${ts},INFO,collection,Operator: ${NAME}" >>"$log_file"
    echo "${ts},INFO,collection,Case: ${CASE}" >>"$log_file"

    if [[ -f "$(hostname)/DETECTIONS/findings.csv" ]]; then
        tail -n +2 "$(hostname)/DETECTIONS/findings.csv" | while IFS=, read -r severity mitre category description evidence; do
            echo "${ts},${severity},detections,${category}: ${description} [${mitre}] Evidence: ${evidence}" >>"$log_file"
            echo "${ts},${severity},detections,${category}: ${description} [${mitre}] Evidence: ${evidence}" >>"$findings_log"
        done
    fi

    echo "${ts},INFO,summary,Total detections: ${F_DETECTION_TOTAL:-0} (CRITICAL:${F_DETECTION_CRITICAL:-0} HIGH:${F_DETECTION_HIGH:-0} MEDIUM:${F_DETECTION_MEDIUM:-0} LOW:${F_DETECTION_LOW:-0})" >>"$log_file"
    green "[!] Structured logs written"
    set -e
}

##########################################################
# Per-check JSON output (for Forensicator Enterprise)
##########################################################

# Escape a string for safe embedding inside a JSON double-quoted value
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    # Replace literal newlines with \n
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# Convert multi-line text to a JSON array of {"data":"<line>"} objects
lines_to_json_array() {
    local input="$1"
    local first=1
    printf '['
    while IFS= read -r ln; do
        [[ -z "$ln" ]] && continue
        [[ $first -eq 0 ]] && printf ','
        printf '{"data":"%s"}' "$(json_escape "$ln")"
        first=0
    done <<< "$input"
    printf ']'
}

# Write a single per-check finding JSON file
# Args: category check_name finding_type title description command severity evidence_json
write_finding_json() {
    local category="$1"
    local check_name="$2"
    local finding_type="$3"
    local title="$4"
    local description="$5"
    local command="$6"
    local severity="${7:-INFO}"
    local evidence_json="${8:-[]}"

    local out_dir
    out_dir="$(hostname)/investigation/${category}"
    mkdir -p "$out_dir"
    local out_file="${out_dir}/${check_name}-finding.json"
    local ts
    ts=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ')
    local entry_count
    entry_count=$(printf '%s' "$evidence_json" | grep -o '"data"' | wc -l | tr -d ' ')

    cat > "$out_file" <<FINDINGJSON
{
  "finding_id": "$(json_escape "${CASE}")-$(json_escape "${check_name}")",
  "finding_type": "$(json_escape "${finding_type}")",
  "category": "$(json_escape "${category}")",
  "findingtags": ["forensicator", "$(json_escape "${category}")", "linux"],
  "severity": "$(json_escape "${severity}")",
  "host": {
    "hostname": "$(json_escape "${Hostname}")",
    "username": "$(json_escape "$(whoami 2>/dev/null || echo unknown)")"
  },
  "source": {
    "collector": "Live Forensicator",
    "artifact_type": "$(json_escape "${finding_type}")",
    "command": "$(json_escape "${command}")"
  },
  "summary": {
    "title": "$(json_escape "${title}")",
    "description": "$(json_escape "${description}")",
    "total_entries": ${entry_count}
  },
  "risk": {
    "score": 0,
    "level": "informational",
    "reason": "Raw forensic artifact collected for analysis"
  },
  "mitre": {},
  "ai_analysis": {"status": "pending"},
  "timeline": {
    "collection_timestamp": "${ts}",
    "event": "artifact_collected"
  },
  "evidence": ${evidence_json},
  "metadata": {
    "collector": "Live Forensicator",
    "version": "$(json_escape "${MyVersion}")",
    "platform": "Linux",
    "collection_time": "${ts}"
  }
}
FINDINGJSON

    # Forensicator AI (optional, opt-in via config.json's "ai" block — see
    # Forensicator-Share/forensicator_ai_client.py, a port of the Windows
    # collector's ForensicatorAiClient.ps1). Never allowed to fail or even
    # slow down collection when disabled: FAI_ENABLED is read once at
    # startup, so this is a single cheap string comparison per finding
    # when AI is off, with zero process spawned.
    if [[ "$FAI_ENABLED" == "true" ]]; then
        if [[ "$FAI_BANNER_SHOWN" != "1" ]]; then
            FAI_BANNER_SHOWN=1
            echo ""
            yellow "[*] Starting AI Analysis — each check's findings are sent to the configured LLM as they're collected."
            yellow "[*] This runs inline with acquisition and can noticeably extend total run time, especially on a cold-loaded model."
        fi
        FAI_FINDING_COUNTER=$((FAI_FINDING_COUNTER + 1))
        echo "  [AI ${FAI_FINDING_COUNTER}] Analyzing '${title}'..."
        local ai_result ai_ms
        ai_result=$(python3 "./Forensicator-Share/forensicator_ai_client.py" process "$out_file" 2>/dev/null)
        ai_ms="${ai_result##*ms=}"
        [[ "$ai_ms" == "$ai_result" || -z "$ai_ms" ]] && ai_ms="?"
        if [[ "$ai_result" == RESULT\ status=complete* ]]; then
            green "  [AI ${FAI_FINDING_COUNTER}] Verdict received (${ai_ms}ms)"
        else
            yellow "  [AI ${FAI_FINDING_COUNTER}] No verdict (${ai_ms}ms)"
        fi
    fi
}

# Generate all per-check finding JSON files
generate_findings_json() {
    set +e
    cyan "[*] Generating per-check finding JSONs for Forensicator Enterprise..."

    # --- NETWORK ---
    write_finding_json "network" "ip-addresses" "Network Interface Configuration" \
        "IP Address Configuration" "Network interface and IP address information" \
        "ip a" "INFO" "$(lines_to_json_array "${F_ip}")"

    write_finding_json "network" "routing-table" "Routing Table" \
        "IP Routing Table" "Kernel IP routing table entries" \
        "ip route show" "INFO" "$(lines_to_json_array "${F_route}")"

    write_finding_json "network" "connections" "Active Network Connections" \
        "Active Network Connections" "All active network socket connections" \
        "ss -anp" "INFO" "$(lines_to_json_array "${F_ss}")"

    write_finding_json "network" "listening-ports" "Listening Ports" \
        "Listening Ports" "TCP/UDP ports listening for connections" \
        "ss -antp" "INFO" "$(lines_to_json_array "${F_ss2}")"

    write_finding_json "network" "firewall-rules" "Firewall Rules" \
        "Firewall Rules" "Active firewall rules (iptables/nft/ufw)" \
        "iptables --list-rules" "INFO" "$(lines_to_json_array "${F_iptables}")"

    write_finding_json "network" "arp-table" "ARP Cache" \
        "ARP Cache / Neighbor Table" "ARP cache and neighbour discovery table" \
        "ip neigh show" "INFO" "$(lines_to_json_array "${F_arp}")"

    write_finding_json "network" "dns-config" "DNS Configuration" \
        "DNS Configuration" "Resolver config, hosts file, and hosts.allow entries" \
        "cat /etc/resolv.conf /etc/hosts /etc/hosts.allow" "INFO" \
        "$(lines_to_json_array "$(printf '%s\n%s\n%s' "${F_resolv}" "${F_hosts}" "${F_hosts2}")")"

    write_finding_json "network" "open-files-network" "Open Network Files" \
        "Open Network Files (lsof)" "Processes with open network connections" \
        "lsof -i -n" "INFO" "$(lines_to_json_array "${F_lsof}")"

    # --- USERS ---
    write_finding_json "users" "local-users" "Local User Accounts" \
        "Local User Accounts" "All local user accounts from /etc/passwd" \
        "cat /etc/passwd" "INFO" "$(lines_to_json_array "${F_passwd}")"

    write_finding_json "users" "sudo-group" "Sudo Group Members" \
        "Sudo / Wheel Group Members" "Users with sudo privileges" \
        "grep ^sudo: /etc/group" "INFO" "$(lines_to_json_array "${F_sudoers}")"

    write_finding_json "users" "sudoers-file" "Sudoers Configuration" \
        "Sudoers File" "Full sudoers configuration" \
        "cat /etc/sudoers" "INFO" "$(lines_to_json_array "${F_sudoers_full}")"

    write_finding_json "users" "active-sessions" "Active User Sessions" \
        "Active User Sessions" "Currently logged-in users and their sessions" \
        "w" "INFO" "$(lines_to_json_array "${F_w}")"

    write_finding_json "users" "login-history" "Login History" \
        "Login History" "Recent successful logins (last)" \
        "last -Faiwx" "INFO" "$(lines_to_json_array "${F_last2}")"

    write_finding_json "users" "failed-logins" "Failed Login Attempts" \
        "Failed Login Attempts" "Failed authentication attempts (lastb)" \
        "lastb -Faiwx" "MEDIUM" "$(lines_to_json_array "${F_lastb}")"

    write_finding_json "users" "auth-logs" "Authentication Logs" \
        "Authentication Logs" "Authentication and session log entries" \
        "grep -iE session/accepted/sudoers /var/log/auth.log" "INFO" \
        "$(lines_to_json_array "${F_authlogs}")"

    write_finding_json "users" "ssh-keys" "SSH Authorized Keys" \
        "SSH Authorized Keys" "SSH authorized_keys files found on system" \
        "find / -name authorized_keys" "INFO" "$(lines_to_json_array "${F_keys}")"

    write_finding_json "users" "login-shells" "Login Shells" \
        "Login Shell Accounts" "Accounts with interactive shell access" \
        "grep sh$ /etc/passwd" "INFO" "$(lines_to_json_array "${F_shell}")"

    write_finding_json "users" "who" "Who Output" \
        "Who / Logged In Users" "who -a output showing login state" \
        "who -a" "INFO" "$(lines_to_json_array "${F_who}")"

    write_finding_json "users" "bash-history" "Shell History" \
        "Shell Command History" "Recent command history for all users across bash/zsh/sh/fish" \
        "tail -100 ~/.{bash,zsh,sh}_history ~/.local/share/fish/fish_history" "INFO" "$(lines_to_json_array "${F_bash_history}")"

    write_finding_json "users" "ssh-config" "SSH Server Configuration" \
        "SSH Daemon Configuration" "SSHD server configuration file" \
        "cat /etc/ssh/sshd_config" "INFO" "$(lines_to_json_array "${F_sshconfig}")"

    write_finding_json "users" "credential-file-timeline" "Credential File Timeline" \
        "Credential File Tampering Timeline" "mtime/ctime of auth-gating files (passwd, shadow, sudoers, group, authorized_keys) -- a ctime newer than mtime suggests a forged modification time" \
        "stat /etc/passwd /etc/shadow /etc/sudoers /etc/group <authorized_keys>" "INFO" "$(lines_to_json_array "${F_cred_file_timeline}")"

    # --- SYSTEM ---
    write_finding_json "system" "os-info" "Operating System Information" \
        "OS and Kernel Information" "OS version, kernel version, and system identity" \
        "uname -a" "INFO" "$(lines_to_json_array "${F_uname}")"

    write_finding_json "system" "kernel-taint" "Kernel Taint Status" \
        "Kernel Taint Status" "Whether the running kernel has loaded anything that voids normal support guarantees (out-of-tree/unsigned modules, staging drivers, etc.)" \
        "cat /proc/sys/kernel/tainted" "INFO" "$(lines_to_json_array "${F_kernel_taint}")"

    write_finding_json "system" "hardware-info" "Hardware Information" \
        "System Hardware Information" "Physical hardware details (lshw/dmidecode)" \
        "lshw" "INFO" "$(lines_to_json_array "${F_lshw}")"

    write_finding_json "system" "cpu-info" "CPU Information" \
        "CPU Information" "Processor specifications and capabilities" \
        "lscpu" "INFO" "$(lines_to_json_array "${F_lscpu}")"

    write_finding_json "system" "disk-info" "Disk / Block Devices" \
        "Disk and Block Device Information" "Block devices and partition layout" \
        "lsblk -a" "INFO" "$(lines_to_json_array "${F_lsblk}")"

    write_finding_json "system" "disk-detail" "Disk Drive Detail" \
        "Disk Drive Detailed Info" "Disk drive firmware and transport info (hdparm/lsblk)" \
        "hdparm -I" "INFO" "$(lines_to_json_array "${F_hdparm}")"

    write_finding_json "system" "luks-encryption" "Disk Encryption Status" \
        "Disk Encryption Status (LUKS)" "LUKS-encrypted volumes and unlocked dm-crypt mappings (metadata only, no key material)" \
        "lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT" "INFO" "$(lines_to_json_array "${F_luks}")"

    write_finding_json "system" "usb-devices" "USB Devices" \
        "Connected USB Devices" "USB devices currently connected to the system" \
        "lsusb" "INFO" "$(lines_to_json_array "${F_lsusb}")"

    write_finding_json "system" "pci-devices" "PCI Devices" \
        "PCI Devices" "PCI bus devices installed in the system" \
        "lspci" "INFO" "$(lines_to_json_array "${F_lspci}")"

    write_finding_json "system" "journal-logs" "System Journal" \
        "System Journal Log" "Recent systemd journal entries" \
        "journalctl -n 500 --no-pager" "INFO" "$(lines_to_json_array "${F_journalctl}")"

    # --- PROCESSES ---
    write_finding_json "processes" "running-processes" "Running Processes" \
        "Running Process List" "All running processes with full command lines" \
        "ps auxfww" "INFO" "$(lines_to_json_array "${F_ps}")"

    write_finding_json "processes" "services" "System Services" \
        "System Service Status" "All systemd service units and their states" \
        "systemctl list-units --type=service --no-pager" "INFO" \
        "$(lines_to_json_array "${F_services}")"

    write_finding_json "processes" "enabled-units" "Enabled Systemd Units" \
        "Enabled Systemd Unit Files" "Unit files enabled to start at boot" \
        "systemctl list-unit-files --state=enabled" "INFO" \
        "$(lines_to_json_array "${F_systemctl}")"

    write_finding_json "processes" "scheduled-timers" "Systemd Timers" \
        "Scheduled Systemd Timers" "Active and inactive systemd timers" \
        "systemctl list-timers --all" "INFO" "$(lines_to_json_array "${F_systemctl2}")"

    write_finding_json "processes" "cron-jobs" "Cron Jobs" \
        "Cron Job Entries" "User and system cron job entries" \
        "crontab -l" "INFO" "$(lines_to_json_array "${F_cron2}")"

    write_finding_json "processes" "kernel-modules" "Kernel Modules" \
        "Loaded Kernel Modules" "Kernel modules currently loaded (lsmod)" \
        "lsmod" "INFO" "$(lines_to_json_array "${F_lsmod}")"

    write_finding_json "processes" "docker-containers" "Docker Containers" \
        "Docker Container List" "Running and stopped Docker containers" \
        "docker ps -a" "INFO" "$(lines_to_json_array "${F_docker_ps}")"

    write_finding_json "processes" "docker-images" "Docker Images" \
        "Docker Image List" "Docker images present on the system" \
        "docker images" "INFO" "$(lines_to_json_array "${F_docker_images}")"

    # --- FILES ---
    write_finding_json "files" "suid-binaries" "SUID Binaries" \
        "SUID / SGID Binaries" "Executables with SUID or SGID permission bits set" \
        "find / -type f -perm -u=s" "HIGH" "$(lines_to_json_array "${F_suid}")"

    write_finding_json "files" "capabilities" "File Capabilities" \
        "File Capabilities" "Binaries with elevated Linux capabilities" \
        "getcap -r /" "MEDIUM" \
        "$(lines_to_json_array "$(printf '%s\n%s\n%s' "${F_getcap}" "${F_getcap2}" "${F_getcap3}")")"

    write_finding_json "files" "persistence-paths" "Persistence Locations" \
        "Persistence Mechanism Paths" "Files in common persistence locations (cron/init/systemd)" \
        "ls -la /etc/cron* /etc/init.d/ /etc/systemd/system/" "MEDIUM" \
        "$(lines_to_json_array "$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
            "${F_p1}" "${F_p2}" "${F_p3}" "${F_p4}" "${F_p5}" \
            "${F_p6}" "${F_p7}" "${F_p8}" "${F_p9}")")"

    write_finding_json "files" "recent-executables" "Recently Modified Executables" \
        "Recently Modified Executables" "Executable files modified within the configured lookback window, in config-driven search paths" \
        "find <search_paths> -type f -executable -newermt '-N day'" "MEDIUM" \
        "$(lines_to_json_array "${F_new_files}")"

    write_finding_json "files" "deleted-binaries" "Deleted Binary Execution" \
        "Processes Running From Deleted Binaries" "Processes still executing from a file that no longer exists on disk (fileless/self-deleting malware indicator)" \
        "readlink /proc/*/exe" "HIGH" "$(lines_to_json_array "${F_deleted_exe}")"

    write_finding_json "files" "path-writable" "World-Writable PATH Entries" \
        "World-Writable Directories/Files on \$PATH" "PATH directories or binaries writable by any local user, enabling PATH-hijack persistence or privilege escalation" \
        "stat -c %a <each \$PATH dir>" "HIGH" "$(lines_to_json_array "${F_path_ww}")"

    write_finding_json "files" "package-integrity" "Package Integrity Verification" \
        "Package Integrity Verification" "Installed files compared against the package manager's recorded checksums (debsums on Debian/Ubuntu, rpm -Va on RHEL/Fedora)" \
        "debsums -c / rpm -Va" "HIGH" "$(lines_to_json_array "${F_pkg_integrity}")"

    # --- DETECTIONS ---
    local det_evidence=""
    if [[ -f "$(hostname)/DETECTIONS/findings.csv" ]]; then
        det_evidence="$(lines_to_json_array "$(cat "$(hostname)/DETECTIONS/findings.csv")")"
    else
        det_evidence="[]"
    fi
    write_finding_json "detections" "detection-results" "Detection Engine Results" \
        "MITRE ATT&CK Detection Results" \
        "Detection engine ran ${F_DETECTION_TOTAL:-0} rules: ${F_DETECTION_CRITICAL:-0} critical, ${F_DETECTION_HIGH:-0} high, ${F_DETECTION_MEDIUM:-0} medium, ${F_DETECTION_LOW:-0} low" \
        "run_detections()" "HIGH" "${det_evidence}"

    green "[!] Per-check finding JSONs written to $(hostname)/investigation/"
    set -e
}

# Zip all finding JSONs for Forensicator Enterprise upload
zip_findings() {
    set +e
    local inv_dir
    inv_dir="$(hostname)/investigation"
    local zip_out="${Hostname}_findings.zip"

    if ! find "$inv_dir" -name "*-finding.json" 2>/dev/null | grep -q .; then
        return 0
    fi

    if command -v zip >/dev/null 2>&1; then
        find "$inv_dir" -name "*.json" -print0 | zip -j "$zip_out" -@ 2>/dev/null
        green "[!] Finding JSONs zipped: ${zip_out}"
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$inv_dir" "$zip_out" <<'PYEOF'
import zipfile, sys, os, glob
inv_dir, zip_out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_out, 'w', zipfile.ZIP_DEFLATED) as z:
    for f in glob.glob(os.path.join(inv_dir, '**', '*.json'), recursive=True):
        z.write(f, os.path.basename(f))
PYEOF
        green "[!] Finding JSONs zipped: ${zip_out}"
    else
        yellow "[!] zip/python3 not found — skipping zip (JSONs in ${inv_dir})"
    fi
    set -e
}

# Function to encrypt artifacts
encrypt_artifacts() {
    set +e
    local tarball="${Hostname}_artifacts.tar.gz"
    local encrypted="${Hostname}_artifacts.tar.gz.forensicator"
    local keyfile="${Hostname}_key.txt"
    local password
    password=$(cat /proc/sys/kernel/random/uuid 2>/dev/null | tr -d '-' | head -c 32)
    [[ -z "$password" ]] && password=$(date +%s%N | sha256sum | head -c 32)

    cyan "[*] Creating artifact archive..."
    tar -czf "$tarball" "$(hostname)/" 2>/dev/null

    cyan "[*] Encrypting artifact archive..."
    openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -in "$tarball" -out "$encrypted" -pass "pass:${password}" 2>/dev/null

    if [[ $? -eq 0 ]]; then
        echo "$password" >"$keyfile"
        rm -f "$tarball"
        green "[!] Artifacts encrypted: $encrypted"
        green "[!] Decryption key saved to: $keyfile"
    else
        green "[!] Encryption failed - keeping unencrypted archive: $tarball"
    fi
    set -e
}

# Function to decrypt artifacts
decrypt_artifacts() {
    set +e
    local encrypted_file="$1"
    local keyfile="${encrypted_file%.forensicator}"
    keyfile="${keyfile%.tar.gz}_key.txt"

    if [[ ! -f "$encrypted_file" ]]; then
        echo "Error: Encrypted file not found: $encrypted_file"
        return 1
    fi

    local password
    if [[ -f "$keyfile" ]]; then
        password=$(cat "$keyfile")
    else
        read -s -p "Enter decryption password: " password
        echo ""
    fi

    local output_tar="${encrypted_file%.forensicator}"
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in "$encrypted_file" -out "$output_tar" -pass "pass:${password}" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        tar -xzf "$output_tar" 2>/dev/null
        rm -f "$output_tar"
        green "[!] Artifacts decrypted successfully"
    else
        echo "Decryption failed. Wrong password or corrupted file."
    fi
    set -e
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

# Setting Operator Details
NAME=""
CASE=""
TITLE=""
LOCATION=""
DEVICE=""



# Assigning functions to parameters
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -t|--timeline)
            TIMELINE=1
            START_DATE="$2"
            END_DATE="$3"
            validate_date "$START_DATE"
            validate_date "$END_DATE"
            RUN_TIMELINE=1
            shift 3
            ;;
        -logdir|--logdir)
            LOG_DIR="$2"
            shift 2
            ;;
        -log|--logfiles)
            IFS=',' read -r -a LOG_FILES <<< "$2"
            shift 2
            ;;
        -name|--name)
            NAME="$2"
            shift 2
            ;;
        -case|--case)
            CASE="$2"
            shift 2
            ;;
        -title|--title)
            TITLE="$2"
            shift 2
            ;;
        -loc|--location)
            LOCATION="$2"
            shift 2
            ;;
        -device|--device)
            DEVICE="$2"
            shift 2
            ;;
        -p|--pcap)
            RUN_PCAP=1
            shift
            ;;
        -z|--update)
            RUN_UPDATE=1
            shift
            ;;
        -u|--usage)
            usage
            ;;
        -r|--ram)
            RUN_RAM=1
            shift
            ;;
        -w|--weblogs)
            RUN_WEBLOGS=1
            shift
            ;;
        -b|--browser)
            RUN_BROWSER=1
            shift
            ;;
        -s|--ransom)
            RUN_RANSOM=1
            shift
            ;;
        -H|--hashcheck)
            RUN_HASHCHECK=1
            shift
            ;;
        -e|--encrypt)
            RUN_ENCRYPT=1
            shift
            ;;
        -d|--decrypt)
            DECRYPT_FILE="$2"
            decrypt_artifacts "$DECRYPT_FILE"
            exit 0
            shift 2
            ;;
        *)
            # Unknown option
            echo "Error: Unknown option: $key"
            usage
            ;;
    esac
done

echo ""
echo ""

# Prompt for investigator details if not provided
if [[ -z "$NAME" ]]; then
    read -p "Enter investigator name: " NAME
fi
if [[ -z "$CASE" ]]; then
    read -p "Enter case number: " CASE
fi
if [[ -z "$TITLE" ]]; then
    read -p "Enter case title: " TITLE
fi
if [[ -z "$LOCATION" ]]; then
    read -p "Enter examination location: " LOCATION
fi
if [[ -z "$DEVICE" ]]; then
    read -p "Enter device description: " DEVICE
fi

echo ""
echo ""

# Check that all required details are provided before running any functions
if [[ -z "$NAME" || -z "$CASE" || -z "$TITLE" || -z "$LOCATION" || -z "$DEVICE" ]]; then
    echo "Error: Missing required investigator or case details."
    usage
fi

# Execute functions only if required details are provided
if [[ $RUN_PCAP ]]; then
    pcap
fi
if [[ $RUN_UPDATE ]]; then
    update
fi
if [[ $RUN_RAM ]]; then
    ram
fi
if [[ $RUN_WEBLOGS ]]; then
    weblogs
fi
if [[ $RUN_BROWSER ]]; then
    browser
fi
if [[ $RUN_RANSOM ]]; then
    ransom
fi
if [[ $RUN_TIMELINE ]]; then
    timeline
fi

# Setting our html files

# Setting index output file
ForensicatorIndexFile="$(hostname)/index.html"

# Setting Network Information Output
NetworkFile="$(hostname)/network.html"

# Setting Users Information Output
UserFile="$(hostname)/users.html"

# Setting System Information Output
SystemFile="$(hostname)/system.html"

# Setting Processes Output
ProcessFile="$(hostname)/processes.html"

# Setting Other Checks Output
OthersFile="$(hostname)/others.html"

# Setting Extras Output file
ForensicatorExtrasFile="$(hostname)/extras.html"

# Setting Detections Output file
DetectionsFile="$(hostname)/detections.html"


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

# List firewall rules (distro-independent: iptables → nft → ufw)
F_iptables=$(iptables --list-rules 2>/dev/null || nft list ruleset 2>/dev/null || ufw status verbose 2>/dev/null || echo "No firewall tool available (iptables/nft/ufw)")

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

# Kernel taint status - nonzero means the kernel loaded something that voids
# normal support guarantees (out-of-tree/unsigned modules, forced loads,
# staging drivers, etc.). Bits 12 (out-of-tree) and 13 (unsigned) in
# particular are the classic rootkit-relevant kernel-module indicators.
F_kernel_taint_raw=$(cat /proc/sys/kernel/tainted 2>/dev/null)
if [[ -z "$F_kernel_taint_raw" ]]; then
    F_kernel_taint="Not accessible"
elif [[ "$F_kernel_taint_raw" == "0" ]]; then
    F_kernel_taint="0 (clean - no taint flags set)"
else
    F_kernel_taint_notes=""
    (( F_kernel_taint_raw & (1 << 12) )) && F_kernel_taint_notes+="OUT_OF_TREE_MODULE "
    (( F_kernel_taint_raw & (1 << 13) )) && F_kernel_taint_notes+="UNSIGNED_MODULE "
    (( F_kernel_taint_raw & (1 << 8) ))  && F_kernel_taint_notes+="STAGING_DRIVER "
    (( F_kernel_taint_raw & (1 << 5) ))  && F_kernel_taint_notes+="BAD_PAGE/OOPS "
    F_kernel_taint="${F_kernel_taint_raw} (nonzero - kernel is tainted${F_kernel_taint_notes:+: ${F_kernel_taint_notes}})"
fi

# Hardware info (distro-independent)
F_lshw=$(lshw 2>/dev/null || dmidecode 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | head -50)
echo "Hardware Information" >./$(hostname)/OTHER/Kernel_Info.txt
echo "$F_lshw" >>./$(hostname)/OTHER/Kernel_Info.txt

#CPU information (lscpu is on virtually all Linux distros)
F_lscpu=$(lscpu 2>/dev/null || cat /proc/cpuinfo 2>/dev/null | grep -E "model name|cpu cores|siblings|vendor" | sort -u)

#Block devices
F_lsblk=$(lsblk -a 2>/dev/null || cat /proc/partitions 2>/dev/null)

# USB controllers
F_lsusb=$(lsusb 2>/dev/null || cat /proc/bus/usb/devices 2>/dev/null || echo "USB info not available")

# PCI devices
F_lspci=$(lspci 2>/dev/null || cat /proc/bus/pci/devices 2>/dev/null | head -50 || echo "PCI info not available")
echo "PCI Devices" >./$(hostname)/OTHER/PCI_Devices.txt
echo "$F_lspci" >>./$(hostname)/OTHER/PCI_Devices.txt

# Disk info (hdparm is optional; use lsblk detail as fallback)
F_hdparm=$(hdparm -I /dev/sda 2>/dev/null || hdparm -I /dev/nvme0n1 2>/dev/null || lsblk -d -o NAME,SIZE,ROTA,TRAN 2>/dev/null || echo "Disk detail not available")

# Disk encryption status (LUKS) - Linux analogue of BitLocker.
# Reports encryption posture only (cipher/UUID/keyslot metadata); never
# attempts to read or derive the actual passphrase/master key.
F_luks_lsblk=$(lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT -P 2>/dev/null)
F_luks_volumes=$(echo "$F_luks_lsblk" | grep 'FSTYPE="crypto_LUKS"')
F_luks_mapped=$(echo "$F_luks_lsblk" | grep 'TYPE="crypt"')
if [[ -n "$F_luks_volumes" || -n "$F_luks_mapped" ]]; then
    F_luks="LUKS-encrypted volumes:
${F_luks_volumes:-none}

Unlocked/mapped dm-crypt devices:
${F_luks_mapped:-none}
"
    if command -v cryptsetup >/dev/null 2>&1; then
        while IFS= read -r dev_name; do
            [[ -z "$dev_name" ]] && continue
            dev_path="/dev/${dev_name}"
            F_luks+="
--- $dev_path ---
$($SUDO cryptsetup luksDump "$dev_path" 2>/dev/null | grep -E 'Version|Cipher|UUID|Key Slot')"
        done < <(echo "$F_luks_volumes" | sed -n 's/NAME="\([^"]*\)".*/\1/p')
    else
        F_luks+="
(cryptsetup not installed; showing lsblk-based detection only)"
    fi
else
    F_luks="No LUKS-encrypted or unlocked dm-crypt block devices detected"
fi

green "[!] Done"

###############################################
# User(s) Info
###############################################

cyan "[*] Collecting user information"

# who is connected
F_w=$(w)

# Users with login shells
F_shell=$(cat /etc/passwd | grep sh$)

# users with SSH Auth keys (combined with the SUID walk below into one pass
# over "/" instead of two, pruning pseudo-filesystems along the way)
F_suid_and_keys=$(find / \( "${PRUNE_PATHS[@]}" \) -prune -o -type f \( -perm -u=s -o -name authorized_keys \) -print 2>/dev/null)
F_keys=$(echo "$F_suid_and_keys" | grep 'authorized_keys$')

F_passwd=$(cat /etc/passwd)
F_sudoers=$(grep '^sudo:' /etc/group)
F_bashrc=$(cat /etc/bash.bashrc)
echo "Current User Bash Profile" >./$(hostname)/OTHER/bash_bashrc.txt
echo "$F_bashrc" >>./$(hostname)/OTHER/bash_bashrc.txt

# Credential-file tampering timeline: mtime (content) vs ctime (metadata) on
# the files that gate authentication. A ctime noticeably newer than mtime on
# one of these is a timestomping tell -- content or perms were touched after
# the fact and the mtime was faked back, but ctime can't be faked without
# root-level timestomp tooling.
F_cred_file_timeline=""
F_cred_files=(/etc/passwd /etc/shadow /etc/sudoers /etc/group)
while IFS= read -r keyfile; do
    [[ -n "$keyfile" ]] && F_cred_files+=("$keyfile")
done <<< "$F_keys"
for f in "${F_cred_files[@]}"; do
    [[ -f "$f" ]] || continue
    f_mtime_epoch=$(stat -c '%Y' "$f" 2>/dev/null)
    f_ctime_epoch=$(stat -c '%Z' "$f" 2>/dev/null)
    f_mtime=$(stat -c '%y' "$f" 2>/dev/null)
    f_ctime=$(stat -c '%z' "$f" 2>/dev/null)
    f_flag=""
    if [[ -n "$f_mtime_epoch" && -n "$f_ctime_epoch" ]] && (( f_ctime_epoch - f_mtime_epoch > 60 )); then
        f_flag=" [POSSIBLE TIMESTOMP: ctime ~$((f_ctime_epoch - f_mtime_epoch))s newer than mtime]"
    fi
    F_cred_file_timeline+="${f} | mtime=${f_mtime} | ctime=${f_ctime}${f_flag}"$'\n'
done
[[ -z "$F_cred_file_timeline" ]] && F_cred_file_timeline="No credential files found"

green "[!] Done"

###############################################
# Process Info
###############################################

cyan "[*] Collecting Process Information"

# List all services (systemd-first, SysV fallback)
F_services=$(systemctl list-units --type=service --no-pager 2>/dev/null || service --status-all 2>/dev/null || echo "Service manager not accessible")
F_systemctl=$(systemctl list-unit-files --state=enabled 2>/dev/null || echo "systemctl not available")

# List all timers
F_systemctl2=$(systemctl list-timers --all)

F_cron2=$(cat /etc/passwd | cut -d: -f1 | $SUDO xargs -I{} sh -c 'crontab -l -u {} 2>/dev/null || echo "No crontab for {}"')

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

# SUID (derived from the combined suid+authorized_keys walk done earlier,
# instead of a second full "find /" pass)
F_suid=$(echo "$F_suid_and_keys" | grep -v 'authorized_keys$')

# Deleted-but-running binaries: a process still executing from a file that no
# longer exists on disk is a classic fileless/self-deleting malware
# indicator. The kernel appends " (deleted)" to /proc/<pid>/exe's symlink
# target once the underlying inode is unlinked while still open/mapped.
F_deleted_exe=""
for exe_link in /proc/[0-9]*/exe; do
    [[ -L "$exe_link" ]] || continue
    exe_target=$(readlink "$exe_link" 2>/dev/null)
    [[ "$exe_target" == *" (deleted)" ]] || continue
    exe_pid=$(basename "$(dirname "$exe_link")")
    exe_comm=$(cat "/proc/${exe_pid}/comm" 2>/dev/null)
    exe_cmdline=$(tr '\0' ' ' < "/proc/${exe_pid}/cmdline" 2>/dev/null)
    F_deleted_exe+="PID=${exe_pid} COMM=${exe_comm} DELETED_EXE=${exe_target% (deleted)} CMDLINE=${exe_cmdline}"$'\n'
done
[[ -z "$F_deleted_exe" ]] && F_deleted_exe="No processes running from deleted binaries"

# World-writable directories/files on $PATH: lets any local user drop or
# overwrite a binary that a privileged process/script later resolves and
# executes by bare name -- a classic PATH-hijack persistence/priv-esc vector.
F_path_ww=""
IFS=':' read -ra F_path_dirs <<< "$PATH"
for path_dir in "${F_path_dirs[@]}"; do
    [[ -d "$path_dir" ]] || continue
    path_dir_perm=$(stat -c '%a' "$path_dir" 2>/dev/null)
    if [[ -n "$path_dir_perm" && "${path_dir_perm: -1}" =~ [2367] ]]; then
        F_path_ww+="WRITABLE_DIR: ${path_dir} (mode ${path_dir_perm})"$'\n'
    fi
    while IFS= read -r ww_file; do
        F_path_ww+="WRITABLE_FILE: ${ww_file}"$'\n'
    done < <(find "$path_dir" -maxdepth 1 -type f -perm -o+w 2>/dev/null)
done
[[ -z "$F_path_ww" ]] && F_path_ww="No world-writable directories or files found in \$PATH"

# Package integrity verification: compares installed files against the
# package manager's recorded checksums to catch a system binary that was
# swapped out post-install (a common persistence/backdoor technique).
# Distro-detected (debsums on Debian/Ubuntu, rpm -Va on RHEL/Fedora); bounded
# with `timeout` since a full verification pass can take minutes on a large
# system, and output is capped so one heavily-modified box can't flood the
# report. Both bounds are config-driven since the right value depends heavily
# on how many packages are installed on the target box.
pkg_integrity_timeout=$(read_config_array "pkg_integrity_timeout_seconds" | head -1)
[[ -z "$pkg_integrity_timeout" || ! "$pkg_integrity_timeout" =~ ^[0-9]+$ ]] && pkg_integrity_timeout=180
pkg_integrity_max_lines=$(read_config_array "pkg_integrity_max_lines" | head -1)
[[ -z "$pkg_integrity_max_lines" || ! "$pkg_integrity_max_lines" =~ ^[0-9]+$ ]] && pkg_integrity_max_lines=100

cyan "[*] Verifying installed package integrity (timeout ${pkg_integrity_timeout}s, this can take a while)..."
F_pkg_integrity=""
if command -v debsums >/dev/null 2>&1; then
    F_pkg_integrity=$(timeout "$pkg_integrity_timeout" debsums -c 2>/dev/null | head -n "$pkg_integrity_max_lines")
    [[ -z "$F_pkg_integrity" ]] && F_pkg_integrity="debsums: no modified package files detected"
elif command -v rpm >/dev/null 2>&1; then
    # rpm -Va output: 9-char attribute string + path; a '5' in position 3
    # means the file's MD5 checksum no longer matches the package database.
    F_pkg_integrity=$(timeout "$pkg_integrity_timeout" rpm -Va 2>/dev/null | awk '$1 ~ /^..5/' | head -n "$pkg_integrity_max_lines")
    [[ -z "$F_pkg_integrity" ]] && F_pkg_integrity="rpm -Va: no checksum-modified package files detected"
elif command -v dpkg >/dev/null 2>&1; then
    F_pkg_integrity="Package integrity verification not available: install 'debsums' to enable this check (apt-get install debsums)"
else
    F_pkg_integrity="Package integrity verification not available (requires debsums on Debian/Ubuntu or rpm on RHEL/Fedora)"
fi

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

#Authlogs (distro-independent: Debian uses auth.log, RHEL/Fedora uses secure, fallback to journalctl)
#
# Not chained with `||`: grep exits non-zero when a file exists but simply has
# no matching lines, while journalctl exits 0 even when it returns nothing --
# mixing those failure semantics in one `||` chain let an empty-but-successful
# journalctl call swallow the final fallback message. Checked explicitly
# instead, and widened past "accepted password" alone (which misses the very
# common "Accepted publickey" key-based logins) to cover the full range of
# SSH connection events: accepted/failed logins, invalid users, and
# disconnects, so this actually shows SSH connections to/from the host.
AUTH_LOG_PATTERN='sshd.*(Accepted (password|publickey|keyboard-interactive)|Failed password|Invalid user|Connection (closed|reset) by|Received disconnect from|Disconnected from|session (opened|closed))|not in sudoers'

F_authlogs=""
if [[ -r /var/log/auth.log ]]; then
    F_authlogs=$(grep -iE "$AUTH_LOG_PATTERN" /var/log/auth.log 2>/dev/null)
fi
if [[ -z "$F_authlogs" && -r /var/log/secure ]]; then
    F_authlogs=$(grep -iE "$AUTH_LOG_PATTERN" /var/log/secure 2>/dev/null)
fi
if [[ -z "$F_authlogs" ]] && command -v journalctl >/dev/null 2>&1; then
    # -t (syslog identifier) matches sshd's own log tag regardless of what the
    # wrapping systemd unit is named (ssh.service on Debian/Ubuntu vs
    # sshd.service on RHEL/Fedora) -- unlike filtering by _SYSTEMD_UNIT.
    F_authlogs=$(journalctl -t sshd --no-pager -n 500 2>/dev/null)
fi
if [[ -z "$F_authlogs" ]]; then
    F_authlogs="No SSH/auth events found (checked /var/log/auth.log, /var/log/secure, and journalctl -t sshd)"
fi
echo "$F_authlogs" >./$(hostname)/OTHER/AuthLogs.txt

ioc_checks

green "[!] Done"

# Additional Linux artifacts
cyan "[*] Collecting additional Linux artifacts"
F_lastb=$(lastb -Faiwx 2>/dev/null | head -200)
F_who=$(who -a 2>/dev/null)
F_journalctl=$(journalctl -n 500 --no-pager 2>/dev/null)
F_sshconfig=$(cat /etc/ssh/sshd_config 2>/dev/null)
F_arp=$(ip neigh show 2>/dev/null)
F_sudoers_full=$(cat /etc/sudoers 2>/dev/null)
F_docker_ps=$(docker ps -a 2>/dev/null)
F_docker_images=$(docker images 2>/dev/null)

# Collect per-user shell histories -- not just bash. zsh/ksh/sh history files
# use the same one-command-per-line layout (zsh's optional extended format
# with a leading ": <epoch>:<dur>;" prefix is still readable as-is); fish
# uses its own YAML-ish format, included raw rather than parsed.
F_bash_history=""
for home_dir in /root /home/*/; do
    user=$(basename "$home_dir")
    for hist_spec in ".bash_history:bash" ".zsh_history:zsh" ".sh_history:sh" ".local/share/fish/fish_history:fish"; do
        hist_file="${home_dir}/${hist_spec%%:*}"
        shell_name="${hist_spec##*:}"
        if [[ -f "$hist_file" ]]; then
            F_bash_history+="=== ${user} (${shell_name}) ===\n"
            F_bash_history+=$(tail -100 "$hist_file" 2>/dev/null)
            F_bash_history+="\n"
        fi
    done
done
green "[!] Done"

new_files_check

if [[ $RUN_HASHCHECK ]]; then hash_check; fi
if [[ $RUN_BROWSER ]]; then browser_ioc_check; fi
run_detections
run_sigma_detections

# Recording end time
enddate=$(date)


#########################################################
# Single-page HTML Report (Windows-compatible SPA)
#########################################################

#########################################################
# Single-page HTML report (Windows-compatible structure)
#########################################################

html_esc() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

# Inline-escape and emit one <tr> per line — NO subshell per line so it stays fast
# on large datasets (ps, ss, auth logs, etc.)
pre_rows() {
    local data="$1" cols="${2:-1}" _ln
    if [[ -z "${data//[[:space:]]/}" ]]; then
        printf '<tr><td colspan="%s"><div class="empty"><div class="empty-icon">&#9675;</div><div class="empty-msg">No data collected</div></div></td></tr>' "$cols"
        return
    fi
    while IFS= read -r _ln; do
        [[ -z "$_ln" ]] && continue
        _ln="${_ln//&/&amp;}"
        _ln="${_ln//</&lt;}"
        _ln="${_ln//>/&gt;}"
        _ln="${_ln//\"/&quot;}"
        printf '<tr><td colspan="%s"><pre class="mono-cell" style="margin:0;white-space:pre-wrap;word-break:break-all">%s</pre></td></tr>\n' "$cols" "$_ln"
    done <<< "$data"
}

kv_list_row() {
    local _k="$1" _v="$2"
    _k="${_k//&/&amp;}"; _k="${_k//</&lt;}"; _k="${_k//>/&gt;}"; _k="${_k//\"/&quot;}"
    _v="${_v//&/&amp;}"; _v="${_v//</&lt;}"; _v="${_v//>/&gt;}"; _v="${_v//\"/&quot;}"
    printf '<div class="kv-list-row"><div class="kv-list-k">%s</div><div class="kv-list-v">%s</div></div>\n' "$_k" "$_v"
}

build_sigma_json() {
    local _j="[" _first=1 _ts
    _ts=$(date '+%Y-%m-%d %H:%M:%S')
    local _df; _df="$(hostname)/DETECTIONS/findings.csv"
    if [[ -f "$_df" ]]; then
        while IFS=, read -r _sev _mitre _cat _desc _evid; do
            [[ "$_sev" == "severity" || -z "$_sev" ]] && continue
            [[ $_first -eq 0 ]] && _j+=","
            _j+="{\"TimeCreated\":\"$(json_escape "$_ts")\","
            _j+="\"RuleLevel\":\"$(json_escape "${_sev,,}")\","
            _j+="\"RuleTitle\":\"$(json_escape "$_desc")\","
            _j+="\"EventId\":\"$(json_escape "$_mitre")\","
            _j+="\"User\":\"N\\/A\","
            _j+="\"Process\":\"$(json_escape "$_evid")\","
            _j+="\"CommandLine\":\"N\\/A\","
            _j+="\"LogName\":\"linux-forensicator\","
            _j+="\"RuleFile\":\"$(json_escape "$_cat")\","
            _j+="\"RuleTags\":\"$(json_escape "$_mitre")\"}"
            _first=0
        done < "$_df"
    fi
    printf '%s]' "$_j"
}

build_hash_json() {
    local _j="[" _first=1 _ts
    _ts=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ -n "$F_hash_results" ]] && \
       [[ "$F_hash_results" != *"Hash check not"* ]] && \
       [[ "$F_hash_results" != *"No malicious"* ]] && \
       [[ "$F_hash_results" != *"skipped"* ]]; then
        while IFS= read -r _ln; do
            [[ -z "$_ln" ]] && continue
            [[ $_first -eq 0 ]] && _j+=","
            _j+="{\"TimeCreated\":\"$(json_escape "$_ts")\","
            _j+="\"RuleLevel\":\"critical\","
            _j+="\"RuleTitle\":\"Malicious Hash Match\","
            _j+="\"EventId\":\"\",\"User\":\"N\\/A\","
            _j+="\"Process\":\"$(json_escape "$_ln")\","
            _j+="\"CommandLine\":\"$(json_escape "$_ln")\","
            _j+="\"LogName\":\"hash-check\","
            _j+="\"RuleFile\":\"md5sum-check\","
            _j+="\"RuleTags\":\"malware,hash\"}"
            _first=0
        done <<< "$F_hash_results"
    fi
    printf '%s]' "$_j"
}

build_ioc_json() {
    local _j="[" _first=1 _ts
    _ts=$(date '+%Y-%m-%d %H:%M:%S')
    local _combined
    _combined="$(printf '%s\n%s\n%s' \
        "${F_suspicious_exec_hits:-}" \
        "${F_suspicious_cmd_hits:-}" \
        "${F_browser_ioc_hits:-}")"
    while IFS= read -r _ln; do
        [[ -z "$_ln" ]] && continue
        [[ "$_ln" == "No matches found" ]] && continue
        [[ "$_ln" == *"not requested"* ]] && continue
        [[ $_first -eq 0 ]] && _j+=","
        _j+="{\"TimeCreated\":\"$(json_escape "$_ts")\","
        _j+="\"RuleLevel\":\"high\","
        _j+="\"RuleTitle\":\"IOC Match\","
        _j+="\"EventId\":\"\",\"User\":\"N\\/A\","
        _j+="\"Process\":\"$(json_escape "$_ln")\","
        _j+="\"CommandLine\":\"$(json_escape "$_ln")\","
        _j+="\"LogName\":\"ioc-check\","
        _j+="\"RuleFile\":\"config.json\","
        _j+="\"RuleTags\":\"ioc,suspicious\"}"
        _first=0
    done <<< "$_combined"
    printf '%s]' "$_j"
}

build_report_fragments() {
    local _os_ver _k _v _e
    _os_ver=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')

    # Build host summary — kv_list_row escapes inline, subshells only for uname/hostname (13 total, fast)
    local _kern _arch _hostip _uname_a
    _kern=$(uname -r 2>/dev/null); _arch=$(uname -m 2>/dev/null)
    _hostip=$(hostname -I 2>/dev/null | awk '{print $1}')
    _uname_a=$(uname -a 2>/dev/null)
    _frag_host_summary=""
    _frag_host_summary+="$(kv_list_row 'host.hostname'           "${Hostname}")"
    _frag_host_summary+="$(kv_list_row 'host.os'                "${_os_ver:-$(uname -s)}")"
    _frag_host_summary+="$(kv_list_row 'host.kernel'            "${_kern}")"
    _frag_host_summary+="$(kv_list_row 'host.arch'              "${_arch}")"
    _frag_host_summary+="$(kv_list_row 'host.ip'                "${_hostip}")"
    _frag_host_summary+="$(kv_list_row 'investigation.case'     "${CASE}")"
    _frag_host_summary+="$(kv_list_row 'investigation.title'    "${TITLE}")"
    _frag_host_summary+="$(kv_list_row 'investigation.operator' "${NAME}")"
    _frag_host_summary+="$(kv_list_row 'investigation.location' "${LOCATION}")"
    _frag_host_summary+="$(kv_list_row 'investigation.device'   "${DEVICE}")"
    _frag_host_summary+="$(kv_list_row 'collection.start'       "${startdate}")"
    _frag_host_summary+="$(kv_list_row 'collection.end'         "${enddate}")"
    _frag_host_summary+="$(kv_list_row 'collector.version'      "${MyVersion}")"

    _frag_os_info=""
    while IFS== read -r _k _v; do
        [[ -z "$_k" || "$_k" =~ ^# ]] && continue
        _v="${_v//\"/}"
        _frag_os_info+="$(kv_list_row "$_k" "$_v")"
    done < <(cat /etc/os-release 2>/dev/null)
    _frag_os_info+="$(kv_list_row 'uname' "${_uname_a}")"
    _frag_os_info+="$(kv_list_row 'kernel.taint' "${F_kernel_taint:-Not accessible}")"

    # Top detections for overview panel (server-rendered, first 5)
    # Inline-escape all values — no subshells inside the loop
    _frag_top_detections=""
    local _df; _df="${Hostname}/DETECTIONS/findings.csv"
    if [[ -f "$_df" ]]; then
        local _cnt=0
        while IFS=, read -r _sev _mitre _cat _desc _evid; do
            [[ "$_sev" == "severity" || -z "$_sev" ]] && continue
            [[ $_cnt -ge 5 ]] && break
            local _sbg
            case "${_sev,,}" in
                critical) _sbg="#ef4444" ;; high) _sbg="#f97316" ;;
                medium)   _sbg="#eab308" ;; low)  _sbg="#22c55e" ;;
                *)        _sbg="#3b82f6" ;;
            esac
            local _uid="ov${_cnt}"
            local _es _em _ed _ev _ec
            _es="${_sev}"; _es="${_es//&/&amp;}"; _es="${_es//</&lt;}"; _es="${_es//>/&gt;}"
            _em="${_mitre}"; _em="${_em//&/&amp;}"; _em="${_em//</&lt;}"; _em="${_em//>/&gt;}"
            _ed="${_desc}";  _ed="${_ed//&/&amp;}";  _ed="${_ed//</&lt;}";  _ed="${_ed//>/&gt;}"
            _ev="${_evid:0:60}"; _ev="${_ev//&/&amp;}"; _ev="${_ev//</&lt;}"; _ev="${_ev//>/&gt;}"
            _ec="${_cat}"; _ec="${_ec//&/&amp;}"; _ec="${_ec//</&lt;}"; _ec="${_ec//>/&gt;}"
            _frag_top_detections+="<tr class=\"d-row\" style=\"border-left:3px solid ${_sbg}\" onclick=\"toggleDRow('${_uid}')\">"
            _frag_top_detections+="<td class=\"d-expand\" id=\"ico-${_uid}\">&#9658;</td>"
            _frag_top_detections+="<td class=\"d-time\">${startdate}</td>"
            _frag_top_detections+="<td><span class=\"sev\" style=\"background:${_sbg};color:#fff\">${_es^^}</span></td>"
            _frag_top_detections+="<td class=\"d-rule\"><strong>${_ed}</strong></td>"
            _frag_top_detections+="<td class=\"d-evid\">${_em}</td>"
            _frag_top_detections+="<td class=\"d-user\">&#8212;</td>"
            _frag_top_detections+="<td class=\"d-proc\">${_ev}</td></tr>"
            _frag_top_detections+="<tr id=\"det-${_uid}\" class=\"d-detail\" style=\"display:none\"><td colspan=\"7\"><div class=\"kv-panel\"><table>"
            _frag_top_detections+="<tr><td class=\"kv-k\">rule.title</td><td class=\"kv-v\">${_ed}</td></tr>"
            _frag_top_detections+="<tr><td class=\"kv-k\">rule.level</td><td class=\"kv-v\">${_es}</td></tr>"
            _frag_top_detections+="<tr><td class=\"kv-k\">mitre</td><td class=\"kv-v\">${_em}</td></tr>"
            _frag_top_detections+="<tr><td class=\"kv-k\">category</td><td class=\"kv-v\">${_ec}</td></tr>"
            _frag_top_detections+="<tr><td class=\"kv-k\">evidence</td><td class=\"kv-v\"><code>${_ev}</code></td></tr>"
            _frag_top_detections+="</table></div></td></tr>"
            _cnt=$((_cnt+1))
        done < "$_df"
    fi
    [[ -z "$_frag_top_detections" ]] && \
        _frag_top_detections='<tr><td colspan="7"><div class="empty"><div class="empty-icon">&#10004;</div><div class="empty-msg">No detections found on this host.</div></div></td></tr>'

    # Users (parsed /etc/passwd) — inline-escape, no subshells
    _frag_users=""
    if [[ -n "$F_passwd" ]]; then
        local _u _p _uid _gid _gecos _home _shell _sc
        while IFS=: read -r _u _p _uid _gid _gecos _home _shell; do
            [[ -z "$_u" ]] && continue
            _sc="mono-cell"
            [[ "$_shell" == */nologin || "$_shell" == */false ]] && _sc="mono-cell dim-cell"
            _u="${_u//&/&amp;}"; _u="${_u//</&lt;}"; _u="${_u//>/&gt;}"
            _home="${_home//&/&amp;}"; _home="${_home//</&lt;}"; _home="${_home//>/&gt;}"
            _shell="${_shell//&/&amp;}"; _shell="${_shell//</&lt;}"; _shell="${_shell//>/&gt;}"
            _gecos="${_gecos//&/&amp;}"; _gecos="${_gecos//</&lt;}"; _gecos="${_gecos//>/&gt;}"
            _frag_users+="<tr><td class=\"mono-cell\">${_u}</td>"
            _frag_users+="<td class=\"mono-cell\">${_uid}</td><td class=\"mono-cell\">${_gid}</td>"
            _frag_users+="<td class=\"mono-cell\">${_home}</td>"
            _frag_users+="<td class=\"${_sc}\">${_shell}</td>"
            _frag_users+="<td class=\"dim-cell\">${_gecos}</td></tr>"
        done <<< "$F_passwd"
    fi
    [[ -z "$_frag_users" ]] && \
        _frag_users='<tr><td colspan="6"><div class="empty"><div class="empty-icon">&#9675;</div><div class="empty-msg">No data</div></div></td></tr>'

    # Cap large data sources to keep report generation fast
    local _ps500 _ss500 _auth500 _jrnl500 _hist300 _lsof500 _svc500 _mod500
    _ps500=$(printf '%s' "$F_ps"      | head -500)
    _ss500=$(printf '%s' "$F_ss"      | head -500)
    _auth500=$(printf '%s' "$F_authlogs" | head -500)
    _jrnl500=$(printf '%s' "$F_journalctl" | head -500)
    _hist300=$(printf '%s' "$F_bash_history" | head -300)
    _lsof500=$(printf '%s' "$F_lsof"  | head -500)
    _svc500=$(printf '%s' "$F_services" | head -300)
    _mod500=$(printf '%s' "$F_lsmod"  | head -300)

    _frag_sudo="$(pre_rows "$F_sudoers")"
    _frag_sessions="$(pre_rows "$F_w")"
    _frag_login_history="$(pre_rows "$F_last2")"
    _frag_failed_logins="$(pre_rows "$F_lastb")"
    _frag_ssh_keys="$(pre_rows "$F_keys")"
    _frag_cred_timeline="$(pre_rows "${F_cred_file_timeline:-No credential files found}")"
    _frag_who="$(pre_rows "$F_who")"
    _frag_cpu="$(pre_rows "$F_lscpu")"
    _frag_disk="$(pre_rows "$F_lsblk")"
    _frag_disk_detail="$(pre_rows "$F_hdparm")"
    _frag_luks="$(pre_rows "${F_luks:-No LUKS-encrypted or unlocked dm-crypt block devices detected}")"
    _frag_hardware="$(pre_rows "$F_lshw")"
    _frag_usb="$(pre_rows "$F_lsusb")"
    _frag_pci="$(pre_rows "$F_lspci")"
    _frag_interfaces="$(pre_rows "$F_ip")"
    _frag_routes="$(pre_rows "$F_route")"
    _frag_connections="$(pre_rows "$_ss500")"
    _frag_ports="$(pre_rows "$F_ss2")"
    _frag_arp="$(pre_rows "$F_arp")"
    _frag_firewall="$(pre_rows "$F_iptables")"
    _frag_dns="$(pre_rows "$(printf '%s\n--- hosts ---\n%s\n--- hosts.allow ---\n%s' "$F_resolv" "$F_hosts" "${F_hosts2:-}")")"
    _frag_lsof="$(pre_rows "$_lsof500")"
    _frag_procs="$(pre_rows "$_ps500")"
    _frag_services="$(pre_rows "$_svc500")"
    _frag_enabled_units="$(pre_rows "$F_systemctl")"
    _frag_timers="$(pre_rows "$F_systemctl2")"
    _frag_cron="$(pre_rows "$F_cron2")"
    _frag_docker="$(pre_rows "$F_docker_ps")"
    _frag_docker_images="$(pre_rows "$F_docker_images")"
    _frag_modules="$(pre_rows "$_mod500")"
    local _persist_all
    _persist_all="$(printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
        "${F_p1:-}" "${F_p2:-}" "${F_p3:-}" "${F_p4:-}" "${F_p5:-}" "${F_p6:-}" "${F_p7:-}" "${F_p8:-}" "${F_p9:-}")"
    _frag_persistence="$(pre_rows "$_persist_all")"
    _frag_authlogs="$(pre_rows "$_auth500")"
    _frag_journal="$(pre_rows "$_jrnl500")"
    _frag_bash_history="$(pre_rows "$_hist300")"
    _frag_sshconfig="$(pre_rows "${F_sshconfig:-}")"
    _frag_bashrc="$(pre_rows "$F_bashrc")"
    _frag_suid="$(pre_rows "$F_suid")"
    local _caps_all
    _caps_all="$(printf '%s\n%s\n%s' "${F_getcap:-}" "${F_getcap2:-}" "${F_getcap3:-}")"
    _frag_caps="$(pre_rows "$_caps_all")"
    _frag_new_files="$(pre_rows "${F_new_files:-No recently modified executables found}")"
    _frag_deleted_exe="$(pre_rows "${F_deleted_exe:-No processes running from deleted binaries}")"
    _frag_path_ww="$(pre_rows "${F_path_ww:-No world-writable directories or files found in \$PATH}")"
    _frag_pkg_integrity="$(pre_rows "${F_pkg_integrity:-Package integrity verification not available}")"
    _frag_ioc_exec="$(pre_rows "${F_suspicious_exec_hits:-No executable IOC data}")"
    _frag_ioc_cmd="$(pre_rows "${F_suspicious_cmd_hits:-No command IOC data}")"
    _frag_browser_ioc="$(pre_rows "${F_browser_ioc_hits:-Browser IOC check not requested}")"
    _frag_hash_results="$(pre_rows "${F_hash_results:-Hash check not requested}")"
}

generate_report_html() {
    set +e
    cyan "[*] Generating single-page HTML report..."

    local _rd; _rd="$(hostname)/reports"
    mkdir -p "$_rd"

    # Copy runtime JS from script directory
    local _sd
    _sd="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || \
    _sd="$(dirname "$(readlink -f "$0" 2>/dev/null || echo "$0")")"
    [[ -f "$_sd/forensicator-runtime.js" ]] && \
        cp "$_sd/forensicator-runtime.js" "$_rd/forensicator-runtime.js"

    build_report_fragments

    local _sigma_data _hash_data _ioc_data
    _sigma_data="$(build_sigma_json)"
    _hash_data="$(build_hash_json)"
    _ioc_data="$(build_ioc_json)"

    local _out; _out="$_rd/index.html"

    # ── HEAD + CSS (single-quoted heredoc: no bash expansion) ──────────────
    cat > "$_out" << 'HTMLHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
HTMLHEAD
    printf '<title>Live Forensicator &#8212; %s</title>\n' "$(html_esc "$Hostname")" >> "$_out"
    cat >> "$_out" << 'STYLEBLOCK'
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600;700&display=swap');
:root{--bg:#07090f;--surface:#0d111a;--surface2:#111827;--surface3:#161e2e;--border:#1e2d42;--border2:#243650;--blue:#3b82f6;--blue-dim:#1d4ed8;--blue-bg:rgba(59,130,246,.08);--crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;--info:#3b82f6;--text:#e2e8f0;--text2:#94a3b8;--text3:#4b6278;--sb-w:220px;--topbar-h:52px;--font:'IBM Plex Sans',system-ui,sans-serif;--mono:'IBM Plex Mono',monospace;}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{font-family:var(--font);background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;display:flex;flex-direction:column;min-height:100vh;}
#topbar{position:fixed;top:0;left:0;right:0;height:var(--topbar-h);background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 16px 0 0;z-index:300;}
.topbar-brand{width:var(--sb-w);flex-shrink:0;display:flex;align-items:center;gap:10px;padding:0 16px;border-right:1px solid var(--border);height:100%;}
.brand-icon{width:28px;height:28px;background:var(--blue);border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px;flex-shrink:0;}
.brand-text{font-size:13px;font-weight:700;color:var(--text);letter-spacing:-.3px;}
.brand-text span{color:var(--blue);}
.topbar-meta{display:flex;align-items:center;padding:0 12px;flex:1;overflow:hidden;gap:6px;}
.meta-chip{display:flex;align-items:center;gap:6px;padding:4px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;font-size:11px;color:var(--text2);font-family:var(--mono);white-space:nowrap;}
.meta-chip strong{color:var(--text);}
.topbar-right{margin-left:auto;display:flex;align-items:center;gap:8px;flex-shrink:0;}
.version-pill{background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);color:var(--blue);font-size:10px;font-weight:600;padding:3px 9px;border-radius:12px;}
#sidebar{position:fixed;top:var(--topbar-h);left:0;bottom:0;width:var(--sb-w);background:var(--surface);border-right:1px solid var(--border);overflow-y:auto;z-index:200;padding:16px 0 40px;scrollbar-width:thin;scrollbar-color:var(--border2) transparent;}
.sb-label{font-size:10px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--text3);padding:10px 16px 5px;}
.sb-link{display:flex;align-items:center;gap:9px;padding:7px 16px;color:var(--text2);cursor:pointer;border-left:2px solid transparent;transition:all .12s;user-select:none;font-size:13px;}
.sb-link:hover{color:var(--text);background:rgba(255,255,255,.03);}
.sb-link.active{color:var(--blue);border-left-color:var(--blue);background:var(--blue-bg);}
.sb-icon{width:16px;text-align:center;font-style:normal;flex-shrink:0;}
.sb-badge{margin-left:auto;background:var(--crit);color:#fff;font-size:10px;font-weight:700;padding:1px 6px;border-radius:10px;display:none;}
.sb-badge.show{display:inline-block;}
.sb-divider{height:1px;background:var(--border);margin:10px 0;}
#main{margin-left:var(--sb-w);margin-top:var(--topbar-h);flex:1;min-width:0;}
.view{display:none;padding:24px 28px 60px;}
.view.active{display:block;}
.view-header{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:24px;gap:16px;flex-wrap:wrap;}
.view-title{font-size:18px;font-weight:700;color:var(--text);letter-spacing:-.3px;}
.view-sub{font-size:12px;color:var(--text2);margin-top:3px;}
.stat-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px;}
.stat-card{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:16px;cursor:pointer;transition:border-color .15s,transform .15s;position:relative;overflow:hidden;}
.stat-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent,var(--blue));opacity:.6;}
.stat-card:hover{border-color:var(--accent,var(--blue));transform:translateY(-1px);}
.stat-num{font-size:28px;font-weight:700;color:var(--accent,var(--blue));line-height:1;font-family:var(--mono);}
.stat-label{font-size:11px;color:var(--text2);text-transform:uppercase;letter-spacing:.08em;margin-top:5px;}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;margin-bottom:20px;overflow:hidden;}
.panel-head{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;background:var(--surface2);border-bottom:1px solid var(--border);gap:12px;}
.panel-title{font-size:13px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;}
.panel-count{font-family:var(--mono);font-size:11px;color:var(--text2);background:var(--surface3);border:1px solid var(--border);padding:2px 8px;border-radius:4px;}
.search-bar{display:flex;align-items:center;gap:8px;padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border);}
.search-wrap{flex:1;position:relative;}
.search-wrap input{width:100%;background:var(--surface2);border:1px solid var(--border2);color:var(--text);font-family:var(--mono);font-size:12px;padding:7px 12px 7px 32px;border-radius:5px;outline:none;transition:border-color .15s;}
.search-wrap input:focus{border-color:var(--blue);}
.search-wrap input::placeholder{color:var(--text3);}
.search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--text3);font-size:12px;pointer-events:none;}
.filter-row{display:flex;gap:6px;flex-wrap:wrap;padding:8px 16px;border-bottom:1px solid var(--border);background:var(--surface);}
.f-pill{display:flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid;cursor:pointer;transition:all .12s;user-select:none;}
.f-pill:hover{filter:brightness(1.2);}
.f-num{font-family:var(--mono);font-size:13px;font-weight:700;}
.sev{display:inline-block;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;white-space:nowrap;}
.disc-wrap{overflow-x:auto;}
table.disc{width:100%;border-collapse:collapse;font-size:12px;}
.disc thead th{background:var(--surface2);color:var(--text3);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:9px 12px;border-bottom:1px solid var(--border);white-space:nowrap;text-align:left;}
.disc tbody tr.d-row{border-bottom:1px solid var(--surface2);cursor:pointer;transition:background .08s;}
.disc tbody tr.d-row:hover{background:var(--surface2);}
.disc td{padding:8px 12px;color:var(--text);vertical-align:middle;}
.d-expand{width:20px;color:var(--text3);font-size:10px;text-align:center;}
.d-time{font-family:var(--mono);font-size:11px;color:var(--text2);white-space:nowrap;}
.d-rule{max-width:280px;font-weight:500;}
.d-evid{font-family:var(--mono);font-size:11px;color:#7dd3fc;text-align:center;width:55px;}
.d-user{font-size:11px;color:#c4b5fd;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.d-proc{font-family:var(--mono);font-size:11px;color:#93c5fd;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
tr.d-detail td{background:var(--surface3)!important;padding:0!important;border:none!important;}
.kv-panel{border-top:1px solid var(--border2);}
.kv-panel table{width:100%;border-collapse:collapse;}
.kv-panel tr{border-bottom:1px solid var(--border);}
.kv-panel td{padding:6px 20px;vertical-align:top;font-size:12px;}
.kv-k{color:var(--text2);font-family:var(--mono);width:230px;white-space:nowrap;font-weight:500;}
.kv-v{color:var(--text);font-family:var(--mono);word-break:break-all;}
.kv-v code{background:var(--surface);padding:3px 7px;border-radius:3px;font-size:11px;display:inline-block;border:1px solid var(--border);}
.tbl-wrap{overflow-x:auto;}
table.std{width:100%;border-collapse:collapse;font-size:12px;}
.std thead th{background:var(--surface2);color:var(--text3);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;padding:9px 14px;border-bottom:1px solid var(--border);white-space:nowrap;text-align:left;}
.std tbody tr{border-bottom:1px solid var(--surface2);transition:background .08s;}
.std tbody tr:hover{background:var(--surface2);}
.std td{padding:8px 14px;color:var(--text);vertical-align:top;}
.mono-cell{font-family:var(--mono);font-size:11px;color:#93c5fd;}
.dim-cell{color:var(--text2);}
.flag-cell{color:var(--crit)!important;font-weight:600;}
.bar-chart{padding:12px 16px 16px;}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;}
.bar-label{width:160px;font-size:12px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0;}
.bar-track{flex:1;height:16px;background:var(--surface2);border-radius:3px;overflow:hidden;border:1px solid var(--border);}
.bar-fill{height:100%;border-radius:3px;background:var(--blue);transition:width .4s ease;}
.bar-val{width:40px;text-align:right;font-family:var(--mono);font-size:11px;color:var(--text2);}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px;}
@media(max-width:1024px){.grid-2{grid-template-columns:1fr;}}
.empty{text-align:center;padding:48px 20px;color:var(--text3);}
.empty-icon{font-size:32px;margin-bottom:10px;}
.empty-msg{font-size:13px;}
.btn{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:5px;font-family:var(--font);font-size:12px;font-weight:500;border:1px solid var(--border2);background:var(--surface2);color:var(--text2);cursor:pointer;transition:all .12s;white-space:nowrap;}
.btn:hover{border-color:var(--blue);color:var(--text);}
.btn.primary{background:var(--blue);border-color:var(--blue);color:#fff;}
.btn.primary:hover{background:var(--blue-dim);}
.alert-banner{border-left:3px solid;padding:10px 14px;border-radius:0 5px 5px 0;font-size:12px;margin-bottom:12px;}
.alert-banner.crit{background:rgba(239,68,68,.08);border-color:var(--crit);color:#fca5a5;}
.alert-banner.high{background:rgba(249,115,22,.08);border-color:var(--high);color:#fdba74;}
.alert-banner.info{background:rgba(59,130,246,.08);border-color:var(--blue);color:#93c5fd;}
.kv-list{padding:12px 0;}
.kv-list-row{display:flex;border-bottom:1px solid var(--border);padding:7px 16px;}
.kv-list-row:last-child{border-bottom:none;}
.kv-list-k{width:200px;flex-shrink:0;color:var(--text2);font-family:var(--mono);font-size:11px;font-weight:500;}
.kv-list-v{color:var(--text);font-size:12px;word-break:break-all;}
::-webkit-scrollbar{width:5px;height:5px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px;}
@media print{#sidebar,#topbar{display:none;}#main{margin:0;}.view{display:block!important;page-break-before:always;}.view:first-of-type{page-break-before:avoid;}}
.pg-bar{display:flex;align-items:center;justify-content:space-between;padding:9px 16px;border-top:1px solid var(--border);background:var(--surface2);gap:12px;flex-wrap:wrap;}
.pg-info{font-size:11px;color:var(--text2);font-family:var(--mono);white-space:nowrap;}
.pg-controls{display:flex;align-items:center;gap:3px;}
.pg-btn{background:var(--surface3);border:1px solid var(--border2);color:var(--text2);font-family:var(--mono);font-size:12px;padding:4px 9px;border-radius:4px;cursor:pointer;transition:all .12s;min-width:30px;text-align:center;line-height:1.4;}
.pg-btn:hover:not([disabled]){border-color:var(--blue);color:var(--blue);}
.pg-btn.pg-active{background:var(--blue);border-color:var(--blue);color:#fff;}
.pg-btn[disabled]{opacity:.28;cursor:not-allowed;}
.pg-ellipsis{padding:0 5px;color:var(--text3);font-size:12px;line-height:1.8;}
.pg-select{background:var(--surface3);border:1px solid var(--border2);color:var(--text2);font-family:var(--mono);font-size:11px;padding:4px 7px;border-radius:4px;cursor:pointer;outline:none;margin-right:10px;}
.pg-select:focus{border-color:var(--blue);}
#fi-backdrop{position:fixed;inset:0;z-index:499;background:rgba(0,0,0,.4);display:none;}
#fi-backdrop.open{display:block;}
#fi-panel{position:fixed;top:var(--topbar-h);right:-500px;bottom:0;width:480px;max-width:calc(100vw - 40px);background:var(--surface2);border-left:1px solid var(--border);z-index:500;display:flex;flex-direction:column;transition:right .28s cubic-bezier(.4,0,.2,1);overflow:hidden;}
#fi-panel.open{right:0;}
#fi-panel-header{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;border-bottom:1px solid var(--border);flex-shrink:0;gap:10px;background:var(--surface3);}
#fi-panel-title{font-size:12px;font-weight:700;color:var(--text);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
#fi-panel-close{background:none;border:1px solid var(--border2);color:var(--text2);cursor:pointer;padding:4px 10px;border-radius:4px;font-size:11px;flex-shrink:0;transition:border-color .15s,color .15s;}
#fi-panel-close:hover{border-color:var(--blue);color:var(--blue);}
#fi-panel-tabs{display:flex;padding:0 16px;border-bottom:1px solid var(--border);flex-shrink:0;background:var(--surface2);}
#fi-panel-content{flex:1;overflow-y:auto;padding:16px;}
</style>
</head>
<body>
<div id="fi-backdrop"></div>
<div id="fi-panel">
  <div id="fi-panel-header">
    <span id="fi-panel-title">Details</span>
    <button id="fi-panel-close" onclick="closePanel()">&#x2715; Close</button>
  </div>
  <div id="fi-panel-tabs"></div>
  <div id="fi-panel-content"></div>
</div>
STYLEBLOCK

    # ── Inline data (bash expansion needed for JSON vars) ──────────────────
    cat >> "$_out" << DATABLOCK
<script id="forensicator-data">
var SIGMA_DATA    = ${_sigma_data};
var HASH_DATA     = ${_hash_data};
var IOC_DATA      = ${_ioc_data};
var EVTLOG_COUNTS = {};
var TOP_EVENT_IDS = {};
</script>
<script defer src="forensicator-runtime.js"></script>
DATABLOCK

    # ── Topbar (single-quoted prefix, then bash-expanded chips) ───────────
    cat >> "$_out" << 'TOPBAR1'
<header id="topbar">
  <div class="topbar-brand">
    <div class="brand-icon">&#128269;</div>
    <div class="brand-text">Live<span>Forensicator</span></div>
  </div>
  <div class="topbar-meta">
TOPBAR1
    printf '    <div class="meta-chip">&#128421; <strong>%s</strong></div>\n' "$(html_esc "$Hostname")" >> "$_out"
    printf '    <div class="meta-chip">&#128100; <strong>%s</strong></div>\n' "$(html_esc "$NAME")"     >> "$_out"
    printf '    <div class="meta-chip">&#128203; <strong>%s</strong></div>\n' "$(html_esc "$CASE")"     >> "$_out"
    printf '    <div class="meta-chip">&#128193; <strong>%s</strong></div>\n' "$(html_esc "$TITLE")"    >> "$_out"
    printf '    <div class="meta-chip">&#127760; <strong>%s</strong></div>\n' "$(html_esc "$LOCATION")" >> "$_out"
    printf '    <div class="meta-chip">&#128336; <strong>%s</strong></div>\n' "$(html_esc "$startdate")">> "$_out"
    cat >> "$_out" << TOPBAR2
  </div>
  <div class="topbar-right">
    <span class="version-pill">${MyVersion}</span>
    <button class="btn" onclick="window.print()">&#128424; Print</button>
  </div>
</header>
TOPBAR2

    # ── Sidebar + nav script ───────────────────────────────────────────────
    cat >> "$_out" << 'SIDEBAR'
<nav id="sidebar">
  <div class="sb-section">
    <div class="sb-label">Navigation</div>
    <div class="sb-link active" onclick="nav('overview')"><i class="sb-icon">&#128202;</i> Overview</div>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-section">
    <div class="sb-label">Host Data</div>
    <div class="sb-link" onclick="nav('users')"><i class="sb-icon">&#128100;</i> Users &amp; Accounts</div>
    <div class="sb-link" onclick="nav('system')"><i class="sb-icon">&#128421;</i> System Info</div>
    <div class="sb-link" onclick="nav('processes')"><i class="sb-icon">&#9881;</i> Processes</div>
    <div class="sb-link" onclick="nav('network')"><i class="sb-icon">&#127760;</i> Network</div>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-section">
    <div class="sb-label">Analysis</div>
    <div class="sb-link" onclick="nav('logs')"><i class="sb-icon">&#128203;</i> Logs &amp; History</div>
    <div class="sb-link" onclick="nav('files')"><i class="sb-icon">&#128193;</i> Files &amp; Artifacts</div>
  </div>
  <div class="sb-divider"></div>
  <div class="sb-section">
    <div class="sb-label">Detections</div>
    <div class="sb-link" onclick="nav('detections')"><i class="sb-icon">&#128680;</i> Rule Detections <span class="sb-badge" id="badge-detections">0</span></div>
    <div class="sb-link" onclick="nav('hashes')"><i class="sb-icon">&#129440;</i> Hash Matches <span class="sb-badge" id="badge-hashes">0</span></div>
    <div class="sb-link" onclick="nav('ioc')"><i class="sb-icon">&#128279;</i> IOC Matches <span class="sb-badge" id="badge-ioc">0</span></div>
  </div>
</nav>
<script>
window.nav = window.nav || function(id) {
  document.querySelectorAll('.view').forEach(function(v){ v.classList.remove('active'); });
  document.querySelectorAll('.sb-link').forEach(function(l){ l.classList.remove('active'); });
  var view = document.getElementById('view-' + id);
  if (view) view.classList.add('active');
  document.querySelectorAll('.sb-link').forEach(function(link){
    var handler = link.getAttribute('onclick') || '';
    if (handler.indexOf("'" + id + "'") !== -1) link.classList.add('active');
  });
  window.scrollTo(0,0);
};
</script>
<main id="main">
SIDEBAR

    # ── All views (bash expansion for fragment vars) ───────────────────────
    cat >> "$_out" << VIEWS
<!-- OVERVIEW -->
<div class="view active" id="view-overview">
  <div class="view-header">
    <div><div class="view-title">Investigation Overview</div>
    <div class="view-sub">Summary of collected artifacts and detections &#8212; Linux &#183; ${Hostname}</div></div>
    <button class="btn primary" onclick="nav('detections')">&#128680; View Detections</button>
  </div>
  <div id="overview-alerts"></div>
  <div class="stat-row" id="overview-stats"><div></div></div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128680; Detection Breakdown</div></div>
      <div class="bar-chart" id="sev-bars"></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128203; Host Summary</div></div>
      <div class="kv-list">${_frag_host_summary}</div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">&#128293; Top Detections</div>
      <button class="btn" onclick="nav('detections')">View all &#8594;</button>
    </div>
    <div class="disc-wrap"><table class="disc">
      <thead><tr><th></th><th>Time</th><th>Severity</th><th>Rule</th><th>MITRE</th><th>User</th><th>Evidence</th></tr></thead>
      <tbody id="overview-hits-body">${_frag_top_detections}</tbody>
    </table></div>
  </div>
</div>

<!-- USERS -->
<div class="view" id="view-users">
  <div class="view-header">
    <div><div class="view-title">Users &amp; Accounts</div>
    <div class="view-sub">Local accounts, sessions, SSH keys, sudo access</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128100; Local User Accounts <span class="panel-count" id="users-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter username, home, shell..." oninput="filterTable('users-tbody',this.value,[0,3,4])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std">
      <thead><tr><th>Username</th><th>UID</th><th>GID</th><th>Home</th><th>Shell</th><th>GECOS</th></tr></thead>
      <tbody id="users-tbody">${_frag_users}</tbody>
    </table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128737; Sudo Group Members</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Entry</th></tr></thead>
      <tbody>${_frag_sudo}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128273; Active Sessions (w) <span class="panel-count" id="sessions-count">0</span></div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Session Info</th></tr></thead>
      <tbody id="sessions-tbody">${_frag_sessions}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128220; Login History (last)</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Login Entry</th></tr></thead>
      <tbody id="history-tbody">${_frag_login_history}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128683; Failed Logins (lastb)</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Failed Login Entry</th></tr></thead>
      <tbody>${_frag_failed_logins}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128273; SSH Authorized Keys</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>File Path</th></tr></thead>
      <tbody>${_frag_ssh_keys}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128101; Logged In Users (who)</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Entry</th></tr></thead>
      <tbody>${_frag_who}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128340; Credential File Timeline</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>File | mtime | ctime</th></tr></thead>
    <tbody>${_frag_cred_timeline}</tbody></table></div>
  </div>
</div>

<!-- SYSTEM -->
<div class="view" id="view-system">
  <div class="view-header">
    <div><div class="view-title">System Information</div>
    <div class="view-sub">OS details, hardware, disk, USB devices</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128421; OS Details</div></div>
      <div class="kv-list">${_frag_os_info}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#9881; CPU Info</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>CPU Info</th></tr></thead>
      <tbody>${_frag_cpu}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128190; Disk &amp; Block Devices</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Block Device Info</th></tr></thead>
    <tbody>${_frag_disk}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128274; Disk Encryption Status (LUKS)</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>LUKS / dm-crypt Info</th></tr></thead>
    <tbody>${_frag_luks}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128268; USB Devices <span class="panel-count" id="usb-count">0</span></div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>USB Device</th></tr></thead>
      <tbody id="usb-tbody">${_frag_usb}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128246; PCI Devices</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>PCI Device</th></tr></thead>
      <tbody>${_frag_pci}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#129513; Hardware Info</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Hardware Info</th></tr></thead>
    <tbody>${_frag_hardware}</tbody></table></div>
  </div>
</div>

<!-- PROCESSES -->
<div class="view" id="view-processes">
  <div class="view-header">
    <div><div class="view-title">Processes &amp; Services</div>
    <div class="view-sub">Running processes, services, cron jobs, persistence, kernel modules</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#9881; Running Processes <span class="panel-count" id="procs-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter processes..." oninput="filterTable('procs-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Process Info</th></tr></thead>
    <tbody id="procs-tbody">${_frag_procs}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#9889; Services <span class="panel-count" id="svc-count">0</span></div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Service Info</th></tr></thead>
      <tbody id="svc-tbody">${_frag_services}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#9989; Enabled Units</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Unit File</th></tr></thead>
      <tbody>${_frag_enabled_units}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128197; Cron Jobs</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Cron Entry</th></tr></thead>
      <tbody>${_frag_cron}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#8987; Systemd Timers</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Timer Info</th></tr></thead>
      <tbody>${_frag_timers}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128295; Persistence Paths</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Path Entry</th></tr></thead>
    <tbody>${_frag_persistence}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128051; Docker Containers</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Container</th></tr></thead>
      <tbody>${_frag_docker}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128039; Kernel Modules</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Module</th></tr></thead>
      <tbody>${_frag_modules}</tbody></table></div>
    </div>
  </div>
</div>

<!-- NETWORK -->
<div class="view" id="view-network">
  <div class="view-header">
    <div><div class="view-title">Network</div>
    <div class="view-sub">Interfaces, connections, ports, ARP, firewall, DNS</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#127760; Interfaces (ip a) <span class="panel-count" id="net-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter interfaces..." oninput="filterTable('net-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Interface Info</th></tr></thead>
    <tbody id="net-tbody">${_frag_interfaces}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128268; Active Connections (ss -anp) <span class="panel-count" id="conn-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter connections..." oninput="filterTable('conn-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Connection Info</th></tr></thead>
    <tbody id="conn-tbody">${_frag_connections}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128263; Listening Ports (ss -antp) <span class="panel-count" id="listen-count">0</span></div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Port Info</th></tr></thead>
    <tbody id="listen-tbody">${_frag_ports}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128225; ARP / Neighbor Table</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>ARP Entry</th></tr></thead>
      <tbody>${_frag_arp}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128737; Firewall Rules</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Rule</th></tr></thead>
      <tbody>${_frag_firewall}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128507; Routing Table</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Route</th></tr></thead>
      <tbody>${_frag_routes}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128214; DNS / Hosts Config</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>DNS / Hosts Entry</th></tr></thead>
      <tbody>${_frag_dns}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128194; Open Network Files (lsof -i)</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Open File / Connection</th></tr></thead>
    <tbody>${_frag_lsof}</tbody></table></div>
  </div>
</div>

<!-- LOGS -->
<div class="view" id="view-logs">
  <div class="view-header">
    <div><div class="view-title">Logs &amp; History</div>
    <div class="view-sub">Authentication logs, system journal, bash history, SSH config</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128274; Authentication Logs <span class="panel-count" id="evtlog-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input id="evtlog-search" type="text" placeholder="Filter auth logs..." oninput="filterTable('evtlog-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Auth Log Entry</th></tr></thead>
    <tbody id="evtlog-tbody">${_frag_authlogs}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128211; System Journal (journalctl -n 500)</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Journal Entry</th></tr></thead>
    <tbody>${_frag_journal}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128187; Shell History (all users, bash/zsh/sh/fish)</div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter history..." oninput="filterTable('hist-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Command</th></tr></thead>
    <tbody id="hist-tbody">${_frag_bash_history}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128295; SSH Server Config</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Config Line</th></tr></thead>
      <tbody>${_frag_sshconfig}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128024; Shell Profile</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Profile Line</th></tr></thead>
      <tbody>${_frag_bashrc}</tbody></table></div>
    </div>
  </div>
</div>

<!-- FILES -->
<div class="view" id="view-files">
  <div class="view-header">
    <div><div class="view-title">Files &amp; Artifacts</div>
    <div class="view-sub">SUID binaries, capabilities, IOC matches, hash results</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#9888; SUID / SGID Binaries <span class="panel-count" id="files-count">0</span></div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>SUID Binary Path</th></tr></thead>
    <tbody id="files-tbody">${_frag_suid}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#127991; File Capabilities</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Capability Entry</th></tr></thead>
    <tbody>${_frag_caps}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128293; Recently Modified Executables</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Recently Modified Executable</th></tr></thead>
    <tbody>${_frag_new_files}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128128; Deleted Binary Execution</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Process Running From a Deleted Binary</th></tr></thead>
    <tbody>${_frag_deleted_exe}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128273; World-Writable PATH Entries</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Writable Directory/File</th></tr></thead>
      <tbody>${_frag_path_ww}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128230; Package Integrity Verification</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Checksum-Modified Package File</th></tr></thead>
      <tbody>${_frag_pkg_integrity}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129440; Suspicious Executable Matches</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Match</th></tr></thead>
      <tbody>${_frag_ioc_exec}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129440; Suspicious Command Matches</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Match</th></tr></thead>
      <tbody>${_frag_ioc_cmd}</tbody></table></div>
    </div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#127758; Browser URL IOC Matches</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Browser IOC</th></tr></thead>
      <tbody>${_frag_browser_ioc}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129440; Hash Check Results</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Hash Match</th></tr></thead>
      <tbody>${_frag_hash_results}</tbody></table></div>
    </div>
  </div>
</div>

<!-- DETECTIONS -->
<div class="view" id="view-detections">
  <div class="view-header">
    <div><div class="view-title">Rule Detections</div>
    <div class="view-sub">MITRE ATT&amp;CK-mapped detection engine results &#8212; ${F_DETECTION_TOTAL:-0} total findings</div></div>
  </div>
  <div class="panel">
    <div class="panel-head">
      <div class="panel-title">&#128680; Detection Findings</div>
      <span id="det-hits" class="panel-count">0 hits</span>
    </div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input id="det-search" type="text" placeholder="Search detections..." oninput="renderDetections()"/>
    </div></div>
    <div class="filter-row" id="det-filter-row"></div>
    <div class="disc-wrap"><table class="disc">
      <thead><tr><th></th><th>Time</th><th>Severity</th><th>Rule</th><th>MITRE</th><th>User</th><th>Evidence</th></tr></thead>
      <tbody id="det-tbody"></tbody>
    </table></div>
  </div>
</div>

<!-- HASHES -->
<div class="view" id="view-hashes">
  <div class="view-header">
    <div><div class="view-title">Hash Matches</div>
    <div class="view-sub">Files matching known malicious MD5 hashes</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#129440; Hash Match Results <span class="panel-count" id="hash-count">0</span></div></div>
    <div class="disc-wrap"><table class="disc">
      <thead><tr><th></th><th>Time</th><th>Severity</th><th>Rule</th><th>File Path</th><th>Hash</th><th>Source</th></tr></thead>
      <tbody id="hash-tbody"></tbody>
    </table></div>
  </div>
</div>

<!-- IOC -->
<div class="view" id="view-ioc">
  <div class="view-header">
    <div><div class="view-title">IOC Matches</div>
    <div class="view-sub">Indicators of compromise from config.json</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128279; IOC Match Results <span class="panel-count" id="ioc-count">0</span></div></div>
    <div class="disc-wrap"><table class="disc">
      <thead><tr><th></th><th>Time</th><th>Severity</th><th>Rule</th><th>Match</th><th>Details</th><th>Source</th></tr></thead>
      <tbody id="ioc-tbody"></tbody>
    </table></div>
  </div>
</div>

</main>
<script>
document.addEventListener('DOMContentLoaded', function() {
  var pg = {
    'users-tbody':[0,3,4],'sessions-tbody':[0],'history-tbody':[0],
    'procs-tbody':[0],'svc-tbody':[0],'net-tbody':[0],
    'conn-tbody':[0],'listen-tbody':[0],'evtlog-tbody':[0],
    'hist-tbody':[0],'files-tbody':[0],'usb-tbody':[0]
  };
  Object.keys(pg).forEach(function(id){
    if(typeof initPagination==='function') initPagination(id, pg[id], 25);
  });
  var counts = {
    'users-tbody':'users-count','sessions-tbody':'sessions-count',
    'svc-tbody':'svc-count','net-tbody':'net-count',
    'usb-tbody':'usb-count','files-tbody':'files-count',
    'evtlog-tbody':'evtlog-count','procs-tbody':'procs-count',
    'conn-tbody':'conn-count','listen-tbody':'listen-count'
  };
  Object.keys(counts).forEach(function(tid){
    if(typeof syncCount==='function') syncCount(tid, counts[tid]);
  });
});
</script>
</body>
</html>
VIEWS

    green "[!] Report: ${_rd}/index.html"
    set -e
}


#########################################################
# Generate single-page HTML report
#########################################################
generate_report_html

#########################################################
# Write metadata JSON and structured logs
#########################################################
write_metadata_json
write_structured_log
generate_findings_json
zip_findings

# Save bash histories to a file
if [[ -n "$F_bash_history" ]]; then
    mkdir -p "$(hostname)/OTHER"
    printf '%b\n' "$F_bash_history" > "$(hostname)/OTHER/bash_histories.txt"
fi

# Optional encryption
if [[ $RUN_ENCRYPT ]]; then
    encrypt_artifacts
fi

#########################################################
# COMPLETION SUMMARY
#########################################################
echo ""
green "[!] ============================================================"
green "[!]  Live Forensicator (Linux) - Collection Complete"
green "[!] ============================================================"
green "[!]  Hostname    : $Hostname"
green "[!]  Case        : $CASE"
green "[!]  Investigator: $NAME"
green "[!]  Output Dir  : $(pwd)/$Hostname"
green "[!] ============================================================"
green "[!]  DETECTIONS  : ${F_DETECTION_TOTAL:-0} total findings"
echo  "      CRITICAL   : ${F_DETECTION_CRITICAL:-0}"
echo  "      HIGH       : ${F_DETECTION_HIGH:-0}"
echo  "      MEDIUM     : ${F_DETECTION_MEDIUM:-0}"
echo  "      LOW        : ${F_DETECTION_LOW:-0}"
green "[!] ============================================================"
green "[!]  Open $Hostname/index.html in a browser to view results"
green "[!]  Upload ${Hostname}_findings.zip to Forensicator Enterprise"
green "[!] ============================================================"