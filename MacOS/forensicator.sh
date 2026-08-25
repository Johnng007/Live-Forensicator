#!/bin/bash
# Live Forensicator MacOS Script
# Part of the Black Widow Tools
# Coded by Ebuka John Onyejegbu

set +e

# Make all relative paths (./config.json, ./Forensicator-Share/*, output dirs)
# resolve against the script's own location rather than the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || { echo "Error: unable to resolve script directory"; exit 1; }

# Resolve how to run commands that need root once, instead of hardcoding sudo
# at each call site (running as root already, or with no sudo binary present,
# would otherwise break or hang an unattended run).
if [[ $EUID -eq 0 ]]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo -n"
else
    SUDO=""
fi

# Paths to prune from any full-disk find(1) walk below: virtual/mirrored
# mounts and device nodes that are meaningless to search and can be slow or
# hang (network shares under /Volumes, the /System/Volumes/Data firmlink
# mirror that would otherwise double-walk most of the real filesystem, swap).
PRUNE_PATHS=(-path /dev -o -path /Volumes -o -path /System/Volumes/Data -o -path /System/Volumes/VM -o -path /private/var/vm -o -path /.vol)

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "  -p, --pcap            Record network traffic and save as pcap file"
    echo "  -r, --ram             Extract system RAM (requires osxpmem or avml)"
    echo "  -s, --ransom          Check filesystem for ransomware encrypted files"
    echo "  -w, --weblogs         Collect web server logs"
    echo "  -b, --browser         Collect browser history"
    echo "  -H, --hashcheck       Hash check running process executables"
    echo "  -e, --encrypt         Encrypt forensic artifacts with AES-256"
    echo "  -z, --update          Check GitHub for a newer version"
    echo "  -u, --usage           Show this usage message"
    echo "  -name NAME            Investigator name"
    echo "  -case CASE            Case reference number"
    echo "  -title TITLE          Investigation title"
    echo "  -loc LOCATION         Examination location"
    echo "  -device DEVICE        Device description"
    exit 1
}

create_directory() {
    WORKDIR=$(hostname)
    if [ -d "$WORKDIR" ]; then
        echo "Removing existing directory: $WORKDIR"
        rm -rf "$WORKDIR"
    elif [ -f "$WORKDIR" ]; then
        echo "A file with this name already exists."
        exit 1
    fi
    if mkdir "$WORKDIR"; then
        echo "Working directory created: $WORKDIR"
        return 0
    else
        echo "Failed to create directory: $WORKDIR"
        return 1
    fi
}

create_directory

Hostname=$(hostname)

green()  { echo -e "\e[32m$*\e[0m"; }
cyan()   { echo -e "\e[36m$*\e[0m"; }
yellow() { echo -e "\e[33m$*\e[0m"; }

read_config_array() {
    local key="$1"
    local json_file="./config.json"
    [[ ! -f "$json_file" ]] && return 1
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

read_first_available_config_array() {
    local key values
    for key in "$@"; do
        values=$(read_config_array "$key")
        if [[ -n "$values" ]]; then
            printf '%s\n' "$values"
            return 0
        fi
    done
    return 1
}

write_ioc_matches() {
    local key_spec="$1"
    local output_file="$2"
    shift 2
    local sources=("$@")
    local indicator source_name source_data match_found

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

MyVersion=$(<version.txt 2>/dev/null || echo "4.1.6")

t=$(cat <<-"EOF"
___________                                .__               __
\_   _____/__________   ____   ____   _____|__| ____ _____ _/  |_  ___________
 |    __)/  _ \_  __ \_/ __ \ /    \ /  ___/  |/ ___\\__  \\   __\/  _ \_  __ \
 |     \(  <_> )  | \/\  ___/|   |  \\___ \|  \  \___ / __ \|  | (  <_> )  | \/
 \___  / \____/|__|    \___  >___|  /____  >__|\___  >____  /__|  \____/|__|
     \/                    \/     \/     \/        \/     \/


EOF
echo ""
echo "                                                           macOS   $MyVersion"
)

len=${#t}
for ((i = 0; i < len; i++)); do
    if   ((i % 2)); then c="31"
    elif ((i % 5)); then c="33"
    elif ((i % 7)); then c="32"
    else                  c="39"
    fi
    echo -ne "\033[1;${c}m${t:$i:1}"
done
echo -e "\033[0m"

echo ""
echo -e "\e[36m[!] https://forensicator.io\e[0m"
echo -e "\e[36m[!] https://github.com/Johnng007/Live-Forensicator\e[0m"
echo ""

yellow "====================================================="
yellow "[!] Heads up: the HTML report renders best on Windows"
yellow "[!] because Windows collectors return structured, tabular"
yellow "[!] data. Most macOS command output (ps, log show,"
yellow "[!] system_profiler, etc.) is free-form text, so some HTML"
yellow "[!] report panels may show raw text blocks instead of"
yellow "[!] neatly split columns."
yellow "[!] The underlying JSON findings under investigation/ are"
yellow "[!] collected the same way regardless and remain fully"
yellow "[!] reliable for analysis even where the HTML view is not."
yellow "====================================================="
echo ""

yellow "====================================================="
yellow "[!] Heads up: the Sigma detection engine on macOS is"
yellow "[!] best-effort. Apple restricts real process-creation"
yellow "[!] telemetry (comparable to Linux auditd or Windows"
yellow "[!] Sysmon) to its Endpoint Security Framework, which"
yellow "[!] requires a signed system extension with a special"
yellow "[!] Apple entitlement -- not something this script can"
yellow "[!] access. It falls back to the unified log (log show),"
yellow "[!] which is a diagnostic log, not a process auditor, so"
yellow "[!] most command-line-based Sigma rules will not have"
yellow "[!] matching data to fire against. Rules that only need a"
yellow "[!] process's own image path may still catch something;"
yellow "[!] do not read a quiet Sigma tab as \"nothing happened.\""
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

startdate=$(date '+%Y-%m-%d %H:%M:%S')

repoOwner="johnng007"
repoName="Live-Forensicator"
branch="MacOS"
versionFile="version.txt"
rawUrl="https://raw.githubusercontent.com/$repoOwner/$repoName/$branch/$versionFile"

CheckForUpdates() {
    remoteVersion=$(curl -s "$rawUrl" 2>/dev/null | tr -d '[:space:]')
    if [[ -z "$remoteVersion" ]]; then
        cyan "[!] Could not reach GitHub to check for updates."
        return
    fi
    if [[ "$MyVersion" < "$remoteVersion" ]]; then
        cyan "[!] A new version $remoteVersion is available on GitHub. Please upgrade your copy of Forensicator."
    else
        green "[!] You are using the latest version $MyVersion. No updates available."
    fi
}

pcap() {
    mkdir -p "$(hostname)/PCAP"
    cyan "[*] Recording network traffic for 60 seconds..."
    $SUDO tcpdump -i any -w "./$(hostname)/PCAP/network_traffic.pcap" -G 60 -W 1 2>/dev/null
    green "[!] Network traffic recorded and saved"
}

ram() {
    mkdir -p "$(hostname)/RAM"
    cyan "[*] Attempting RAM extraction..."
    if [[ -f "./Forensicator-Share/osxpmem.app/osxpmem" ]]; then
        cyan "[*] Using osxpmem..."
        $SUDO ./Forensicator-Share/osxpmem.app/osxpmem -o "./$(hostname)/RAM/$(hostname).aff4" 2>/dev/null
        green "[!] RAM extracted with osxpmem"
    elif [[ -f "./Forensicator-Share/avml" ]]; then
        cyan "[*] Using avml..."
        $SUDO ./Forensicator-Share/avml --compress "./$(hostname)/RAM/$(hostname).lime.compressed" 2>/dev/null
        green "[!] RAM extracted with avml"
    else
        echo "No supported RAM extraction tool found (osxpmem or avml). Place tool in ./Forensicator-Share/" \
            > "./$(hostname)/RAM/ram_extraction_error.txt"
        cyan "[!] RAM extraction tool not found. See ./$(hostname)/RAM/ram_extraction_error.txt"
    fi
}

weblogs() {
    mkdir -p "$(hostname)/WEBLOGS"
    cyan "[*] Collecting web server logs..."
    for apache_dir in /var/log/apache2 /usr/local/var/log/httpd /opt/homebrew/var/log/httpd; do
        if [[ -d "$apache_dir" ]]; then
            find "$apache_dir" -type f -name "*.log" -exec cp {} "$(hostname)/WEBLOGS/" \; 2>/dev/null
            green "[!] Copied Apache logs from $apache_dir"
        fi
    done
    for nginx_dir in /usr/local/var/log/nginx /opt/homebrew/var/log/nginx /var/log/nginx; do
        if [[ -d "$nginx_dir" ]]; then
            find "$nginx_dir" -type f -name "*.log" -exec cp {} "$(hostname)/WEBLOGS/" \; 2>/dev/null
            green "[!] Copied NGINX logs from $nginx_dir"
        fi
    done
    green "[!] Web log collection complete"
}

browser() {
    cyan "[*] Getting Browser History"
    mkdir -p "$(hostname)/BROWSING_HISTORY"

    for db in $(find ~/Library/Application\ Support/Firefox/Profiles -name 'places.sqlite' 2>/dev/null); do
        profilename=$(basename "$(dirname "$db")")
        outname="history-firefox_$(date '+%Y-%m-%d_%H-%M-%S')_${profilename}"
        tmpdb="/tmp/ff_places_$$.sqlite"
        cp "$db" "$tmpdb" 2>/dev/null
        {
            echo ".headers on"
            echo ".mode csv"
            echo ".output $(hostname)/BROWSING_HISTORY/${outname}.csv"
            echo "SELECT datetime(moz_historyvisits.visit_date/1000000,'unixepoch'), moz_places.url, moz_places.title FROM moz_places, moz_historyvisits WHERE moz_places.id = moz_historyvisits.place_id ORDER BY moz_historyvisits.visit_date DESC LIMIT 5000;"
        } | sqlite3 "$tmpdb" 2>/dev/null
        rm -f "$tmpdb"
    done

    for chrome_base in \
        "$HOME/Library/Application Support/Google/Chrome" \
        "$HOME/Library/Application Support/Chromium" \
        "$HOME/Library/Application Support/Microsoft Edge" \
        "$HOME/Library/Application Support/BraveSoftware/Brave-Browser"; do
        [[ -d "$chrome_base" ]] || continue
        for db in $(find "$chrome_base" -name 'History' 2>/dev/null); do
            profilename=$(basename "$(dirname "$db")")
            browsername=$(basename "$chrome_base" | tr ' ' '_')
            outname="history-${browsername}_$(date '+%Y-%m-%d_%H-%M-%S')_${profilename}"
            tmpdb="/tmp/ch_history_$$.sqlite"
            cp "$db" "$tmpdb" 2>/dev/null
            {
                echo ".headers on"
                echo ".mode csv"
                echo ".output $(hostname)/BROWSING_HISTORY/${outname}.csv"
                echo "SELECT datetime((visits.visit_time/1000000)-11644473600,'unixepoch'), urls.url, urls.title FROM visits, urls WHERE urls.id = visits.url ORDER BY visits.visit_time DESC LIMIT 5000;"
            } | sqlite3 "$tmpdb" 2>/dev/null
            rm -f "$tmpdb"
        done
    done

    if [[ -f "$HOME/Library/Safari/History.db" ]]; then
        tmpdb="/tmp/safari_history_$$.sqlite"
        cp "$HOME/Library/Safari/History.db" "$tmpdb" 2>/dev/null
        outname="history-safari_$(date '+%Y-%m-%d_%H-%M-%S').csv"
        {
            echo ".headers on"
            echo ".mode csv"
            echo ".output $(hostname)/BROWSING_HISTORY/${outname}"
            echo "SELECT datetime(history_visits.visit_time + 978307200,'unixepoch'), history_items.url, history_visits.title FROM history_visits JOIN history_items ON history_items.id = history_visits.history_item ORDER BY history_visits.visit_time DESC LIMIT 5000;"
        } | sqlite3 "$tmpdb" 2>/dev/null
        rm -f "$tmpdb"
    fi

    green "[!] Browser history collection complete"
}

ransom() {
    mkdir -p "$(hostname)/RANSOM_MALICIOUS"
    cyan "[*] Checking for ransomware-encrypted files..."
    cyan "[*] This may take a while..."
    local json_file="./config.json"
    if [[ ! -f "$json_file" ]]; then
        echo "Error: config.json not found." > "$(hostname)/RANSOM_MALICIOUS/error.txt"
        return
    fi
    local extensions
    extensions=($(grep -o '"\.[^"]*"' "$json_file" | tr -d '"'))
    # Single filesystem walk with an -o-joined name expression instead of one
    # full "/" walk per extension.
    local name_expr=()
    for ext in "${extensions[@]}"; do
        [[ ${#name_expr[@]} -gt 0 ]] && name_expr+=(-o)
        name_expr+=(-name "*${ext}")
    done
    find / \( "${PRUNE_PATHS[@]}" \) -prune -o -type f \( "${name_expr[@]}" \) -print 2>/dev/null \
        > "$(hostname)/RANSOM_MALICIOUS/$(hostname)_ransom.txt"
    green "[!] Ransomware check complete"
}

ioc_checks() {
    mkdir -p "$(hostname)/OTHER"
    cyan "[*] Checking suspicious executables and shell commands from config.json..."

    IOC_EXECUTABLES_FILE="./$(hostname)/OTHER/suspicious_executables.txt"
    IOC_SHELL_COMMANDS_FILE="./$(hostname)/OTHER/suspicious_shell_commands.txt"

    write_ioc_matches \
        "suspicious_executables" \
        "$IOC_EXECUTABLES_FILE" \
        F_ps F_services F_launchdaemons F_launchagents F_userlaunchagents F_cron F_p1 F_p2 F_p3 F_p4

    write_ioc_matches \
        "suspicious_SH_commands|suspicious_PS_commands" \
        "$IOC_SHELL_COMMANDS_FILE" \
        F_ps F_cron F_p1 F_p2 F_p3 F_p4 F_bashrc

    F_suspicious_exec_hits=$(cat "$IOC_EXECUTABLES_FILE")
    F_suspicious_sh_hits=$(cat "$IOC_SHELL_COMMANDS_FILE")

    green "[!] IOC checks complete"
}

hash_check() {
    mkdir -p "$(hostname)/OTHER"
    cyan "[*] Checking md5 hashes of running process executables..."

    # Auto-download the known-bad MD5 feed (default: abuse.ch MalwareBazaar
    # recent list), refreshing it when missing or older than 7 days -- same
    # feed and staleness policy as the Windows/Linux hash-check collectors.
    # Uses BSD `stat -f %m` for mtime, not GNU's `stat -c %Y` / `date -r
    # <file>` -- macOS ships BSD stat/date, and BSD `date -r` takes a seconds-
    # since-epoch number, not a filename, so the Linux idiom would break here.
    local hash_source
    hash_source=$(read_config_array "hash_source" | head -1)
    [[ -z "$hash_source" ]] && hash_source="https://bazaar.abuse.ch/export/txt/md5/recent/"

    local hashfile="$SCRIPT_DIR/Forensicator-Share/md5hashes.txt"
    local custom_hashfile="$SCRIPT_DIR/Forensicator-Share/custom_hashes.txt"

    local needs_download=0
    if [[ ! -s "$hashfile" ]]; then
        needs_download=1
    else
        local age_days
        age_days=$(( ( $(date +%s) - $(stat -f %m "$hashfile" 2>/dev/null || echo 0) ) / 86400 ))
        if [[ $age_days -gt 7 ]]; then
            needs_download=1
            echo "[!] Hash feed is ${age_days} days old -- refreshing"
        fi
    fi

    if [[ $needs_download -eq 1 ]]; then
        if command -v curl >/dev/null 2>&1; then
            cyan "[*] Downloading known-bad MD5 hash feed from $hash_source"
            if curl -s --max-time 60 -o "${hashfile}.tmp" "$hash_source" && [[ -s "${hashfile}.tmp" ]]; then
                mv -f "${hashfile}.tmp" "$hashfile"
                green "[!] Hash feed downloaded"
            else
                rm -f "${hashfile}.tmp"
                echo "[!] Hash feed download failed -- using cached copy if available"
            fi
        else
            echo "[!] curl not found -- cannot download hash feed, using cached copy if available"
        fi
    fi

    local hash_files=()
    [[ -f "$hashfile" ]] && hash_files+=("$hashfile")
    [[ -f "$custom_hashfile" ]] && hash_files+=("$custom_hashfile")

    if [[ ${#hash_files[@]} -eq 0 ]]; then
        echo "No hash list files available (feed download failed and no custom hash file found)" > "$(hostname)/OTHER/hash_results.txt"
        F_hash_results="No hash list files available"
        green "[!] Hash check done (no hash lists found)"
        return
    fi

    local proc_paths
    proc_paths=$(ps auxww 2>/dev/null | awk 'NR>1 {print $11}' | sort -u | grep -v '^-\|^\[')
    local results=""
    while IFS= read -r exe; do
        [[ -z "$exe" || ! -x "$exe" ]] && continue
        local hash
        hash=$(md5 -q "$exe" 2>/dev/null)
        [[ -z "$hash" ]] && continue
        for hf in "${hash_files[@]}"; do
            if grep -qiF "$hash" "$hf" 2>/dev/null; then
                results+="MATCH|$hash|$exe\n"
            fi
        done
    done <<< "$proc_paths"
    if [[ -z "$results" ]]; then
        results="No hash matches found"
    fi
    printf '%b' "$results" > "$(hostname)/OTHER/hash_results.txt"
    F_hash_results=$(cat "$(hostname)/OTHER/hash_results.txt")
    green "[!] Hash check complete"
}

browser_ioc_check() {
    mkdir -p "$(hostname)/OTHER"
    cyan "[*] Checking browser history against malicious URL list..."

    # Auto-download the malicious URL/domain feed (default: abuse.ch URLhaus
    # recent list) if it isn't already present -- same feed and
    # download-if-missing policy as the Windows/Linux browser-IOC collectors.
    local url_source
    url_source=$(read_config_array "url_source" | head -1)
    [[ -z "$url_source" ]] && url_source="https://urlhaus.abuse.ch/downloads/text_recent/"

    local urlfile="$SCRIPT_DIR/Forensicator-Share/malicious_URLs.txt"
    local custom_iocsfile="$SCRIPT_DIR/Forensicator-Share/custom_iocs.txt"
    local outfile="$(hostname)/OTHER/browser_ioc_hits.txt"
    : >"$outfile"

    if [[ ! -s "$urlfile" ]] && command -v curl >/dev/null 2>&1; then
        cyan "[*] Downloading malicious URL feed from $url_source"
        if curl -s --max-time 60 -o "${urlfile}.tmp" "$url_source" && [[ -s "${urlfile}.tmp" ]]; then
            mv -f "${urlfile}.tmp" "$urlfile"
            green "[!] Malicious URL feed downloaded"
        else
            rm -f "${urlfile}.tmp"
            echo "[!] Malicious URL feed download failed"
        fi
    fi

    local ioc_files=()
    [[ -f "$urlfile" ]] && ioc_files+=("$urlfile")
    [[ -f "$custom_iocsfile" ]] && ioc_files+=("$custom_iocsfile")

    if [[ ${#ioc_files[@]} -eq 0 ]]; then
        echo "No IOC list files available (feed download failed and no custom IOC file found)" >"$outfile"
        F_browser_ioc_hits="No IOC list files available"
        return
    fi

    local match_found=""
    local csv_dir="$(hostname)/BROWSING_HISTORY"
    if [[ ! -d "$csv_dir" ]]; then
        echo "No browsing history collected." >"$outfile"
        F_browser_ioc_hits="No browsing history collected."
        return
    fi

    for ioc_file in "${ioc_files[@]}"; do
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            while IFS= read -r csvfile; do
                while IFS= read -r line; do
                    echo "HIT|$url|$csvfile|$line" >>"$outfile"
                    match_found=1
                done < <(grep -iF "$url" "$csvfile" 2>/dev/null)
            done < <(find "$csv_dir" -name "*.csv" 2>/dev/null)
        done < "$ioc_file"
    done

    if [[ -z "$match_found" ]]; then
        echo "No malicious URL matches found" >"$outfile"
    else
        sort -u "$outfile" -o "$outfile"
    fi

    F_browser_ioc_hits=$(cat "$outfile")
    green "[!] Browser IOC check complete"
}

encrypt_artifacts() {
    cyan "[*] Encrypting artifacts..."
    local key
    key=$(openssl rand -hex 32)
    local archive="${Hostname}_forensicator_$(date '+%Y%m%d_%H%M%S').tar.gz"
    tar czf "$archive" "$Hostname/" 2>/dev/null
    openssl enc -aes-256-cbc -salt -pbkdf2 -k "$key" -in "$archive" -out "${archive}.enc" 2>/dev/null
    rm -f "$archive"
    echo "Encryption key: $key" > "${Hostname}_ENCRYPTION_KEY.txt"
    echo "Encrypted file: ${archive}.enc" >> "${Hostname}_ENCRYPTION_KEY.txt"
    green "[!] Artifacts encrypted. Key saved to ${Hostname}_ENCRYPTION_KEY.txt"
    green "[!] IMPORTANT: Save the encryption key securely!"
}

write_metadata_json() {
    mkdir -p "$(hostname)/investigation"
    cat > "$(hostname)/investigation/metadata.json" <<METAJSON
{
  "case_reference": "$CASE",
  "examiner_name": "$NAME",
  "exhibit_reference": "$TITLE",
  "device": "$DEVICE",
  "examination_location": "$LOCATION",
  "hostname": "$Hostname",
  "start_time": "$startdate",
  "end_time": "$enddate",
  "script_version": "$MyVersion",
  "os": "macOS",
  "detections_total": $DETECTION_COUNT,
  "detections_critical": $CRITICAL_COUNT,
  "detections_high": $HIGH_COUNT,
  "detections_medium": $MEDIUM_COUNT,
  "detections_low": $LOW_COUNT
}
METAJSON
    green "[!] Metadata JSON written to $(hostname)/investigation/metadata.json"
}

write_structured_log() {
    mkdir -p "$(hostname)/LOGS"
    echo "Timestamp,Hostname,Category,Detail" > "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Case\",\"$CASE\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Examiner\",\"$NAME\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Title\",\"$TITLE\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Location\",\"$LOCATION\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Device\",\"$DEVICE\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "\"$enddate\",\"$Hostname\",\"Detections\",\"Total=$DETECTION_COUNT CRITICAL=$CRITICAL_COUNT HIGH=$HIGH_COUNT MEDIUM=$MEDIUM_COUNT LOW=$LOW_COUNT\"" >> "$(hostname)/LOGS/forensicator_summary.csv"
    echo "Severity,Tactic,Description" > "$(hostname)/LOGS/detections.csv"
    echo "$DETECTION_FINDINGS" | sed 's/<[^>]*>//g' | grep -v '^[[:space:]]*$' >> "$(hostname)/LOGS/detections.csv"
    green "[!] Structured logs written to $(hostname)/LOGS/"
}

##########################################################
# Per-check JSON output (for Forensicator Enterprise)
##########################################################

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

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
  "findingtags": ["forensicator", "$(json_escape "${category}")", "macos"],
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
    "platform": "macOS",
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

generate_findings_json() {
    set +e
    cyan "[*] Generating per-check finding JSONs for Forensicator Enterprise..."

    # --- NETWORK ---
    write_finding_json "network" "ip-addresses" "Network Interface Configuration" \
        "Network Interface Configuration" "Network interface and IP address information (ifconfig)" \
        "ifconfig" "INFO" "$(lines_to_json_array "${F_ip}")"

    write_finding_json "network" "routing-table" "Routing Table" \
        "IP Routing Table" "Kernel IP routing table entries" \
        "netstat -rn" "INFO" "$(lines_to_json_array "${F_route}")"

    write_finding_json "network" "connections" "Active Network Connections" \
        "Active Network Connections" "All active network socket connections" \
        "netstat -an" "INFO" "$(lines_to_json_array "${F_ss}")"

    write_finding_json "network" "listening-ports" "Listening Ports" \
        "Listening Ports" "TCP/UDP ports listening for connections" \
        "lsof -i -n -P" "INFO" "$(lines_to_json_array "${F_ss2}")"

    write_finding_json "network" "firewall-rules" "Firewall Rules (pf)" \
        "Packet Filter Rules" "Active pf firewall rules" \
        "pfctl -sr" "INFO" "$(lines_to_json_array "${F_iptables}")"

    write_finding_json "network" "arp-table" "ARP Cache" \
        "ARP Cache" "Address Resolution Protocol cache" \
        "arp -a" "INFO" "$(lines_to_json_array "${F_arp}")"

    write_finding_json "network" "dns-config" "DNS Configuration" \
        "DNS Configuration" "Resolver config, hosts file, and scutil DNS settings" \
        "scutil --dns" "INFO" \
        "$(lines_to_json_array "$(printf '%s\n%s\n%s' "${F_resolv}" "${F_hosts}" "${F_dns}")")"

    write_finding_json "network" "open-files-network" "Open Network Files" \
        "Open Network Files (lsof)" "Processes with open network connections" \
        "lsof -i -n" "INFO" "$(lines_to_json_array "${F_lsof}")"

    # --- USERS ---
    write_finding_json "users" "local-users" "Local User Accounts" \
        "Local User Accounts" "All local user accounts (dscl)" \
        "dscl . -list /Users" "INFO" "$(lines_to_json_array "${F_users}")"

    write_finding_json "users" "login-shells" "Login Shell Accounts" \
        "Login Shell Accounts" "Accounts with interactive shell access" \
        "dscl . -list /Users UserShell" "INFO" "$(lines_to_json_array "${F_shell}")"

    write_finding_json "users" "admin-groups" "Admin / Privileged Groups" \
        "Admin Group Members" "Users in admin/wheel/sudo groups" \
        "dscl . -list /Groups GroupMembership" "INFO" "$(lines_to_json_array "${F_groups}")"

    write_finding_json "users" "sudoers-file" "Sudoers Configuration" \
        "Sudoers File" "Full sudoers configuration" \
        "cat /etc/sudoers" "INFO" "$(lines_to_json_array "${F_sudoers}")"

    write_finding_json "users" "active-sessions" "Active User Sessions" \
        "Active User Sessions" "Currently logged-in users" \
        "w" "INFO" "$(lines_to_json_array "${F_w}")"

    write_finding_json "users" "login-history" "Login History" \
        "Login History" "Recent successful logins (last)" \
        "last -Faiw" "INFO" "$(lines_to_json_array "${F_last2}")"

    write_finding_json "users" "failed-logins" "Failed Login Attempts" \
        "Failed Login Attempts" "Failed authentication attempts (lastb)" \
        "lastb" "MEDIUM" "$(lines_to_json_array "${F_lastb}")"

    write_finding_json "users" "auth-logs" "Authentication Logs" \
        "Authentication Logs" "SSH and sudo log entries from unified log" \
        "log show --predicate 'process==sshd OR process==sudo'" "INFO" \
        "$(lines_to_json_array "${F_authlogs}")"

    write_finding_json "users" "ssh-keys" "SSH Authorized Keys" \
        "SSH Authorized Keys" "SSH authorized_keys files found on system" \
        "find / -name authorized_keys" "INFO" "$(lines_to_json_array "${F_keys}")"

    write_finding_json "users" "login-items" "Login Items" \
        "macOS Login Items" "Applications configured to run at login" \
        "osascript (System Events)" "INFO" "$(lines_to_json_array "${F_loginitems}")"

    write_finding_json "users" "bash-history" "Shell History" \
        "Shell Command History" "Recent command history for all users across bash/zsh/sh/fish" \
        "tail -100 ~/.{bash,zsh,sh}_history ~/.local/share/fish/fish_history" "INFO" "$(lines_to_json_array "${F_bash_history}")"

    write_finding_json "users" "credential-file-timeline" "Credential File Timeline" \
        "Credential File Tampering Timeline" "mtime/ctime of auth-gating files (passwd, sudoers, group, authorized_keys) -- a ctime newer than mtime suggests a forged modification time" \
        "stat -f '%Sm %Sc' /etc/passwd /etc/sudoers /etc/group <authorized_keys>" "INFO" "$(lines_to_json_array "${F_cred_file_timeline}")"

    # --- SYSTEM ---
    write_finding_json "system" "os-info" "Operating System Information" \
        "OS and Kernel Information" "macOS version and kernel build" \
        "sw_vers && uname -a" "INFO" \
        "$(lines_to_json_array "$(printf '%s\n%s' "${F_sw_vers}" "${F_uname}")")"

    write_finding_json "system" "hardware-info" "Hardware Information" \
        "System Hardware Information" "Physical hardware details (system_profiler)" \
        "system_profiler SPHardwareDataType" "INFO" "$(lines_to_json_array "${F_lshw}")"

    write_finding_json "system" "cpu-info" "CPU Information" \
        "CPU Information" "Processor brand and specifications" \
        "sysctl -n machdep.cpu.brand_string" "INFO" "$(lines_to_json_array "${F_lscpu}")"

    write_finding_json "system" "disk-info" "Disk Information" \
        "Disk and Volume Information" "Disk and volume layout (diskutil list)" \
        "diskutil list" "INFO" "$(lines_to_json_array "${F_lsblk}")"

    write_finding_json "system" "usb-devices" "USB Devices" \
        "Connected USB Devices" "USB devices connected to the system" \
        "system_profiler SPUSBDataType" "INFO" "$(lines_to_json_array "${F_lsusb}")"

    write_finding_json "system" "gatekeeper" "Gatekeeper Status" \
        "Gatekeeper Status" "macOS Gatekeeper application security setting" \
        "spctl --status" "INFO" "$(lines_to_json_array "${F_gatekeeper}")"

    write_finding_json "system" "sip-status" "System Integrity Protection" \
        "SIP Status" "System Integrity Protection enabled/disabled state" \
        "csrutil status" "INFO" "$(lines_to_json_array "${F_sip}")"

    write_finding_json "system" "filevault" "FileVault Encryption" \
        "FileVault Status" "Full-disk encryption status" \
        "fdesetup status" "INFO" "$(lines_to_json_array "${F_filevault}")"

    write_finding_json "system" "kernel-taint" "Kernel/Kext Integrity Status" \
        "Kernel/Kext Integrity Status" "Non-Apple kernel extensions currently loaded, alongside SIP status -- macOS analog of Linux's kernel taint flags" \
        "kmutil showloaded / kextstat" "INFO" "$(lines_to_json_array "${F_kernel_taint}")"

    write_finding_json "system" "installed-apps" "Installed Applications" \
        "Installed Applications" "Applications in /Applications/" \
        "ls /Applications/" "INFO" "$(lines_to_json_array "${F_apps}")"

    write_finding_json "system" "tcc-database" "TCC Privacy Database" \
        "TCC Privacy Database" "Application permissions to privacy-sensitive resources" \
        "sqlite3 TCC.db 'SELECT * FROM access'" "HIGH" "$(lines_to_json_array "${F_tcc}")"

    write_finding_json "system" "quarantine-events" "Quarantine Events" \
        "Quarantine Events Database" "Files downloaded from the internet (quarantine DB)" \
        "sqlite3 QuarantineEventsV2" "INFO" "$(lines_to_json_array "${F_quarantine}")"

    write_finding_json "system" "recent-files" "Recently Modified Files" \
        "Recently Modified Files" "Files modified recently in user directories" \
        "find ~/Desktop ~/Downloads ~/Documents -newer /etc/passwd" "INFO" \
        "$(lines_to_json_array "${F_mdls_recent}")"

    # --- PROCESSES ---
    write_finding_json "processes" "running-processes" "Running Processes" \
        "Running Process List" "All running processes with full command lines" \
        "ps auxww" "INFO" "$(lines_to_json_array "${F_ps}")"

    write_finding_json "processes" "services" "LaunchCtl Services" \
        "LaunchCtl Service List" "Services managed by launchd" \
        "launchctl list" "INFO" "$(lines_to_json_array "${F_services}")"

    write_finding_json "processes" "launch-daemons" "Launch Daemons" \
        "System Launch Daemons" "Launch daemons in /Library/LaunchDaemons/" \
        "ls -la /Library/LaunchDaemons/" "MEDIUM" "$(lines_to_json_array "${F_launchdaemons}")"

    write_finding_json "processes" "launch-agents" "Launch Agents" \
        "System Launch Agents" "Launch agents in /Library/LaunchAgents/" \
        "ls -la /Library/LaunchAgents/" "MEDIUM" "$(lines_to_json_array "${F_launchagents}")"

    write_finding_json "processes" "user-launch-agents" "User Launch Agents" \
        "User Launch Agents" "User-level launch agents in ~/Library/LaunchAgents/" \
        "ls -la ~/Library/LaunchAgents/" "MEDIUM" "$(lines_to_json_array "${F_userlaunchagents}")"

    write_finding_json "processes" "cron-jobs" "Cron Jobs" \
        "Cron Job Entries" "User and system cron job entries" \
        "crontab -l" "INFO" "$(lines_to_json_array "${F_cron}")"

    write_finding_json "processes" "kernel-extensions" "Kernel Extensions" \
        "Loaded Kernel Extensions" "Kernel extensions loaded via kextstat" \
        "kextstat" "INFO" "$(lines_to_json_array "${F_lsmod}")"

    # --- FILES ---
    write_finding_json "files" "suid-binaries" "SUID Binaries" \
        "SUID / SGID Binaries" "Executables with SUID permission bits set" \
        "find / -type f -perm -u=s" "HIGH" "$(lines_to_json_array "${F_suid}")"

    write_finding_json "files" "capabilities" "File Capabilities / Interpreter Paths" \
        "Interpreter Binaries" "Python/Perl/Ruby interpreter paths with attributes" \
        "ls -la /usr/bin/python* /usr/bin/perl* /usr/bin/ruby*" "INFO" \
        "$(lines_to_json_array "${F_getcap}")"

    write_finding_json "files" "persistence-paths" "Persistence Locations" \
        "Persistence Mechanism Paths" "Files in common persistence locations" \
        "ls -la /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents" "MEDIUM" \
        "$(lines_to_json_array "$(printf '%s\n%s\n%s\n%s' "${F_p1}" "${F_p2}" "${F_p3}" "${F_p4}")")"

    write_finding_json "files" "path-writable" "World-Writable PATH Entries" \
        "World-Writable Directories/Files on \$PATH" "PATH directories or binaries writable by any local user, enabling PATH-hijack persistence or privilege escalation" \
        "stat -f %Lp <each \$PATH dir>" "HIGH" "$(lines_to_json_array "${F_path_ww}")"

    write_finding_json "files" "deleted-binaries" "Deleted Binary Execution" \
        "Processes Running From Deleted Binaries" "Processes still executing from a file that no longer exists on disk (fileless/self-deleting malware indicator)" \
        "lsof +L1" "HIGH" "$(lines_to_json_array "${F_deleted_exe}")"

    write_finding_json "files" "package-integrity" "Package Integrity Verification" \
        "Package Integrity Verification" "Signed System Volume seal status plus code-signature verification of installed /Applications bundles" \
        "csrutil authenticated-root status / codesign --verify --deep --strict" "HIGH" "$(lines_to_json_array "${F_pkg_integrity}")"

    # --- DETECTIONS ---
    local det_evidence="[]"
    if [[ -f "$(hostname)/LOGS/detections.csv" ]]; then
        det_evidence="$(lines_to_json_array "$(cat "$(hostname)/LOGS/detections.csv")")"
    fi
    write_finding_json "detections" "detection-results" "Detection Engine Results" \
        "MITRE ATT&CK Detection Results" \
        "Detection engine: ${DETECTION_COUNT:-0} total, ${CRITICAL_COUNT:-0} critical, ${HIGH_COUNT:-0} high, ${MEDIUM_COUNT:-0} medium, ${LOW_COUNT:-0} low" \
        "run_detections()" "HIGH" "${det_evidence}"

    green "[!] Per-check finding JSONs written to $(hostname)/investigation/"
    set -e
}

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
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$inv_dir" "$zip_out" <<'PYEOF'
import zipfile, sys, os, glob
inv_dir, zip_out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_out, 'w', zipfile.ZIP_DEFLATED) as z:
    for f in glob.glob(os.path.join(inv_dir, '**', '*.json'), recursive=True):
        z.write(f, os.path.basename(f))
PYEOF
    else
        yellow "[!] zip/python3 not available — JSONs are in ${inv_dir}"
        set -e
        return 0
    fi

    # Check the archive actually landed instead of assuming the command
    # above succeeded -- it previously reported "zipped" unconditionally.
    if [[ -f "$zip_out" ]]; then
        green "[!] Finding JSONs zipped: ${zip_out}"
    else
        yellow "[!] Zip step reported no error but ${zip_out} was not created -- JSONs are in ${inv_dir}"
    fi
    set -e
}

# Zip the entire investigation folder (full category-folder structure, not
# just the flat finding-JSONs zip from zip_findings()), hash it, and drop a
# Readme pointing at Forensicator Enterprise -- mirrors the Windows
# Investigation Archive feature.
create_investigation_archive() {
    set +e
    local investigation_dir="$(hostname)/investigation"
    local archive_zip="$(hostname)/investigation.zip"
    local readme_path="$(hostname)/Readme.txt"

    if [[ ! -d "$investigation_dir" ]] || ! find "$investigation_dir" -type f 2>/dev/null | grep -q .; then
        echo "[!] Skipping investigation archive - no investigation files were collected"
        set -e
        return 0
    fi

    cyan "[*] Creating investigation archive..."
    rm -f "$archive_zip"

    if command -v zip >/dev/null 2>&1; then
        (cd "$investigation_dir" && zip -rq "../investigation.zip" .)
    elif command -v python3 >/dev/null 2>&1; then
        python3 - "$investigation_dir" "$archive_zip" <<'PYEOF'
import zipfile, sys, os
inv_dir, zip_out = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(zip_out, 'w', zipfile.ZIP_DEFLATED) as z:
    for root, _, files in os.walk(inv_dir):
        for f in files:
            full = os.path.join(root, f)
            z.write(full, os.path.relpath(full, inv_dir))
PYEOF
    else
        echo "[!] Neither zip nor python3 available - cannot create investigation archive"
        set -e
        return 1
    fi

    if [[ ! -f "$archive_zip" ]]; then
        echo "[!] Failed to create investigation archive"
        set -e
        return 1
    fi

    # macOS ships `shasum` (a Perl wrapper), not GNU coreutils' `sha256sum`.
    local archive_hash
    archive_hash=$(shasum -a 256 "$archive_zip" 2>/dev/null | awk '{print $1}')

    cat > "$readme_path" <<README
Forensicator Investigation Archive
===================================

Host      : ${Hostname}
Generated : $(date)
Archive   : investigation.zip
SHA256    : ${archive_hash}

-----------------------------------------------
Forensicator Enterprise

The investigation archive can be uploaded to
Forensicator Enterprise for:

 * Log Analysis
 * IOC enrichment
 * Cross-host correlation
 * Timeline analysis
 * Case management
 * Team collaboration

Learn more:
https://forensicator.io
-----------------------------------------------
README

    green "[!] Investigation archive created: ${archive_zip} (SHA256: ${archive_hash})"
    echo ""
    cyan "Tip: This archive can be uploaded to"
    cyan "Forensicator Enterprise for automated analysis."
    echo ""
    set -e
}

run_detections() {
    cyan "[*] Running detection engine..."
    DETECTION_COUNT=0
    CRITICAL_COUNT=0
    HIGH_COUNT=0
    MEDIUM_COUNT=0
    LOW_COUNT=0
    DETECTION_FINDINGS=""

    # build_sigma_json() and the overview's "Top Detections" panel both read
    # DETECTIONS/findings.csv -- nothing previously wrote that file, so those
    # views were always empty no matter how many rules fired below.
    mkdir -p "$(hostname)/DETECTIONS"
    local findings_csv="$(hostname)/DETECTIONS/findings.csv"
    echo "severity,mitre_technique,category,description,evidence" > "$findings_csv"

    add_finding() {
        local severity="$1"
        local tactic="$2"
        local description="$3"
        DETECTION_FINDINGS+="<tr><td><span class=\"badge badge-${severity,,}\">${severity}</span></td><td>${tactic}</td><td>${description}</td></tr>\n"
        DETECTION_COUNT=$((DETECTION_COUNT+1))
        case $severity in
            CRITICAL) CRITICAL_COUNT=$((CRITICAL_COUNT+1)) ;;
            HIGH)     HIGH_COUNT=$((HIGH_COUNT+1)) ;;
            MEDIUM)   MEDIUM_COUNT=$((MEDIUM_COUNT+1)) ;;
            LOW)      LOW_COUNT=$((LOW_COUNT+1)) ;;
        esac
        local csv_desc="${description//,/;}"
        echo "${severity},${tactic},Detection,${csv_desc},${csv_desc}" >> "$findings_csv"
    }

    if echo "$F_ps" | grep -qE "(bash -i|sh -i|/dev/tcp/|/dev/udp/|nc -e|ncat -e|socat.*exec)"; then
        add_finding "CRITICAL" "T1059.004" "Possible reverse shell detected in process list"
    fi

    if echo "$F_ps" | grep -qE "(/tmp/|/var/folders/)"; then
        add_finding "HIGH" "T1059" "Process(es) executing from /tmp or /var/folders"
    fi

    if echo "$F_ps" | grep -qiE "(mimikatz|meterpreter|empire|sliver|cobaltstrike|mettle|pspy|linpeas|dnscat|chisel|frpc|frps|mythic)"; then
        add_finding "CRITICAL" "T1588" "Known attack tool detected in running process list"
    fi

    while IFS= read -r suid_file; do
        [[ -z "$suid_file" ]] && continue
        local is_std=0
        for std_path in /bin /usr/bin /sbin /usr/sbin /System; do
            [[ "$suid_file" == ${std_path}* ]] && is_std=1 && break
        done
        if [[ $is_std -eq 0 ]]; then
            add_finding "HIGH" "T1548.001" "Non-standard SUID binary: $suid_file"
            break
        fi
    done <<< "$F_suid"

    if echo "$F_passwd" | awk -F: '$3 == 0 && $1 != "root" {print $1}' | grep -q .; then
        add_finding "CRITICAL" "T1078.003" "Non-root account with UID 0 detected"
    fi

    if echo "$F_cron $F_p1 $F_p2 $F_p4" | grep -qE "(curl |wget |bash -i|/dev/tcp/|nc -e|python -c|base64 -d)"; then
        add_finding "HIGH" "T1053.003" "Suspicious commands found in cron or LaunchAgent/Daemon entries"
    fi

    local fail_ip
    fail_ip=$(echo "$F_authlogs" | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn | awk '$1>10{print $2}' | head -1)
    if [[ -n "$fail_ip" ]]; then
        add_finding "HIGH" "T1110.001" "More than 10 authentication failures from IP: $fail_ip"
    fi

    if echo "$F_launchdaemons $F_launchagents $F_userlaunchagents" | grep -qE "\.(sh|py|rb|pl|php|js)\b"; then
        add_finding "MEDIUM" "T1543.004" "LaunchDaemon/LaunchAgent plist pointing to script file"
    fi

    if echo "$F_sip" | grep -qi "disabled"; then
        add_finding "HIGH" "T1562.001" "System Integrity Protection (SIP) is DISABLED"
    fi

    if echo "$F_env" | grep -q "DYLD_INSERT_LIBRARIES"; then
        add_finding "CRITICAL" "T1574.006" "DYLD_INSERT_LIBRARIES detected in environment - possible dylib hijacking"
    fi

    if [[ -n "$F_keys" ]]; then
        while IFS= read -r keyfile; do
            [[ -z "$keyfile" ]] && continue
            if ! echo "$keyfile" | grep -qE "^/Users/[^/]+/\.ssh/authorized_keys$|^/root/\.ssh/authorized_keys$"; then
                add_finding "HIGH" "T1098.004" "Authorized keys found in unusual location: $keyfile"
                break
            fi
        done <<< "$F_keys"
    fi

    # Reuses F_kernel_taint's non-Apple-kext detection (collected earlier from
    # kmutil/kextstat with proper prefix filtering) instead of re-deriving it
    # here -- the original inline version false-positived whenever F_lsmod
    # was empty, since an empty line doesn't match the "^com.apple." allow
    # list either.
    if [[ "$F_kernel_taint" == "Non-Apple kernel extension"* ]]; then
        add_finding "MEDIUM" "T1047" "Non-Apple kernel extension (kext) loaded: $(echo "$F_non_apple_kexts" | head -1)"
    fi

    if echo "$F_ps" | grep -qE "ssh.*-[LRD][[:space:]]"; then
        add_finding "HIGH" "T1572" "SSH port forwarding detected in process list"
    fi

    local unusual_ports
    unusual_ports=$(echo "$F_ss2" | grep -E "LISTEN" | grep -vE ":(22|80|443|8080|8443|3306|5432|6379|27017|53|631|5900|548|139|445|111) " | head -5)
    if [[ -n "$unusual_ports" ]]; then
        add_finding "MEDIUM" "T1049" "Unusual listening ports detected"
    fi

    if find /Users -maxdepth 3 -name ".*" -type f -perm +111 2>/dev/null | grep -q .; then
        add_finding "MEDIUM" "T1564.001" "Hidden executable files found in /Users directories"
    fi

    if echo "$F_gatekeeper" | grep -qi "disabled"; then
        add_finding "LOW" "T1562.006" "Gatekeeper is DISABLED - unsigned applications can run freely"
    fi

    if echo "$F_ps" | grep -qiE "(tcpdump|wireshark|tshark|dumpcap)"; then
        add_finding "MEDIUM" "T1040" "Packet capture tool (tcpdump/wireshark) detected running"
    fi

    if echo "$F_ps" | grep -qiE "(osxpmem|volatility|osxdump|macmemcapture|avml)"; then
        add_finding "HIGH" "T1003.001" "Memory acquisition/dumping tool detected in process list"
    fi

    if echo "$F_ip" | grep -qE "^(utun|tun)[0-9]+:"; then
        add_finding "LOW" "T1572" "VPN/tunnel interface detected (utun/tun)"
    fi

    if echo "$F_env" | grep -qE "HISTFILE=/dev/null|HISTSIZE=0|HISTFILESIZE=0"; then
        add_finding "MEDIUM" "T1070.003" "Bash history appears to be cleared or disabled via environment variables"
    fi

    local timestomp_hits
    timestomp_hits=$(echo "$F_cred_file_timeline" | grep 'POSSIBLE TIMESTOMP' | head -1)
    if [[ -n "$timestomp_hits" ]]; then
        add_finding "HIGH" "T1070.006" "Credential file ctime is newer than its mtime (the modification time may have been forged): $timestomp_hits"
    fi

    if [[ -n "$F_path_ww" && "$F_path_ww" != "No world-writable directories or files found in \$PATH" ]]; then
        add_finding "HIGH" "T1574.007" "World-writable directory or file found on \$PATH -- any local user could plant a binary a privileged process resolves by name: $(echo "$F_path_ww" | head -1)"
    fi

    if [[ -n "$F_deleted_exe" && "$F_deleted_exe" != "No processes running from deleted binaries" ]]; then
        add_finding "CRITICAL" "T1070.004" "Process is running from a binary that no longer exists on disk (fileless/self-deleting malware indicator): $(echo "$F_deleted_exe" | head -1)"
    fi

    if [[ "$F_ssv_status" == *"disabled"* ]]; then
        add_finding "HIGH" "T1553" "Signed System Volume (SSV) authenticated-root is DISABLED -- OS image tamper protection is off"
    fi

    if [[ -n "$F_app_sig_issues" && "$F_app_sig_issues" != "No code-signature issues detected across /Applications" ]]; then
        add_finding "HIGH" "T1554" "Installed application failed code-signature verification (possible tampering): $(echo "$F_app_sig_issues" | head -1)"
    fi

    green "[!] Detection engine complete: $DETECTION_COUNT finding(s) (CRITICAL=$CRITICAL_COUNT HIGH=$HIGH_COUNT MEDIUM=$MEDIUM_COUNT LOW=$LOW_COUNT)"
}

# Recompute DETECTION_COUNT/*_COUNT from the final findings.csv, since both
# run_detections() (via add_finding) and the Sigma engine append rows to the
# same file -- this is the single source of truth after both have run.
recompute_detection_totals() {
    local findings_file="$(hostname)/DETECTIONS/findings.csv"
    [[ -f "$findings_file" ]] || return 0
    CRITICAL_COUNT=$(awk -F, 'NR>1 && $1=="CRITICAL"' "$findings_file" | wc -l | tr -d ' ')
    HIGH_COUNT=$(awk -F, 'NR>1 && $1=="HIGH"' "$findings_file" | wc -l | tr -d ' ')
    MEDIUM_COUNT=$(awk -F, 'NR>1 && $1=="MEDIUM"' "$findings_file" | wc -l | tr -d ' ')
    LOW_COUNT=$(awk -F, 'NR>1 && $1=="LOW"' "$findings_file" | wc -l | tr -d ' ')
    DETECTION_COUNT=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))
}

# Best-effort Sigma-rule detection engine for macOS: evaluates a compiled
# SigmaHQ macOS ruleset (Forensicator-Share/rules/macos/sigma_rules.json)
# against the unified log (`log show`) -- the only scriptable, historical
# telemetry source available without Apple's Endpoint Security Framework.
# Requires python3; skips cleanly and loudly if it isn't present. See the
# startup banner and sigma_runtime.py's module docstring for why coverage is
# inherently limited here (no accessible process-creation audit trail).
run_sigma_detections() {
    cyan "[*] Running Sigma detection engine (macOS ruleset, unified log -- best effort)"

    local python_bin=""
    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    fi

    if [[ -z "$python_bin" ]]; then
        echo "[!] Sigma engine skipped: python3 not found on this system"
        return 0
    fi

    local rules_file="$SCRIPT_DIR/Forensicator-Share/rules/macos/sigma_rules.json"
    if [[ ! -f "$rules_file" ]]; then
        echo "[!] Sigma engine skipped: rules file not found ($rules_file)"
        return 0
    fi

    local days_back min_level max_events cmd_timeout
    days_back=$(read_config_array "sigma_days_back" | head -1)
    [[ -z "$days_back" || ! "$days_back" =~ ^[0-9]+$ ]] && days_back=1
    min_level=$(read_config_array "sigma_min_level" | head -1)
    [[ -z "$min_level" ]] && min_level="medium"
    max_events=$(read_config_array "sigma_max_events" | head -1)
    [[ -z "$max_events" || ! "$max_events" =~ ^[0-9]+$ ]] && max_events=25000
    cmd_timeout=$(read_config_array "sigma_cmd_timeout_seconds" | head -1)
    [[ -z "$cmd_timeout" || ! "$cmd_timeout" =~ ^[0-9]+$ ]] && cmd_timeout=120

    mkdir -p "$(hostname)/DETECTIONS"
    local sigma_summary
    sigma_summary=$("$python_bin" "$SCRIPT_DIR/Forensicator-Share/sigma_runtime.py" \
        --rules "$rules_file" \
        --output "$(hostname)/DETECTIONS/findings.csv" \
        --days-back "$days_back" \
        --min-level "$min_level" \
        --max-events "$max_events" \
        --cmd-timeout "$cmd_timeout" 2>/dev/null)

    if [[ -n "$sigma_summary" ]]; then
        green "[!] Sigma engine: $sigma_summary"
    else
        echo "[!] Sigma engine produced no output (check for python3 errors)"
    fi

    recompute_detection_totals
}

# ─────────────────────────────────────────────
# Parameter parsing
# ─────────────────────────────────────────────
NAME=""
CASE=""
TITLE=""
LOCATION=""
DEVICE=""
RUN_PCAP=0
RUN_RAM=0
RUN_RANSOM=0
RUN_WEBLOGS=0
RUN_BROWSER=0
RUN_HASHCHECK=0
RUN_ENCRYPT=0
RUN_UPDATE=0

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -name|--name)     NAME="$2";     shift 2 ;;
        -case|--case)     CASE="$2";     shift 2 ;;
        -title|--title)   TITLE="$2";    shift 2 ;;
        -loc|--location)  LOCATION="$2"; shift 2 ;;
        -device|--device) DEVICE="$2";   shift 2 ;;
        -p|--pcap)        RUN_PCAP=1;    shift ;;
        -r|--ram)         RUN_RAM=1;     shift ;;
        -s|--ransom)      RUN_RANSOM=1;  shift ;;
        -w|--weblogs)     RUN_WEBLOGS=1; shift ;;
        -b|--browser)     RUN_BROWSER=1; shift ;;
        -H|--hashcheck)   RUN_HASHCHECK=1; shift ;;
        -e|--encrypt)     RUN_ENCRYPT=1; shift ;;
        -z|--update)      RUN_UPDATE=1;  shift ;;
        -u|--usage)       usage ;;
        *) echo "Error: Unknown option: $key"; usage ;;
    esac
done

echo ""
echo ""

if [[ -z "$NAME" ]];     then read -p "Enter investigator name: "    NAME;     fi
if [[ -z "$CASE" ]];     then read -p "Enter case reference number: " CASE;    fi
if [[ -z "$TITLE" ]];    then read -p "Enter investigation title: "   TITLE;   fi
if [[ -z "$LOCATION" ]]; then read -p "Enter examination location: "  LOCATION; fi
if [[ -z "$DEVICE" ]];   then read -p "Enter device description: "    DEVICE;  fi

echo ""
echo ""

if [[ -z "$NAME" || -z "$CASE" || -z "$TITLE" || -z "$LOCATION" || -z "$DEVICE" ]]; then
    echo "Error: Missing required investigator or case details."
    usage
fi

if [[ $RUN_UPDATE   -eq 1 ]]; then CheckForUpdates; fi
if [[ $RUN_PCAP     -eq 1 ]]; then pcap;    fi
if [[ $RUN_RAM      -eq 1 ]]; then ram;     fi
if [[ $RUN_WEBLOGS  -eq 1 ]]; then weblogs; fi
if [[ $RUN_BROWSER  -eq 1 ]]; then browser; fi
if [[ $RUN_RANSOM   -eq 1 ]]; then ransom;  fi

# ─────────────────────────────────────────────
# HTML output file variables
# ─────────────────────────────────────────────
ForensicatorIndexFile="$(hostname)/index.html"
NetworkFile="$(hostname)/network.html"
UserFile="$(hostname)/users.html"
SystemFile="$(hostname)/system.html"
ProcessFile="$(hostname)/processes.html"
OthersFile="$(hostname)/others.html"
DetectionsFile="$(hostname)/detections.html"
ForensicatorExtrasFile="$(hostname)/extras.html"

mkdir -p "$(hostname)/OTHER"

###############################################
# DATA COLLECTION
###############################################

cyan "[*] Collecting Network Information..."

F_ip=$(ifconfig 2>/dev/null)
F_route=$(netstat -rn 2>/dev/null)
F_ps=$(ps auxww 2>/dev/null)
F_lsof=$(lsof -i -n 2>/dev/null)
F_ss=$(netstat -an 2>/dev/null)
F_ss2=$(netstat -antp 2>/dev/null || lsof -i -n -P 2>/dev/null)
F_iptables=$(pfctl -sr 2>/dev/null || echo "pfctl not available or not running")
F_hosts=$(cat /etc/hosts 2>/dev/null)
F_resolv=$(cat /etc/resolv.conf 2>/dev/null)
F_arp=$(arp -a 2>/dev/null)
F_dns=$(scutil --dns 2>/dev/null)

echo "IP Only Connections" > ./$(hostname)/OTHER/IP_Connections.txt
echo "$F_lsof" >> ./$(hostname)/OTHER/IP_Connections.txt
echo "All Network Sockets" > ./$(hostname)/OTHER/IP_Connections2.txt
echo "$F_ss" >> ./$(hostname)/OTHER/IP_Connections2.txt

green "[!] Done"

cyan "[*] Collecting System Information..."

F_uname=$(uname -a 2>/dev/null)
F_sw_vers=$(sw_vers 2>/dev/null)
F_system_profiler=$(system_profiler SPSoftwareDataType SPHardwareDataType 2>/dev/null)
F_lshw=$(system_profiler SPHardwareDataType 2>/dev/null)
F_lscpu=$(sysctl -n machdep.cpu.brand_string 2>/dev/null)
F_lsblk=$(diskutil list 2>/dev/null)
F_lsusb=$(system_profiler SPUSBDataType 2>/dev/null)
F_apps=$(ls /Applications/ 2>/dev/null)
F_brew=$(brew list 2>/dev/null || echo "Homebrew not installed")
F_gatekeeper=$(spctl --status 2>/dev/null)
F_sip=$(csrutil status 2>/dev/null)
F_filevault=$(fdesetup status 2>/dev/null)
F_lsmod=$(kextstat 2>/dev/null)
F_env=$(env 2>/dev/null)

echo "Hardware Info" > ./$(hostname)/OTHER/Hardware_Info.txt
echo "$F_lshw" >> ./$(hostname)/OTHER/Hardware_Info.txt
echo "Kernel Extensions" > ./$(hostname)/OTHER/Kexts.txt
echo "$F_lsmod" >> ./$(hostname)/OTHER/Kexts.txt

green "[!] Done"

cyan "[*] Collecting User Information..."

F_w=$(w 2>/dev/null)
F_who=$(who -a 2>/dev/null)
F_users=$(dscl . -list /Users 2>/dev/null)
F_shell=$(dscl . -list /Users UserShell 2>/dev/null | grep -v /usr/bin/false | grep -v /sbin/nologin)
# Combined with the SUID walk below into one pass over "/" instead of two,
# pruning virtual/mirrored mounts and device nodes along the way.
F_suid_and_keys=$(find / \( "${PRUNE_PATHS[@]}" \) -prune -o -type f \( -perm -u=s -o -name authorized_keys \) -print 2>/dev/null)
F_keys=$(echo "$F_suid_and_keys" | grep 'authorized_keys$' | head -50)
F_passwd=$(cat /etc/passwd 2>/dev/null)
F_sudoers=$(cat /etc/sudoers 2>/dev/null)
F_groups=$(dscl . -list /Groups GroupMembership 2>/dev/null | grep -E "^(admin|wheel|sudo)")
F_lastlog=$(last -50 2>/dev/null)
F_lastb=$(lastb 2>/dev/null | head -100 || echo "lastb not available on this system")

# Credential-file tampering timeline: mtime (content) vs ctime (metadata) on
# the files that gate authentication. A ctime noticeably newer than mtime on
# one of these is a timestomping tell -- content or perms were touched after
# the fact and the mtime was faked back, but ctime can't be faked without
# root-level timestomp tooling. Uses BSD `stat -f` format specifiers (%m/%c
# raw epoch, %Sm/%Sc formatted) -- macOS ships BSD stat, not GNU coreutils.
F_cred_file_timeline=""
F_cred_files=(/etc/passwd /etc/sudoers /etc/group)
while IFS= read -r keyfile; do
    [[ -n "$keyfile" ]] && F_cred_files+=("$keyfile")
done <<< "$F_keys"
for f in "${F_cred_files[@]}"; do
    [[ -f "$f" ]] || continue
    f_mtime_epoch=$(stat -f '%m' "$f" 2>/dev/null)
    f_ctime_epoch=$(stat -f '%c' "$f" 2>/dev/null)
    f_mtime=$(stat -f '%Sm' "$f" 2>/dev/null)
    f_ctime=$(stat -f '%Sc' "$f" 2>/dev/null)
    f_flag=""
    if [[ -n "$f_mtime_epoch" && -n "$f_ctime_epoch" ]] && (( f_ctime_epoch - f_mtime_epoch > 60 )); then
        f_flag=" [POSSIBLE TIMESTOMP: ctime ~$((f_ctime_epoch - f_mtime_epoch))s newer than mtime]"
    fi
    F_cred_file_timeline+="${f} | mtime=${f_mtime} | ctime=${f_ctime}${f_flag}"$'\n'
done
[[ -z "$F_cred_file_timeline" ]] && F_cred_file_timeline="No credential files found"

# Per-user shell histories -- not just the invoking user's. Loops every real
# home directory (/var/root plus /Users/*) across bash/zsh/sh/fish; zsh is
# the default shell on macOS since Catalina, so .zsh_history is at least as
# relevant here as .bash_history.
F_bash_history=""
for home_dir in /var/root /Users/*/; do
    [[ -d "$home_dir" ]] || continue
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

cyan "[*] Collecting Process Information..."

F_services=$(launchctl list 2>/dev/null)
F_launchdaemons=$(ls -la /Library/LaunchDaemons/ 2>/dev/null)
F_launchagents=$(ls -la /Library/LaunchAgents/ 2>/dev/null)
F_userlaunchagents=$(ls -la ~/Library/LaunchAgents/ 2>/dev/null)
F_cron=$(crontab -l 2>/dev/null; echo "--- /var/at/tabs ---"; ls -la /var/at/tabs/ 2>/dev/null)
F_loginitems=$(osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null || echo "Could not query login items")
F_p1=$(ls -la /Library/LaunchDaemons/ 2>/dev/null)
F_p2=$(ls -la /Library/LaunchAgents/ 2>/dev/null)
F_p3=$(ls -la /System/Library/LaunchDaemons/ 2>/dev/null | head -50)
F_p4=$(ls -la ~/Library/LaunchAgents/ 2>/dev/null)

green "[!] Done"

cyan "[*] Collecting Other Information..."

# Derived from the combined suid+authorized_keys walk done earlier, instead
# of a second full "/" pass.
F_suid=$(echo "$F_suid_and_keys" | grep -v 'authorized_keys$' | head -100)
F_last2=$(last -Faiw 2>/dev/null)
F_getcap=$(ls -la /usr/bin/python* /usr/bin/perl* /usr/bin/ruby* 2>/dev/null)

# World-writable directories/files on $PATH: lets any local user drop or
# overwrite a binary that a privileged process/script later resolves and
# executes by bare name -- a classic PATH-hijack persistence/priv-esc vector.
# Uses BSD `stat -f %Lp` (permission bits in octal, unpadded) -- macOS ships
# BSD stat, not GNU coreutils.
F_path_ww=""
IFS=':' read -ra F_path_dirs <<< "$PATH"
for path_dir in "${F_path_dirs[@]}"; do
    [[ -d "$path_dir" ]] || continue
    path_dir_perm=$(stat -f '%Lp' "$path_dir" 2>/dev/null)
    if [[ -n "$path_dir_perm" && "${path_dir_perm: -1}" =~ [2367] ]]; then
        F_path_ww+="WRITABLE_DIR: ${path_dir} (mode ${path_dir_perm})"$'\n'
    fi
    while IFS= read -r ww_file; do
        F_path_ww+="WRITABLE_FILE: ${ww_file}"$'\n'
    done < <(find "$path_dir" -maxdepth 1 -type f -perm -o+w 2>/dev/null)
done
[[ -z "$F_path_ww" ]] && F_path_ww="No world-writable directories or files found in \$PATH"

# Deleted-but-running binaries: macOS has no /proc, so this uses lsof's
# documented `+L1` flag (list open files with a link count under 1) instead
# of the /proc/<pid>/exe "(deleted)" marker the Linux collector reads.
# Filtered to FD=txt (the process's own executable/loaded library text
# segment), matching the "process still executing from a file that no
# longer exists on disk" fileless/self-deleting malware indicator.
F_deleted_exe=""
if command -v lsof >/dev/null 2>&1; then
    F_deleted_exe=$(lsof +L1 2>/dev/null | awk 'NR==1{next} $4=="txt"{print}')
fi
[[ -z "$F_deleted_exe" ]] && F_deleted_exe="No processes running from deleted binaries"

# Kernel/kext integrity status - macOS analog of Linux's
# /proc/sys/kernel/tainted. There's no single bitmask equivalent, so this
# surfaces the two signals that together indicate whether unsigned/
# third-party code could be running in kernel space: any currently loaded
# non-Apple kernel extension, plus SIP status (F_sip, collected above) as
# context. `kmutil` is the modern (macOS 11+) tool; `kextstat` is the
# pre-Big-Sur / Intel fallback.
if command -v kmutil >/dev/null 2>&1; then
    F_kext_raw=$(kmutil showloaded 2>/dev/null)
elif command -v kextstat >/dev/null 2>&1; then
    F_kext_raw=$(kextstat 2>/dev/null)
else
    F_kext_raw=""
fi
F_non_apple_kexts=$(printf '%s' "$F_kext_raw" | awk 'NR>1 && NF>0' | grep -viE 'com\.apple\.|org\.virtualbox\.|com\.vmware\.|com\.parallels\.')
if [[ -n "$F_non_apple_kexts" ]]; then
    F_kernel_taint="Non-Apple kernel extension(s) loaded (SIP: ${F_sip:-unknown}):"$'\n'"${F_non_apple_kexts}"
else
    F_kernel_taint="No non-Apple kernel extensions currently loaded (SIP: ${F_sip:-unknown})"
fi

# Package/application integrity verification: macOS has no rpm/dpkg. The two
# checks that actually correspond to "was something tampered with here" on
# this platform are: whether the Signed System Volume's cryptographic seal
# is active (the OS image itself, sealed and verified since Catalina -- a
# stronger guarantee than a checksum database, when present), and whether
# installed /Applications bundles still carry a valid, unmodified code
# signature (the analog of a package manager's checksum verification for
# third-party software). `timeout` isn't part of the BSD base install --
# fall back to `gtimeout` (Homebrew coreutils) or run unbounded if neither
# exists.
pkg_integrity_timeout=$(read_config_array "pkg_integrity_timeout_seconds" | head -1)
[[ -z "$pkg_integrity_timeout" || ! "$pkg_integrity_timeout" =~ ^[0-9]+$ ]] && pkg_integrity_timeout=180
pkg_integrity_max_lines=$(read_config_array "pkg_integrity_max_lines" | head -1)
[[ -z "$pkg_integrity_max_lines" || ! "$pkg_integrity_max_lines" =~ ^[0-9]+$ ]] && pkg_integrity_max_lines=100

TIMEOUT_CMD=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD="timeout $pkg_integrity_timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD="gtimeout $pkg_integrity_timeout"
fi

cyan "[*] Verifying system volume seal and application code signatures (this can take a while)..."

F_ssv_status=$(csrutil authenticated-root status 2>/dev/null)
[[ -z "$F_ssv_status" ]] && F_ssv_status="Not available (requires macOS 11+ on Apple Silicon or a T2 Mac)"

F_app_sig_issues=""
if command -v codesign >/dev/null 2>&1; then
    F_app_sig_issues=$($TIMEOUT_CMD find /Applications -maxdepth 1 -name "*.app" -exec bash -c '
        result=$(codesign --verify --deep --strict "$1" 2>&1 1>/dev/null)
        [[ -n "$result" ]] && echo "${1}: ${result}"
    ' _ {} \; 2>/dev/null | head -n "$pkg_integrity_max_lines")
fi
[[ -z "$F_app_sig_issues" ]] && F_app_sig_issues="No code-signature issues detected across /Applications"
F_pkg_integrity="Signed System Volume (SSV) authenticated-root status: ${F_ssv_status}"$'\n'"${F_app_sig_issues}"

# Not chained with `||`: `log show` exits 0 even when its predicate matches
# nothing, so an empty-but-successful unified-log query could swallow the
# /var/log/system.log fallback and the final "not found" message alike.
# Checked explicitly instead, and widened past generic "session opened"/
# "sudo" text to actual SSH connection events (accepted/failed logins,
# invalid users, disconnects) so this shows real SSH traffic to/from the host.
AUTH_LOG_PATTERN='sshd.*(Accepted (password|publickey|keyboard-interactive)|Failed password|Invalid user|Connection (closed|reset)|Disconnected from|session (opened|closed))|sudo.*COMMAND'

F_authlogs=""
if command -v log >/dev/null 2>&1; then
    F_authlogs=$(log show --predicate 'process == "sshd" OR process == "sudo" OR process == "su"' --style syslog --last 7d 2>/dev/null | grep -iE "$AUTH_LOG_PATTERN" | head -500)
fi
if [[ -z "$F_authlogs" && -r /var/log/system.log ]]; then
    F_authlogs=$(grep -iE "$AUTH_LOG_PATTERN" /var/log/system.log 2>/dev/null | head -500)
fi
if [[ -z "$F_authlogs" ]]; then
    F_authlogs="No SSH/auth events found (checked unified log via 'log show' and /var/log/system.log)"
fi
F_tcc=$(sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" 'SELECT * FROM access' 2>/dev/null | head -100 || echo "TCC DB access denied - requires root")
F_quarantine=$(sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 'SELECT LSQuarantineAgentName, LSQuarantineDataURLString, date(LSQuarantineTimeStamp + 978307200, "unixepoch") FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 100' 2>/dev/null || echo "Quarantine DB not accessible")
F_mdls_recent=$(find ~/Desktop ~/Downloads ~/Documents -newer /etc/passwd -maxdepth 2 2>/dev/null | head -50)
F_bashrc=$(cat ~/.bash_profile ~/.bashrc ~/.zshrc 2>/dev/null | head -100)

echo "Auth Logs" > ./$(hostname)/OTHER/AuthLogs.txt
echo "$F_authlogs" >> ./$(hostname)/OTHER/AuthLogs.txt
echo "Shell Profile" > ./$(hostname)/OTHER/Shell_Profile.txt
echo "$F_bashrc" >> ./$(hostname)/OTHER/Shell_Profile.txt

ioc_checks

if [[ $RUN_HASHCHECK -eq 1 ]]; then
    hash_check
else
    F_hash_results="Hash check not requested (use -H flag)"
fi

if [[ $RUN_BROWSER -eq 1 ]]; then
    browser_ioc_check
else
    F_browser_ioc_hits="Browser history not collected (use -b flag)"
fi

green "[!] Done"

enddate=$(date '+%Y-%m-%d %H:%M:%S')

run_detections
run_sigma_detections


###############################################
# Single-page HTML Report (Windows-compatible SPA)
###############################################

#########################################################
# Single-page HTML Report (Windows-compatible SPA)
#########################################################

html_esc() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

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
            _j+="\"LogName\":\"macos-forensicator\","
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
       [[ "$F_hash_results" != *"not requested"* ]]; then
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
        "${F_suspicious_sh_hits:-}" \
        "${F_browser_ioc_hits:-}")"
    while IFS= read -r _ln; do
        [[ -z "$_ln" ]] && continue
        [[ "$_ln" == "No matches found" ]] && continue
        [[ "$_ln" == *"not requested"* ]] && continue
        [[ "$_ln" == *"not collected"* ]] && continue
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
    # Collect fast scalars first (subshells OK here — called only once each)
    local _os_name _os_ver _kern _arch _hostip _uname_a _pname _pver _pbuild
    _pname=$(sw_vers -productName 2>/dev/null)
    _pver=$(sw_vers -productVersion 2>/dev/null)
    _pbuild=$(sw_vers -buildVersion 2>/dev/null)
    _os_ver="${_pname} ${_pver}"
    _kern=$(uname -r 2>/dev/null); _arch=$(uname -m 2>/dev/null)
    _hostip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null)
    _uname_a=$(uname -a 2>/dev/null)

    _frag_host_summary=""
    _frag_host_summary+="$(kv_list_row 'host.hostname'           "${Hostname}")"
    _frag_host_summary+="$(kv_list_row 'host.os'                "${_os_ver}")"
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
    _frag_os_info+="$(kv_list_row 'ProductName'    "${_pname}")"
    _frag_os_info+="$(kv_list_row 'ProductVersion' "${_pver}")"
    _frag_os_info+="$(kv_list_row 'BuildVersion'   "${_pbuild}")"
    _frag_os_info+="$(kv_list_row 'uname'          "${_uname_a}")"
    _frag_os_info+="$(kv_list_row 'SIP'            "${F_sip}")"
    _frag_os_info+="$(kv_list_row 'FileVault'      "${F_filevault}")"
    _frag_os_info+="$(kv_list_row 'Gatekeeper'     "${F_gatekeeper}")"
    _frag_os_info+="$(kv_list_row 'kernel.taint'   "${F_kernel_taint:-Not accessible}")"

    # Top detections — inline-escape, no subshells inside loop
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

    # Users — inline-escape, no subshells per row
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

    # Cap large data sources before processing
    local _ps500 _ss500 _auth500 _lsof500 _svc500 _hist300 _sshcfg
    _ps500=$(printf '%s' "$F_ps"      | head -500)
    _ss500=$(printf '%s' "$F_ss"      | head -500)
    _auth500=$(printf '%s' "$F_authlogs" | head -500)
    _lsof500=$(printf '%s' "$F_lsof"  | head -500)
    _svc500=$(printf '%s' "$F_services" | head -300)
    _hist300=$(printf '%s' "$F_bash_history" | head -300)
    _sshcfg=$(cat /etc/ssh/sshd_config 2>/dev/null | head -80)

    _frag_sudo="$(pre_rows "$F_sudoers")"
    _frag_sessions="$(pre_rows "$F_w")"
    _frag_login_history="$(pre_rows "${F_last2:-${F_lastlog:-}}")"
    _frag_failed_logins="$(pre_rows "$F_lastb")"
    _frag_ssh_keys="$(pre_rows "$F_keys")"
    _frag_cred_timeline="$(pre_rows "${F_cred_file_timeline:-No credential files found}")"
    _frag_who="$(pre_rows "$F_who")"
    _frag_cpu="$(pre_rows "$F_lscpu")"
    _frag_disk="$(pre_rows "$F_lsblk")"
    _frag_hardware="$(pre_rows "$F_system_profiler")"
    _frag_usb="$(pre_rows "$F_lsusb")"
    _frag_interfaces="$(pre_rows "$F_ip")"
    _frag_routes="$(pre_rows "$F_route")"
    _frag_connections="$(pre_rows "$_ss500")"
    _frag_ports="$(pre_rows "$F_ss2")"
    _frag_arp="$(pre_rows "$F_arp")"
    _frag_firewall="$(pre_rows "$F_iptables")"
    _frag_dns="$(pre_rows "$(printf '%s\n--- hosts ---\n%s\n--- scutil --dns ---\n%s' "$F_resolv" "$F_hosts" "$F_dns")")"
    _frag_lsof="$(pre_rows "$_lsof500")"
    _frag_procs="$(pre_rows "$_ps500")"
    _frag_services="$(pre_rows "$_svc500")"
    _frag_cron="$(pre_rows "${F_cron:-}")"
    local _launch_all
    _launch_all="$(printf '--- LaunchDaemons ---\n%s\n--- LaunchAgents ---\n%s\n--- User LaunchAgents ---\n%s\n--- Login Items ---\n%s' \
        "${F_launchdaemons:-}" "${F_launchagents:-}" "${F_userlaunchagents:-}" "${F_loginitems:-}")"
    _frag_enabled_units="$(pre_rows "$_launch_all")"
    _frag_modules="$(pre_rows "$F_lsmod")"
    local _persist_all
    _persist_all="$(printf '%s\n%s\n%s\n%s' "${F_p1:-}" "${F_p2:-}" "${F_p3:-}" "${F_p4:-}")"
    _frag_persistence="$(pre_rows "$_persist_all")"
    _frag_authlogs="$(pre_rows "$_auth500")"
    _frag_bash_history="$(pre_rows "$_hist300")"
    _frag_sshconfig="$(pre_rows "$_sshcfg")"
    _frag_bashrc="$(pre_rows "$F_bashrc")"
    _frag_suid="$(pre_rows "$F_suid")"
    _frag_caps="$(pre_rows "$F_getcap")"
    _frag_path_ww="$(pre_rows "${F_path_ww:-No world-writable directories or files found in \$PATH}")"
    _frag_deleted_exe="$(pre_rows "${F_deleted_exe:-No processes running from deleted binaries}")"
    _frag_pkg_integrity="$(pre_rows "${F_pkg_integrity:-Package integrity verification not available}")"
    _frag_tcc="$(pre_rows "$F_tcc")"
    _frag_quarantine="$(pre_rows "$F_quarantine")"
    _frag_ioc_exec="$(pre_rows "${F_suspicious_exec_hits:-No executable IOC data}")"
    _frag_ioc_sh="$(pre_rows "${F_suspicious_sh_hits:-No shell command IOC data}")"
    _frag_browser_ioc="$(pre_rows "${F_browser_ioc_hits:-Browser IOC check not requested}")"
    _frag_hash_results="$(pre_rows "${F_hash_results:-Hash check not requested}")"
    _frag_apps="$(pre_rows "$F_apps")"
    _frag_brew="$(pre_rows "$F_brew")"
    _frag_mdls="$(pre_rows "$F_mdls_recent")"
}

generate_report_html() {
    set +e
    cyan "[*] Generating single-page HTML report..."

    local _rd; _rd="$(hostname)/reports"
    mkdir -p "$_rd"

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
    <div class="sb-link" onclick="nav('macos')"><i class="sb-icon">&#127822;</i> macOS Specific</div>
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

    cat >> "$_out" << VIEWS
<!-- OVERVIEW -->
<div class="view active" id="view-overview">
  <div class="view-header">
    <div><div class="view-title">Investigation Overview</div>
    <div class="view-sub">Summary of collected artifacts and detections &#8212; macOS &#183; ${Hostname}</div></div>
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
      <div class="panel-head"><div class="panel-title">&#128737; Sudo / Sudoers</div></div>
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
      <div class="panel-head"><div class="panel-title">&#128220; Login History</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Login Entry</th></tr></thead>
      <tbody>${_frag_login_history}</tbody></table></div>
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
    <div class="view-sub">macOS version, hardware, disk, USB devices</div></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128421; OS &amp; Security Details</div></div>
      <div class="kv-list">${_frag_os_info}</div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#9881; CPU Info</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>CPU Info</th></tr></thead>
      <tbody>${_frag_cpu}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128190; Disk Info (diskutil list)</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Disk Info</th></tr></thead>
    <tbody>${_frag_disk}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128268; USB Devices <span class="panel-count" id="usb-count">0</span></div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>USB Device</th></tr></thead>
      <tbody id="usb-tbody">${_frag_usb}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129513; Hardware Info</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Hardware Info</th></tr></thead>
      <tbody>${_frag_hardware}</tbody></table></div>
    </div>
  </div>
</div>

<!-- PROCESSES -->
<div class="view" id="view-processes">
  <div class="view-header">
    <div><div class="view-title">Processes &amp; Services</div>
    <div class="view-sub">Running processes, launchd services, cron, persistence, kernel extensions</div></div>
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
      <div class="panel-head"><div class="panel-title">&#9889; Launchd Services <span class="panel-count" id="svc-count">0</span></div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Service Info</th></tr></thead>
      <tbody id="svc-tbody">${_frag_services}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#9989; LaunchDaemons &amp; LaunchAgents</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Launch Item</th></tr></thead>
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
      <div class="panel-head"><div class="panel-title">&#128295; Persistence Paths</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Path Entry</th></tr></thead>
      <tbody>${_frag_persistence}</tbody></table></div>
    </div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128039; Kernel Extensions (kextstat)</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Kext Info</th></tr></thead>
    <tbody>${_frag_modules}</tbody></table></div>
  </div>
</div>

<!-- NETWORK -->
<div class="view" id="view-network">
  <div class="view-header">
    <div><div class="view-title">Network</div>
    <div class="view-sub">Interfaces, connections, ports, ARP, firewall (pfctl), DNS</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#127760; Interfaces (ifconfig) <span class="panel-count" id="net-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter interfaces..." oninput="filterTable('net-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Interface Info</th></tr></thead>
    <tbody id="net-tbody">${_frag_interfaces}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128268; Active Connections (netstat -an) <span class="panel-count" id="conn-count">0</span></div></div>
    <div class="search-bar"><div class="search-wrap"><span class="search-ico">&#8981;</span>
      <input type="text" placeholder="Filter connections..." oninput="filterTable('conn-tbody',this.value,[0])"/>
    </div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Connection Info</th></tr></thead>
    <tbody id="conn-tbody">${_frag_connections}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128225; ARP / Neighbor Table</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>ARP Entry</th></tr></thead>
      <tbody>${_frag_arp}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128737; Firewall Rules (pfctl)</div></div>
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
    <div class="view-sub">Authentication logs, bash/zsh history, SSH config</div></div>
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
    <div class="panel-head"><div class="panel-title">&#128273; World-Writable PATH Entries</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Writable Directory/File</th></tr></thead>
    <tbody>${_frag_path_ww}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128128; Deleted Binary Execution</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Process Running From a Deleted Binary</th></tr></thead>
    <tbody>${_frag_deleted_exe}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128230; Package Integrity Verification</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>SSV Status / Code-Signature Issue</th></tr></thead>
    <tbody>${_frag_pkg_integrity}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129440; Suspicious Executable Matches</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Match</th></tr></thead>
      <tbody>${_frag_ioc_exec}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#129440; Suspicious Shell Command Matches</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Match</th></tr></thead>
      <tbody>${_frag_ioc_sh}</tbody></table></div>
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
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128194; Recently Modified Files</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>File Path</th></tr></thead>
    <tbody>${_frag_mdls}</tbody></table></div>
  </div>
</div>

<!-- MACOS SPECIFIC -->
<div class="view" id="view-macos">
  <div class="view-header">
    <div><div class="view-title">macOS Specific</div>
    <div class="view-sub">TCC privacy database, quarantine events, installed apps, Homebrew</div></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#128274; TCC Privacy Database</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>TCC Access Entry</th></tr></thead>
    <tbody>${_frag_tcc}</tbody></table></div>
  </div>
  <div class="panel">
    <div class="panel-head"><div class="panel-title">&#127988; Quarantine Events</div></div>
    <div class="tbl-wrap"><table class="std"><thead><tr><th>Quarantine Entry</th></tr></thead>
    <tbody>${_frag_quarantine}</tbody></table></div>
  </div>
  <div class="grid-2">
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#128040; Installed Applications</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Application</th></tr></thead>
      <tbody>${_frag_apps}</tbody></table></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div class="panel-title">&#127866; Homebrew Packages</div></div>
      <div class="tbl-wrap"><table class="std"><thead><tr><th>Package</th></tr></thead>
      <tbody>${_frag_brew}</tbody></table></div>
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
    'users-tbody':[0,3,4],'sessions-tbody':[0],
    'procs-tbody':[0],'svc-tbody':[0],'net-tbody':[0],
    'conn-tbody':[0],'evtlog-tbody':[0],
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
    'conn-tbody':'conn-count'
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
# Write metadata JSON, structured logs, per-check JSONs
#########################################################
write_metadata_json
write_structured_log
generate_findings_json
create_investigation_archive
zip_findings

#########################################################
# COMPLETION SUMMARY
#########################################################
echo ""
green "[!] ============================================================"
green "[!]  Live Forensicator (macOS) - Collection Complete"
green "[!] ============================================================"
green "[!]  Hostname    : $Hostname"
green "[!]  Case        : $CASE"
green "[!]  Investigator: $NAME"
green "[!]  Output Dir  : $(pwd)/$Hostname"
green "[!] ============================================================"
green "[!]  DETECTIONS  : ${DETECTION_COUNT:-0} total findings"
echo  "      CRITICAL   : ${CRITICAL_COUNT:-0}"
echo  "      HIGH       : ${HIGH_COUNT:-0}"
echo  "      MEDIUM     : ${MEDIUM_COUNT:-0}"
echo  "      LOW        : ${LOW_COUNT:-0}"
green "[!] ============================================================"
green "[!]  Open $Hostname/index.html in a browser to view results"
green "[!]  Upload $Hostname/investigation.zip (see $Hostname/Readme.txt) to Forensicator Enterprise"
green "[!]  Upload ${Hostname}_findings.zip to Forensicator Enterprise"
green "[!] ============================================================"