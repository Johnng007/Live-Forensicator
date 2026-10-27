#!/bin/bash
#
# Raw macOS artifact acquisition (-A / --artifacts) — sourced by
# forensicator.sh. The macOS counterpart of the Linux collector's -A and the
# Windows collector's -WINARTIFACTS: it copies the artifacts themselves
# rather than command output, so Forensicator Core can parse them (Host
# Artifacts -> Collector folder upload) and an analyst can re-examine the
# originals.
#
# Output, below <host>/artifacts/MacArtifacts/:
#   Files/<absolute path>     raw copies, mirrored at their real path, with
#                             timestamps, modes and extended attributes kept
#                             (cp -p), SQLite -wal/-shm files alongside
#   Commands/<name>.txt       command output that has no file of its own
#                             (sockets, background items, signing, ...)
#   Commands/codesign.tsv     code signature of every running executable and
#                             every launch item's program
#   Processes/processes.tsv   one row per process, SHA-256 and signer of its
#                             executable
#   Timeline/bodyfile.txt     TSK bodyfile (MACB times, with birth time) of
#                             config-driven paths
#   Logs/unifiedlog-*.log     targeted unified log exports (authentication,
#                             XProtect/Gatekeeper), RFC 3339 timestamps
#   CollectionManifest/artifact-collection-manifest.json
#                             one record per acquisition (Collected / Skipped
#                             / Failed) with the SHA-256 of every collected
#                             file — same format as the Windows and Linux
#                             collectors', verified by Core at upload time
#
# Volatile data first: processes, sockets and sessions are read before any
# file copying or filesystem walk.
#
# Needs root, and Full Disk Access for the terminal, for a complete
# collection (account records, TCC, other users' Library folders, FSEvents);
# a partial run is recorded as such in the manifest.
#
# macOS ships bash 3.2: no associative arrays, no ${var,,}.

MA_ROOT=""
MA_MANIFEST_LINES=""
MA_SEEN=""
MA_SIGN_CACHE=""
MA_MAX_FILE_BYTES=0

ma_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# ma_record STATUS LABEL SOURCE DEST_REL SIZE SHA256 NOTE
ma_record() {
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '{"TimestampUtc":"%s","Label":"%s","SourcePath":"%s","DestinationPath":"%s","Status":"%s","SizeBytes":%s,"SHA256":"%s","Note":"%s"}\n' \
        "$ts" "$(ma_json_escape "$2")" "$(ma_json_escape "$3")" "$(ma_json_escape "MacArtifacts/$4")" \
        "$1" "${5:-0}" "$6" "$(ma_json_escape "$7")" >>"$MA_MANIFEST_LINES"
}

# openssl is in the base system; shasum is a Perl script and much slower to
# start once per file.
ma_sha256() {
    openssl dgst -sha256 "$1" 2>/dev/null | awk '{print toupper($NF)}'
}

ma_size() {
    stat -f %z "$1" 2>/dev/null || echo 0
}

# Records an already-written output file (Commands/, Processes/, ...).
ma_register() {
    local rel="$1" label="$2" src="$3"
    local dest="$MA_ROOT/$rel"
    if [[ -s "$dest" ]]; then
        ma_record "Collected" "$label" "$src" "$rel" "$(ma_size "$dest")" "$(ma_sha256 "$dest")" ""
    else
        rm -f "$dest"
        ma_record "Skipped" "$label" "$src" "$rel" 0 "" "No output"
    fi
}

ma_seen() {
    grep -qxF -- "$1" "$MA_SEEN" 2>/dev/null
}

# ma_copy SOURCE LABEL — copies one regular file to Files/<absolute path>.
# A symlink is copied as its target's content, at the target's path
# (/etc/resolv.conf -> /private/var/run/resolv.conf).
ma_copy() {
    local src="$1" label="$2"
    [[ -e "$src" || -L "$src" ]] || return 0
    if [[ -L "$src" ]]; then
        local target
        target=$(readlink "$src")
        [[ "$target" == /* ]] || target="$(cd "$(dirname "$src")" 2>/dev/null && pwd -P)/$target"
        src="$target"
    fi
    [[ -f "$src" ]] || return 0
    ma_seen "$src" && return 0
    printf '%s\n' "$src" >>"$MA_SEEN"
    local rel="Files${src}" size
    size=$(ma_size "$src")
    if (( size > MA_MAX_FILE_BYTES )); then
        ma_record "Skipped" "$label" "$src" "$rel" "$size" "" "Larger than raw_max_file_mb"
        return 0
    fi
    if [[ ! -r "$src" ]]; then
        ma_record "Failed" "$label" "$src" "$rel" "$size" "" "Not readable (run as root, from a terminal with Full Disk Access)"
        return 0
    fi
    mkdir -p "$MA_ROOT/$(dirname "$rel")"
    if cp -p "$src" "$MA_ROOT/$rel" 2>/dev/null; then
        ma_record "Collected" "$label" "$src" "$rel" "$size" "$(ma_sha256 "$MA_ROOT/$rel")" ""
    else
        rm -f "$MA_ROOT/$rel"
        ma_record "Failed" "$label" "$src" "$rel" "$size" "" "Copy failed (TCC-protected: grant the terminal Full Disk Access)"
    fi
}

# A SQLite database with its write-ahead log: the newest rows are often
# still in the -wal file.
ma_copy_db() {
    local db="$1" label="$2"
    [[ -f "$db" ]] || { [[ -e "$db" ]] && ma_record "Failed" "$label" "$db" "Files$db" 0 "" "Not readable (grant the terminal Full Disk Access)"; return 0; }
    ma_copy "$db" "$label"
    ma_copy "$db-wal" "$label (write-ahead log)"
    ma_copy "$db-shm" "$label (shared memory index)"
}

# ma_copy_tree DIR LABEL [MAXDEPTH] — every regular file below DIR.
ma_copy_tree() {
    local dir="$1" label="$2" depth="${3:-6}" f
    [[ -d "$dir" ]] || return 0
    while IFS= read -r -d '' f; do
        ma_copy "$f" "$label"
    done < <(find "$dir" -maxdepth "$depth" \( -type f -o -type l \) -print0 2>/dev/null)
}

# ma_with_timeout SECONDS COMMAND... — macOS has no timeout(1); Perl does.
ma_with_timeout() {
    local secs="$1"; shift
    perl -e 'alarm shift @ARGV; exec @ARGV or exit 127' "$secs" "$@"
}

# ma_cmd NAME LABEL COMMAND... — command output to Commands/NAME.txt.
ma_cmd() {
    local name="$1" label="$2"; shift 2
    [[ "$1" == /* ]] && [[ ! -x "$1" ]] && return 0
    [[ "$1" != /* ]] && ! command -v "$1" >/dev/null 2>&1 && return 0
    mkdir -p "$MA_ROOT/Commands"
    ma_with_timeout 300 "$@" >"$MA_ROOT/Commands/${name}.txt" 2>/dev/null
    ma_register "Commands/${name}.txt" "$label" "$*"
}

ma_config() {
    read_config_array "$1" | head -1
}

# ── Code signatures ──────────────────────────────────────────────────────
# ma_sign_info PATH -> "status<TAB>team_id<TAB>authority<TAB>identifier<TAB>sha256",
# "-" for an empty field (IFS=$'\t' read collapses empty fields).
# status: apple | app_store | developer_id | development | adhoc | unsigned |
# unknown | missing. Signature metadata only (codesign -dv); verifying every
# bundle's resources would take minutes on a large app.
ma_sign_info() {
    local exe="$1" cached
    cached=$(awk -F'\t' -v p="$exe" '$1 == p { $1 = ""; sub(/^\t/, ""); print; exit }' OFS='\t' "$MA_SIGN_CACHE" 2>/dev/null)
    if [[ -n "$cached" ]]; then
        printf '%s\n' "$cached"
        return
    fi
    local status="unknown" team="" auth="" ident="" sha="" out
    if [[ ! -f "$exe" ]]; then
        status="missing"
    else
        out=$(codesign -dv --verbose=2 "$exe" 2>&1)
        ident=$(printf '%s\n' "$out" | sed -n 's/^Identifier=//p' | head -1)
        team=$(printf '%s\n' "$out" | sed -n 's/^TeamIdentifier=//p' | head -1)
        [[ "$team" == "not set" ]] && team=""
        auth=$(printf '%s\n' "$out" | sed -n 's/^Authority=//p' | head -1)
        if [[ "$out" == *"not signed at all"* ]]; then
            status="unsigned"
        elif [[ "$out" == *"Signature=adhoc"* ]]; then
            status="adhoc"
        else
            case "$auth" in
                "Software Signing") status="apple" ;;
                "Apple Mac OS Application Signing") status="app_store" ;;
                "Developer ID Application"*) status="developer_id" ;;
                "Apple Development"*|"Mac Developer"*|"Apple Distribution"*) status="development" ;;
            esac
        fi
        sha=$(ma_sha256 "$exe")
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$exe" "$status" "${team:--}" "${auth:--}" "${ident:--}" "${sha:--}" >>"$MA_SIGN_CACHE"
    printf '%s\t%s\t%s\t%s\t%s\n' "$status" "${team:--}" "${auth:--}" "${ident:--}" "${sha:--}"
}

# The program a launchd plist runs: Program, else ProgramArguments[0].
ma_plist_program() {
    local plist="$1" v
    v=$(plutil -extract Program xml1 -o - "$plist" 2>/dev/null | sed -n 's:.*<string>\(.*\)</string>.*:\1:p' | head -1)
    [[ -z "$v" ]] && v=$(plutil -extract ProgramArguments.0 xml1 -o - "$plist" 2>/dev/null | sed -n 's:.*<string>\(.*\)</string>.*:\1:p' | head -1)
    v="${v//&amp;/&}"; v="${v//&lt;/<}"; v="${v//&gt;/>}"
    printf '%s' "$v"
}

# ── Processes ────────────────────────────────────────────────────────────
ma_processes() {
    mkdir -p "$MA_ROOT/Processes" "$MA_ROOT/Commands"
    local out="$MA_ROOT/Processes/processes.tsv"
    local t_ps t_cmd t_cwd t_del
    t_ps=$(mktemp); t_cmd=$(mktemp); t_cwd=$(mktemp); t_del=$(mktemp)
    # comm is the full executable path on macOS; lstart is five words of
    # local time ("Mon Oct 26 21:00:00 2026").
    ps -axww -o pid=,ppid=,uid=,user=,lstart=,comm= 2>/dev/null >"$t_ps"
    ps -axww -o pid=,command= 2>/dev/null >"$t_cmd"
    lsof -d cwd -Fpn 2>/dev/null >"$t_cwd"
    lsof -nP +L1 2>/dev/null | awk 'NR > 1 && $4 == "txt" { print $2 }' >"$t_del"

    printf 'pid\tppid\tuid\tuser\tstart_utc\texe\texe_deleted\texe_sha256\tsign_status\tteam_id\tsigning_authority\tcwd\tcomm\tcmdline\n' >"$out"
    local pid ppid uid user lstart exe cwd cmdline deleted start epoch info status team auth ident sha
    while IFS=$'\t' read -r pid ppid uid user lstart exe cwd cmdline; do
        [[ -n "$pid" ]] || continue
        deleted=0
        grep -qx "$pid" "$t_del" && deleted=1
        start=""
        epoch=$(date -j -f '%a %b %d %T %Y' "$lstart" +%s 2>/dev/null)
        [[ -n "$epoch" ]] && start=$(date -u -r "$epoch" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        status=""; team=""; auth=""; sha=""
        if [[ "$exe" == /* ]]; then
            info=$(ma_sign_info "$exe")
            IFS=$'\t' read -r status team auth ident sha <<<"$info"
        fi
        [[ "$cwd" == "-" ]] && cwd=""
        [[ "$cmdline" == "-" ]] && cmdline=""
        [[ "$team" == "-" ]] && team=""
        [[ "$auth" == "-" ]] && auth=""
        [[ "$sha" == "-" ]] && sha=""
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$pid" "$ppid" "$uid" "$user" "$start" "$exe" "$deleted" "$sha" "$status" "$team" "$auth" "$cwd" "$(basename "$exe")" "$cmdline" >>"$out"
    done < <(awk '
        FILENAME == ARGV[1] { if ($0 ~ /^p/) p = substr($0, 2); else if ($0 ~ /^n/ && p != "") cwd[p] = substr($0, 2); next }
        FILENAME == ARGV[2] { pid = $1; line = $0; sub(/^ *[0-9]+ /, "", line); gsub(/\t/, " ", line); cmd[pid] = line; next }
        {
            pid = $1; line = $0
            # (no {n} intervals: older macOS awk lacks them)
            sub(/^ *[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +[^ ]+ +/, "", line)
            lstart = $5 " " $6 " " $7 " " $8 " " $9
            c = (pid in cwd && cwd[pid] != "") ? cwd[pid] : "-"
            m = (pid in cmd && cmd[pid] != "") ? cmd[pid] : "-"
            printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", pid, $2, $3, $4, lstart, line, c, m
        }' "$t_cwd" "$t_cmd" "$t_ps")
    rm -f "$t_ps" "$t_cmd" "$t_cwd" "$t_del"
    ma_register "Processes/processes.tsv" "Process table (ps, lsof, codesign)" "ps -ax"
}

# ── Commands (volatile first, then configuration) ────────────────────────
ma_commands() {
    ma_cmd "sockets" "Network sockets (lsof -nP -i)" lsof -nP -i
    ma_cmd "listening" "Listening TCP sockets (lsof)" lsof -nP -iTCP -sTCP:LISTEN
    ma_cmd "who" "Logged-in sessions (who -a)" who -a
    ma_cmd "last" "Login history (last)" last
    ma_cmd "interfaces" "Interfaces (ifconfig -a)" ifconfig -a
    ma_cmd "routes" "Routes (netstat -rn)" netstat -rn
    ma_cmd "arp" "ARP cache (arp -an)" arp -an
    ma_cmd "dns" "DNS configuration (scutil --dns)" scutil --dns
    ma_cmd "proxy" "Proxy settings (scutil --proxy)" scutil --proxy
    ma_cmd "pf-rules" "Packet filter rules (pfctl -sr)" pfctl -sr
    ma_cmd "firewall-apps" "Application firewall rules" /usr/libexec/ApplicationFirewall/socketfilterfw --listapps
    ma_cmd "launchctl-list" "launchd jobs (launchctl list)" launchctl list
    ma_cmd "launchctl-disabled" "Disabled launchd services" launchctl print-disabled system
    ma_cmd "btm" "Login and background items (sfltool dumpbtm)" sfltool dumpbtm
    if command -v kmutil >/dev/null 2>&1; then
        ma_cmd "kexts" "Loaded kernel extensions (kmutil showloaded)" kmutil showloaded
    else
        ma_cmd "kexts" "Loaded kernel extensions (kextstat)" kextstat
    fi
    ma_cmd "system-extensions" "System extensions" systemextensionsctl list
    ma_cmd "profiles" "Configuration profiles" profiles list -all
    ma_cmd "mdm-enrollment" "MDM enrollment status" profiles status -type enrollment
    ma_cmd "packages" "Installed packages (pkgutil --pkgs)" pkgutil --pkgs
    ma_cmd "authorizationdb-login" "Login authorization rule (system.login.console)" security authorizationdb read system.login.console
    ma_cmd "auth-plugins" "Authorization plugins" ls -la /Library/Security/SecurityAgentPlugins
    ma_cmd "users" "Directory Services users (dscacheutil)" dscacheutil -q user
    ma_cmd "admin-group" "Admin group membership" dscl . -read /Groups/admin GroupMembership
    ma_cmd "sw-vers" "macOS version" sw_vers
    ma_cmd "uname" "Kernel (uname -a)" uname -a
    ma_cmd "boottime" "Boot time" sysctl kern.boottime
    ma_cmd "timezone" "Time zone" systemsetup -gettimezone

    # Security posture, one key=value per line.
    mkdir -p "$MA_ROOT/Commands"
    {
        echo "os_version=$(sw_vers -productVersion 2>/dev/null) ($(sw_vers -buildVersion 2>/dev/null)) $(uname -m)"
        echo "sip=$(csrutil status 2>/dev/null | head -1)"
        echo "ssv=$(csrutil authenticated-root status 2>/dev/null | head -1)"
        echo "gatekeeper=$(spctl --status 2>/dev/null | head -1)"
        echo "filevault=$(fdesetup status 2>/dev/null | head -1)"
        echo "firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | head -1)"
        echo "firewall_stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | head -1)"
        echo "remote_login=$(systemsetup -getremotelogin 2>/dev/null | head -1)"
        echo "remote_apple_events=$(systemsetup -getremoteappleevents 2>/dev/null | head -1)"
        # Screen Sharing and Remote Management run as launchd jobs.
        echo "screen_sharing=$(launchctl print system/com.apple.screensharing >/dev/null 2>&1 && echo on || echo off)"
        echo "remote_management=$(pgrep -x ARDAgent >/dev/null 2>&1 && echo on || echo off)"
        echo "file_sharing=$(launchctl print system/com.apple.smbd >/dev/null 2>&1 && echo on || echo off)"
        echo "auto_login_user=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null)"
        echo "guest_account=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)"
        echo "xprotect_version=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString 2>/dev/null)"
        echo "mdm=$(profiles status -type enrollment 2>/dev/null | tr '\n' ' ')"
    } >"$MA_ROOT/Commands/security-state.txt" 2>/dev/null
    ma_register "Commands/security-state.txt" "Security settings (SIP, Gatekeeper, FileVault, firewall, sharing)" "csrutil, spctl, fdesetup, socketfilterfw, systemsetup"

    # Applications with where they came from (identified developer, App
    # Store, unknown) — system_profiler can take a minute or more.
    mkdir -p "$MA_ROOT/Commands"
    ma_with_timeout 240 system_profiler SPApplicationsDataType -json >"$MA_ROOT/Commands/applications.json" 2>/dev/null
    ma_register "Commands/applications.json" "Applications (system_profiler)" "system_profiler SPApplicationsDataType -json"
}

# codesign.tsv: every distinct running executable (signed up by
# ma_processes), then every launch item's program.
ma_codesign() {
    local out="$MA_ROOT/Commands/codesign.tsv"
    mkdir -p "$MA_ROOT/Commands"
    printf 'context\tpath\tsign_status\tteam_id\tsigning_authority\tidentifier\tsha256\tsource\n' >"$out"
    awk -F'\t' '{ for (i = 3; i <= 6; i++) if ($i == "-") $i = ""; printf "process\t%s\t%s\t%s\t%s\t%s\t%s\tps\n", $1, $2, $3, $4, $5, $6 }' "$MA_SIGN_CACHE" >>"$out" 2>/dev/null
    local dir plist prog info status team auth ident sha
    for dir in /Library/LaunchDaemons /Library/LaunchAgents "${USER_HOMES[@]/%//Library/LaunchAgents}"; do
        [[ -d "$dir" ]] || continue
        for plist in "$dir"/*.plist; do
            [[ -f "$plist" ]] || continue
            prog=$(ma_plist_program "$plist")
            [[ "$prog" == /* ]] || continue
            info=$(ma_sign_info "$prog")
            IFS=$'\t' read -r status team auth ident sha <<<"$info"
            [[ "$team" == "-" ]] && team=""; [[ "$auth" == "-" ]] && auth=""; [[ "$ident" == "-" ]] && ident=""; [[ "$sha" == "-" ]] && sha=""
            printf 'launch_item\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$prog" "$status" "$team" "$auth" "$ident" "$sha" "$plist" >>"$out"
        done
    done
    ma_register "Commands/codesign.tsv" "Code signatures (running executables and launch item programs)" "codesign -dv"
}

# ── Files ────────────────────────────────────────────────────────────────
ma_files() {
    local f d home

    # System identity and configuration
    for f in /System/Library/CoreServices/SystemVersion.plist /etc/hosts /etc/resolv.conf /etc/paths \
             /etc/auto_master /etc/ssh/sshd_config /etc/ssh/ssh_config; do
        ma_copy "$f" "System configuration"
    done
    ma_copy_tree /etc/paths.d "System configuration" 1
    ma_copy_tree /etc/resolver "DNS resolver overrides" 1
    ma_copy_tree /etc/ssh/sshd_config.d "SSH server configuration" 1

    # Accounts: Directory Services records (the real account database;
    # /etc/passwd lists system accounts only), sudo, PAM
    ma_copy_tree /var/db/dslocal/nodes/Default/users "Account records (dslocal)" 1
    ma_copy_tree /var/db/dslocal/nodes/Default/groups "Group records (dslocal)" 1
    ma_copy /etc/sudoers "sudoers"
    ma_copy_tree /etc/sudoers.d "sudoers drop-ins" 1
    ma_copy_tree /etc/pam.d "PAM configuration" 1

    # Persistence: launchd, login hooks, legacy startup items, periodic,
    # emond, cron/at, shell startup
    for d in /Library/LaunchDaemons /Library/LaunchAgents; do
        ma_copy_tree "$d" "Launch items" 1
    done
    ma_copy_tree /Library/StartupItems "Legacy startup items" 3
    ma_copy /Library/Preferences/com.apple.loginwindow.plist "Login window settings (hooks, auto-login)"
    ma_copy /Library/Preferences/com.apple.alf.plist "Application firewall settings"
    ma_copy_tree /var/db/com.apple.backgroundtaskmanagement "Background Task Management database" 1
    ma_copy_tree /etc/periodic "periodic scripts" 2
    for f in /etc/daily.local /etc/weekly.local /etc/monthly.local /etc/rc.common /etc/rc.local /etc/launchd.conf /etc/crontab; do
        ma_copy "$f" "Startup configuration"
    done
    ma_copy_tree /etc/emond.d "emond rules" 3
    ma_copy_tree /var/at/tabs "cron" 1
    ma_copy_tree /var/at/jobs "at jobs" 1
    for f in /etc/profile /etc/bashrc /etc/zshenv /etc/zprofile /etc/zshrc /etc/zlogin /etc/zlogout; do
        ma_copy "$f" "Shell startup"
    done

    # Privacy grants, downloads, app usage, installs, XProtect
    ma_copy_db "/Library/Application Support/com.apple.TCC/TCC.db" "TCC privacy database (system)"
    ma_copy_db /var/db/CoreDuet/Knowledge/knowledgeC.db "KnowledgeC (system)"
    ma_copy_db /var/protected/xprotect/XPdb "XProtect behavioural detections"
    ma_copy /Library/Receipts/InstallHistory.plist "Install history"

    # Per-user artifacts, for every home folder
    for home in "${USER_HOMES[@]}"; do
        local user
        user=$(basename "$home")
        for f in .bash_history .zsh_history .sh_history .history .local/share/fish/fish_history \
                 .python_history .mysql_history .psql_history .sqlite_history .node_repl_history .lesshst .viminfo \
                 .bashrc .bash_profile .bash_login .profile .zshrc .zprofile .zlogin .zshenv .config/fish/config.fish \
                 .gitconfig .git-credentials .netrc .pgpass .my.cnf .aws/credentials .aws/config .kube/config .docker/config.json; do
            ma_copy "$home/$f" "User artifacts ($user)"
        done
        # Terminal keeps a history file per window/tab session.
        ma_copy_tree "$home/.zsh_sessions" "Terminal session histories ($user)" 1
        ma_copy_tree "$home/.bash_sessions" "Terminal session histories ($user)" 1
        for f in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2 "$home"/.ssh/known_hosts "$home"/.ssh/config \
                 "$home"/.ssh/rc "$home"/.ssh/*.pub; do
            ma_copy "$f" "SSH ($user)"
        done
        ma_copy_tree "$home/Library/LaunchAgents" "User launch agents ($user)" 1
        ma_copy "$home/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm" "Login items, macOS 12 and earlier ($user)"
        ma_copy_db "$home/Library/Application Support/com.apple.TCC/TCC.db" "TCC privacy database ($user)"
        ma_copy_db "$home/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2" "Quarantine events / downloads ($user)"
        ma_copy_db "$home/Library/Application Support/Knowledge/knowledgeC.db" "KnowledgeC ($user)"
    done

    # Logs, with their rotations
    local pattern
    while IFS= read -r pattern; do
        [[ -n "$pattern" ]] || continue
        for f in $pattern; do
            [[ -f "$f" ]] && ma_copy "$f" "Logs"
        done
    done < <(read_config_array "raw_log_globs")
}

# FSEvents: the file system's own change journal (creations, deletions,
# renames, with paths) — the newest pages, up to raw_fsevents_max_files.
ma_fsevents() {
    # Since macOS 10.15 the writable Data volume (where users, apps and
    # /private live) keeps its own journal; /.fseventsd is the older layout.
    local dir="/System/Volumes/Data/.fseventsd"
    [[ -d "$dir" ]] || dir="/.fseventsd"
    [[ -d "$dir" ]] || return 0
    local max f
    max=$(ma_config "raw_fsevents_max_files"); [[ "$max" =~ ^[0-9]+$ ]] || max=500
    [[ "$max" -gt 0 ]] || return 0
    if ! ls "$dir" >/dev/null 2>&1; then
        ma_record "Failed" "FSEvents" "$dir" "Files$dir" 0 "" "Not readable (run as root, from a terminal with Full Disk Access)"
        return 0
    fi
    while IFS= read -r f; do
        [[ -n "$f" ]] && ma_copy "$dir/$f" "FSEvents"
    done < <(ls -t "$dir" 2>/dev/null | grep -E '^[0-9a-f]{16}$' | head -n "$max")
}

# Targeted unified log exports for Log Analysis, rewritten to RFC 3339
# ("2026-10-26 10:15:21.473552-0500  host proc[1]: msg" becomes
# "2026-10-26T10:15:21.473552-0500 host proc[1]: msg").
ma_unified_log() {
    command -v log >/dev/null 2>&1 || return 0
    local days
    days=$(ma_config "raw_unifiedlog_days"); [[ "$days" =~ ^[0-9]+$ ]] || days=7
    [[ "$days" -gt 0 ]] || return 0
    mkdir -p "$MA_ROOT/Logs"
    ma_log_export "auth" "Authentication: SSH, sudo, su, login, screen sharing (last ${days} days)" "$days" \
        'process == "sshd" OR process == "sshd-session" OR process == "sudo" OR process == "su" OR process == "login" OR process == "screensharingd" OR process == "sysadminctl" OR (process == "loginwindow" AND eventMessage CONTAINS[c] "authenticat")'
    ma_log_export "security" "XProtect, Gatekeeper and TCC decisions (last ${days} days)" "$days" \
        'process BEGINSWITH "XProtect" OR subsystem BEGINSWITH "com.apple.XProtect" OR (process == "syspolicyd" AND (eventMessage CONTAINS[c] "malware" OR eventMessage CONTAINS[c] "blocked" OR eventMessage CONTAINS[c] "notariz")) OR (subsystem == "com.apple.TCC" AND eventMessage CONTAINS[c] "AUTHREQ_RESULT")'
    ma_log_export "installs" "Software installs (last ${days} days)" "$days" \
        'process == "installd" OR process == "system_installd" OR process == "softwareupdated" OR process == "installer"'

    # The complete unified log as a .logarchive, for analysis outside Core.
    local archive
    archive=$(ma_config "raw_logarchive")
    if [[ "$archive" == "true" ]]; then
        log collect --last "${days}d" --output "$MA_ROOT/Logs/system_logs.logarchive" >/dev/null 2>&1
        if [[ -d "$MA_ROOT/Logs/system_logs.logarchive" ]]; then
            ma_record "Collected" "Unified log archive (last ${days} days)" "log collect" "Logs/system_logs.logarchive" \
                "$(du -sk "$MA_ROOT/Logs/system_logs.logarchive" | awk '{print $1 * 1024}')" "" "Directory bundle: open with log show --archive"
        else
            ma_record "Failed" "Unified log archive" "log collect" "Logs/system_logs.logarchive" 0 "" "log collect failed (needs root)"
        fi
    fi
}

ma_log_export() {
    local name="$1" label="$2" days="$3" predicate="$4"
    local rel="Logs/unifiedlog-${name}.log"
    ma_with_timeout 600 log show --style syslog --info --last "${days}d" --predicate "$predicate" 2>/dev/null \
        | sed -E 's/^([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?)([+-][0-9]{4}) +/\1T\2\4 /' \
        | grep -E '^[0-9]{4}-' >"$MA_ROOT/$rel"
    ma_register "$rel" "Unified log: $label" "log show --predicate '$predicate'"
}

# TSK bodyfile: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
ma_bodyfile() {
    local paths=() p max
    while IFS= read -r p; do [[ -n "$p" && -e "$p" ]] && paths+=("$p"); done < <(read_config_array "raw_bodyfile_paths")
    [[ ${#paths[@]} -gt 0 ]] || return 0
    max=$(ma_config "raw_bodyfile_max_entries"); [[ "$max" =~ ^[0-9]+$ ]] || max=200000
    local prune=() d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        [[ ${#prune[@]} -gt 0 ]] && prune+=(-o)
        prune+=(-name "$d")
    done < <(read_config_array "raw_bodyfile_excluded_dir_names")
    mkdir -p "$MA_ROOT/Timeline"
    local out="$MA_ROOT/Timeline/bodyfile.txt"
    if [[ ${#prune[@]} -gt 0 ]]; then
        find "${paths[@]}" -xdev \( -type d \( "${prune[@]}" \) -prune \) -o -print0 2>/dev/null
    else
        find "${paths[@]}" -xdev -print0 2>/dev/null
    fi | xargs -0 stat -f '0|%N|%i|%Sp|%u|%g|%z|%a|%m|%c|%B' 2>/dev/null | head -n "$max" >"$out"
    ma_register "Timeline/bodyfile.txt" "Filesystem timeline (bodyfile with birth times, up to ${max} entries)" "${paths[*]}"
}

ma_write_manifest() {
    mkdir -p "$MA_ROOT/CollectionManifest"
    local out="$MA_ROOT/CollectionManifest/artifact-collection-manifest.json"
    { echo "["; sed '$!s/$/,/' "$MA_MANIFEST_LINES"; echo "]"; } >"$out"
    rm -f "$MA_MANIFEST_LINES"
}

raw_artifacts() {
    cyan "[*] Collecting raw macOS artifacts (-A)"
    MA_ROOT="${Hostname}/artifacts/MacArtifacts"
    mkdir -p "$MA_ROOT"
    MA_MANIFEST_LINES=$(mktemp)
    MA_SEEN=$(mktemp)
    MA_SIGN_CACHE=$(mktemp)
    local max_mb
    max_mb=$(ma_config "raw_max_file_mb"); [[ "$max_mb" =~ ^[0-9]+$ ]] || max_mb=500
    MA_MAX_FILE_BYTES=$(( max_mb * 1024 * 1024 ))

    if [[ $EUID -ne 0 ]]; then
        yellow "[!] Not running as root -- account records, other users' files, TCC and FSEvents will be missing."
        ma_record "Skipped" "Privilege" "" "" 0 "" "Collector not run as root: the collection is partial"
    fi
    # As root, Full Disk Access shows as being able to list the TCC folder.
    if [[ $EUID -eq 0 ]] && ! ls "/Library/Application Support/com.apple.TCC/" >/dev/null 2>&1; then
        yellow "[!] The terminal has no Full Disk Access -- TCC, Safari, Mail and other protected data will be missing."
        yellow "[!] System Settings > Privacy & Security > Full Disk Access, add the terminal, then run again."
        ma_record "Skipped" "Full Disk Access" "" "" 0 "" "Terminal without Full Disk Access: protected data is missing"
    fi

    cyan "    processes, sockets and code signatures"
    ma_processes
    ma_commands
    ma_codesign
    cyan "    files"
    ma_files
    cyan "    FSEvents"
    ma_fsevents
    cyan "    unified log"
    ma_unified_log
    cyan "    filesystem timeline"
    ma_bodyfile
    ma_write_manifest
    rm -f "$MA_SEEN" "$MA_SIGN_CACHE"

    local manifest="$MA_ROOT/CollectionManifest/artifact-collection-manifest.json"
    local collected failed skipped
    collected=$(grep -c '"Status":"Collected"' "$manifest")
    failed=$(grep -c '"Status":"Failed"' "$manifest")
    skipped=$(grep -c '"Status":"Skipped"' "$manifest")
    green "[!] Raw artifacts: ${collected} collected, ${skipped} skipped, ${failed} failed -> ${MA_ROOT}"
    green "[!] Upload the ${Hostname}/artifacts folder to Forensicator Core: Host Artifacts -> Upload -> Collector folder"
}
