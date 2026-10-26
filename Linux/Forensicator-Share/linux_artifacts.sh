#!/bin/bash
#
# Raw Linux artifact acquisition (-A / --artifacts) — sourced by
# Forensicator.sh. The Linux counterpart of the Windows collector's
# -WINARTIFACTS: it copies the artifacts themselves rather than command
# output, so Forensicator Core can parse them (Host Artifacts -> Collector
# folder upload) and an analyst can re-examine the originals.
#
# Output, below <host>/artifacts/LinuxArtifacts/:
#   Files/<absolute path>     raw copies, mirrored at their real path, with
#                             timestamps and modes preserved (cp -p)
#   Commands/<name>.txt       command output that has no file of its own
#                             (packages, mounts, sockets, containers, ...)
#   Processes/processes.tsv   one row per process from /proc, SHA-256 of
#                             its executable
#   Processes/recovered/      executables still running but deleted from
#                             disk, recovered through /proc/<pid>/exe
#   Timeline/bodyfile.txt     TSK bodyfile (MACB times) of config-driven paths
#   Logs/journal.log          systemd journal export for the last N days
#   CollectionManifest/artifact-collection-manifest.json
#                             one record per acquisition (Collected / Skipped
#                             / Failed) with the SHA-256 of every collected
#                             file — same format as the Windows collector's,
#                             verified by Core at upload time
#
# Volatile data first: processes, sockets and sessions are read before any
# file copying or filesystem walk.
#
# Needs root for a complete collection (shadow, other users' homes, every
# /proc/<pid>/exe); a non-root run is recorded as such in the manifest.

LA_ROOT=""
LA_MANIFEST_LINES=""
declare -A LA_SEEN=()
LA_SYMLINKS=""

la_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"; s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

# la_record STATUS LABEL SOURCE DEST_REL SIZE SHA256 NOTE
la_record() {
    local ts
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    printf '{"TimestampUtc":"%s","Label":"%s","SourcePath":"%s","DestinationPath":"%s","Status":"%s","SizeBytes":%s,"SHA256":"%s","Note":"%s"}\n' \
        "$ts" "$(la_json_escape "$2")" "$(la_json_escape "$3")" "$(la_json_escape "LinuxArtifacts/$4")" \
        "$1" "${5:-0}" "$6" "$(la_json_escape "$7")" >>"$LA_MANIFEST_LINES"
}

la_sha256() {
    sha256sum "$1" 2>/dev/null | awk '{print toupper($1)}'
}

# Records an already-written output file (Commands/, Processes/, ...).
la_register() {
    local rel="$1" label="$2" src="$3"
    local dest="$LA_ROOT/$rel"
    if [[ -s "$dest" ]]; then
        la_record "Collected" "$label" "$src" "$rel" "$(stat -c %s "$dest" 2>/dev/null)" "$(la_sha256 "$dest")" ""
    else
        rm -f "$dest"
        la_record "Skipped" "$label" "$src" "$rel" 0 "" "No output"
    fi
}

# la_copy SOURCE LABEL [follow] — copies one regular file to
# Files/<absolute path>. Symlinks are listed in Commands/symlinks.txt (an
# enabled systemd unit *is* a .wants/ symlink); with "follow", a symlink's
# target content is copied too (/etc/os-release -> ../usr/lib/os-release).
la_copy() {
    local src="$1" label="$2" follow="$3"
    local rel="Files${src}"
    if [[ ! -e "$src" && ! -L "$src" ]] || [[ -n "${LA_SEEN[$src]}" ]]; then
        return 0
    fi
    LA_SEEN[$src]=1
    if [[ -L "$src" ]]; then
        printf '%s\t%s\t%s\n' "$src" "$(readlink "$src")" "$(readlink -f "$src" 2>/dev/null)" >>"$LA_SYMLINKS"
        [[ "$follow" == "follow" ]] || return 0
        src=$(readlink -f "$src" 2>/dev/null)
        [[ -n "$src" && -f "$src" && -z "${LA_SEEN[$src]}" ]] || return 0
        LA_SEEN[$src]=1
        rel="Files${src}"
    fi
    if [[ ! -f "$src" ]]; then
        return 0
    fi
    local size
    size=$(stat -c %s "$src" 2>/dev/null || echo 0)
    if (( size > LA_MAX_FILE_BYTES )); then
        la_record "Skipped" "$label" "$src" "$rel" "$size" "" "Larger than raw_max_file_mb"
        return 0
    fi
    if [[ ! -r "$src" ]]; then
        la_record "Failed" "$label" "$src" "$rel" "$size" "" "Not readable (run as root)"
        return 0
    fi
    mkdir -p "$LA_ROOT/$(dirname "$rel")"
    if cp -p "$src" "$LA_ROOT/$rel" 2>/dev/null; then
        la_record "Collected" "$label" "$src" "$rel" "$size" "$(la_sha256 "$LA_ROOT/$rel")" ""
    else
        la_record "Failed" "$label" "$src" "$rel" "$size" "" "Copy failed"
    fi
}

# la_copy_tree DIR LABEL [MAXDEPTH] — every regular file below DIR.
la_copy_tree() {
    local dir="$1" label="$2" depth="${3:-6}" f
    [[ -d "$dir" ]] || return 0
    while IFS= read -r -d '' f; do
        la_copy "$f" "$label"
    done < <(find "$dir" -maxdepth "$depth" \( -type f -o -type l \) -print0 2>/dev/null)
}

# la_cmd NAME LABEL COMMAND... — command output to Commands/NAME.txt.
la_cmd() {
    local name="$1" label="$2"; shift 2
    command -v "$1" >/dev/null 2>&1 || return 0
    mkdir -p "$LA_ROOT/Commands"
    "$@" >"$LA_ROOT/Commands/${name}.txt" 2>/dev/null
    la_register "Commands/${name}.txt" "$label" "$*"
}

la_config() {
    read_config_array "$1" | head -1
}

# ── Processes ────────────────────────────────────────────────────────────
la_processes() {
    mkdir -p "$LA_ROOT/Processes"
    local out="$LA_ROOT/Processes/processes.tsv"
    local btime clk
    btime=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null)
    clk=$(getconf CLK_TCK 2>/dev/null || echo 100)
    declare -A exe_hash=()
    printf 'pid\tppid\tuid\tuser\tstart_utc\texe\texe_deleted\texe_sha256\tcwd\tcomm\tcmdline\n' >"$out"
    local d pid stat rest ppid starttime uid user exe deleted hash cwd comm cmdline start
    for d in /proc/[0-9]*; do
        pid=${d#/proc/}
        stat=$(cat "$d/stat" 2>/dev/null) || continue
        comm=$(cat "$d/comm" 2>/dev/null)
        rest=${stat##*) }                       # fields after "(comm)"
        read -r _state ppid _rest <<<"$rest"
        starttime=$(awk '{print $20}' <<<"$rest")
        uid=$(awk '/^Uid:/ {print $2}' "$d/status" 2>/dev/null)
        user=$(getent passwd "$uid" 2>/dev/null | cut -d: -f1)
        exe=$(readlink "$d/exe" 2>/dev/null)
        deleted=0
        if [[ "$exe" == *" (deleted)" ]]; then deleted=1; exe=${exe% (deleted)}; fi
        hash=""
        if [[ -n "$exe" ]]; then
            if [[ $deleted -eq 0 && -n "${exe_hash[$exe]}" ]]; then
                hash=${exe_hash[$exe]}
            else
                hash=$(sha256sum "$d/exe" 2>/dev/null | awk '{print toupper($1)}')
                [[ $deleted -eq 0 ]] && exe_hash[$exe]=$hash
            fi
        fi
        cwd=$(readlink "$d/cwd" 2>/dev/null)
        cmdline=$(tr '\0' ' ' <"$d/cmdline" 2>/dev/null | tr '\t\n' '  ')
        start=""
        if [[ -n "$btime" && "$starttime" =~ ^[0-9]+$ ]]; then
            start=$(date -u -d "@$(( btime + starttime / clk ))" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$pid" "$ppid" "$uid" "$user" "$start" "$exe" "$deleted" "$hash" "$cwd" "$comm" "${cmdline% }" >>"$out"
        # The only copy of fileless/self-deleting malware is often the one
        # still mapped by the running process.
        if [[ $deleted -eq 1 ]]; then
            mkdir -p "$LA_ROOT/Processes/recovered"
            local rel="Processes/recovered/${pid}_$(sanitize_filename "$comm").bin"
            if cp "$d/exe" "$LA_ROOT/$rel" 2>/dev/null; then
                la_register "$rel" "Deleted executable recovered from /proc" "$d/exe -> $exe"
            else
                la_record "Failed" "Deleted executable recovered from /proc" "$d/exe -> $exe" "$rel" 0 "" "Not readable"
            fi
        fi
    done
    la_register "Processes/processes.tsv" "Process table (/proc)" "/proc/*"
}

# ── Commands (volatile first, then configuration) ────────────────────────
la_commands() {
    # -e adds the owning uid and inode of each socket.
    la_cmd "sockets" "Sockets (ss -tunape)" ss -tunape
    la_cmd "listening" "Listening sockets (ss -tulnp)" ss -tulnp
    la_cmd "unix-sockets" "Unix sockets (ss -xap)" ss -xap
    la_cmd "who" "Logged-in sessions (who -a)" who -a
    la_cmd "interfaces" "Interfaces (ip addr)" ip addr
    la_cmd "routes" "Routes (ip route)" ip route show table all
    la_cmd "neighbours" "ARP/neighbour cache (ip neigh)" ip neigh
    la_cmd "iptables" "iptables rules (iptables-save)" iptables-save
    la_cmd "nftables" "nftables ruleset" nft list ruleset
    la_cmd "mounts" "Mounts (findmnt)" findmnt -l -o TARGET,SOURCE,FSTYPE,OPTIONS
    la_cmd "uname" "Kernel (uname -a)" uname -a
    la_cmd "timedatectl" "Clock, timezone and NTP (timedatectl)" timedatectl
    la_cmd "uptime" "Uptime and boot time" uptime -s
    la_cmd "sysctl" "Kernel parameters (sysctl -a)" sysctl -a
    la_cmd "lsmod" "Loaded kernel modules (lsmod)" lsmod
    la_cmd "apparmor" "AppArmor status" aa-status
    la_cmd "selinux" "SELinux status" sestatus
    la_cmd "services" "systemd services" systemctl list-units --type=service --all --no-pager --plain
    la_cmd "timers" "systemd timers" systemctl list-timers --all --no-pager
    la_cmd "at-queue" "at job queue (atq)" atq
    la_cmd "bpf-programs" "Loaded eBPF programs (bpftool)" bpftool prog show
    if command -v dpkg-query >/dev/null 2>&1; then
        la_cmd "packages" "Installed packages (dpkg)" dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Status}\n'
    elif command -v rpm >/dev/null 2>&1; then
        la_cmd "packages" "Installed packages (rpm)" rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME:date}\n'
    fi
    if command -v docker >/dev/null 2>&1; then
        la_cmd "docker-ps" "Docker containers" docker ps -a --no-trunc --format '{{json .}}'
        local ids
        ids=$(docker ps -aq 2>/dev/null)
        if [[ -n "$ids" ]]; then
            # shellcheck disable=SC2086
            la_cmd "docker-inspect" "Docker container configuration (mounts, privileges, entrypoint)" docker inspect $ids
        fi
    fi
    # Immutable/append-only attributes on persistence locations (chattr +i
    # keeps planted persistence from being removed).
    if command -v lsattr >/dev/null 2>&1; then
        mkdir -p "$LA_ROOT/Commands"
        lsattr -R -a /etc/cron* /etc/systemd/system /etc/ssh /etc/ld.so.preload /etc/passwd /etc/shadow /etc/sudoers /etc/sudoers.d \
            /root/.ssh /home/*/.ssh /usr/local/bin /usr/local/sbin 2>/dev/null \
            | awk '$1 ~ /[ia]/' >"$LA_ROOT/Commands/immutable.txt"
        la_register "Commands/immutable.txt" "Immutable / append-only files (lsattr)" "lsattr -R"
    fi
    # Kernel identity for Volatility 3 symbol tables (pair with -r).
    mkdir -p "$LA_ROOT/Commands"
    { cat /proc/version; echo "release=$(uname -r)"; echo "machine=$(uname -m)"; } >"$LA_ROOT/Commands/kernel-banner.txt" 2>/dev/null
    la_register "Commands/kernel-banner.txt" "Kernel banner (for memory analysis symbols)" "/proc/version"
}

# ── Files ────────────────────────────────────────────────────────────────
la_files() {
    local f home user

    # System identity and configuration
    for f in /etc/os-release /etc/hostname /etc/hosts /etc/resolv.conf /etc/fstab /etc/timezone \
             /etc/environment /etc/login.defs /etc/nsswitch.conf /etc/hosts.allow /etc/hosts.deny \
             /proc/cmdline /proc/modules /proc/mounts /proc/sys/kernel/tainted /proc/net/tcp /proc/net/tcp6 \
             /proc/net/udp /proc/net/udp6; do
        if [[ "$f" == /proc/* ]]; then
            # /proc files report size 0; copy through cat instead of cp -p.
            [[ -r "$f" ]] || continue
            local rel="Files${f}"
            mkdir -p "$LA_ROOT/$(dirname "$rel")"
            cat "$f" >"$LA_ROOT/$rel" 2>/dev/null
            la_register "$rel" "Kernel state" "$f"
        else
            la_copy "$f" "System configuration" follow
        fi
    done
    la_copy "/boot/System.map-$(uname -r)" "Kernel symbol map (for memory analysis)"

    # Accounts, privilege and authentication
    for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/sudoers; do la_copy "$f" "Accounts" follow; done
    la_copy_tree /etc/sudoers.d "Sudoers drop-ins" 1
    la_copy_tree /etc/pam.d "PAM configuration" 1
    la_copy_tree /etc/security "PAM/security configuration" 2

    # Login records
    for f in /var/log/wtmp /var/log/wtmp.1 /var/log/btmp /var/log/btmp.1 /var/log/lastlog /run/utmp \
             /var/lib/wtmpdb/wtmp.db /var/lib/lastlog/lastlog2.db; do
        la_copy "$f" "Login records"
    done

    # SSH server
    la_copy /etc/ssh/sshd_config "SSH server configuration"
    la_copy_tree /etc/ssh/sshd_config.d "SSH server configuration" 1
    la_copy /etc/ssh/ssh_config "SSH client configuration"

    # Scheduled tasks
    la_copy /etc/crontab "Cron"
    la_copy /etc/anacrontab "Cron"
    local d
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly \
             /var/spool/cron /var/spool/at /var/spool/anacron; do
        la_copy_tree "$d" "Cron / at" 2
    done

    # systemd (units, drop-ins, generators) — locally added locations only;
    # package-shipped units under /usr/lib are covered by package integrity.
    for d in /etc/systemd/system /etc/systemd/user /usr/local/lib/systemd /run/systemd/system \
             /etc/systemd/system-generators /usr/local/lib/systemd/system-generators; do
        la_copy_tree "$d" "systemd" 4
    done
    la_copy_tree /etc/init.d "SysV init scripts" 1
    la_copy /etc/rc.local "rc.local"

    # Shell startup, loader, kernel modules, udev, autostart, hooks
    for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/zshrc /etc/zsh/zshrc /etc/zsh/zprofile \
             /etc/ld.so.preload /etc/ld.so.conf /etc/modules; do
        la_copy "$f" "Startup / loader configuration" follow
    done
    for d in /etc/profile.d /etc/ld.so.conf.d /etc/modules-load.d /etc/modprobe.d /etc/udev/rules.d \
             /etc/xdg/autostart /etc/update-motd.d /etc/apt/apt.conf.d /etc/yum/pluginconf.d \
             /etc/logrotate.d /etc/polkit-1/rules.d /etc/sysctl.d; do
        la_copy_tree "$d" "Persistence locations" 2
    done
    la_copy /etc/sysctl.conf "Kernel parameters"

    # Per-user artifacts
    while IFS=: read -r user _ uid _ _ home _; do
        [[ -n "$home" && -d "$home" && "$home" != "/" ]] || continue
        [[ "$home" == /proc* || "$home" == /dev* || "$home" == /sys* || "$home" == /run* ]] && continue
        for f in .bash_history .zsh_history .sh_history .ksh_history .history .local/share/fish/fish_history \
                 .python_history .mysql_history .psql_history .sqlite_history .node_repl_history .rediscli_history \
                 .lesshst .viminfo .wget-hsts .bashrc .bash_profile .bash_login .bash_logout .profile .zshrc \
                 .zprofile .zlogin .zshenv .config/fish/config.fish .selected_editor .gitconfig .git-credentials \
                 .netrc .pgpass .my.cnf .aws/credentials .aws/config .kube/config .docker/config.json; do
            la_copy "$home/$f" "User artifacts ($user)" follow
        done
        for f in "$home"/.ssh/authorized_keys "$home"/.ssh/authorized_keys2 "$home"/.ssh/known_hosts \
                 "$home"/.ssh/config "$home"/.ssh/*.pub; do
            la_copy "$f" "SSH ($user)"
        done
        la_copy_tree "$home/.config/autostart" "User autostart ($user)" 1
        la_copy_tree "$home/.config/systemd/user" "User systemd units ($user)" 3
    done < <(getent passwd 2>/dev/null || cat /etc/passwd)

    # Logs, with their rotations (.1, .2.gz, ...)
    local pattern
    while IFS= read -r pattern; do
        [[ -n "$pattern" ]] || continue
        for f in $pattern; do
            [[ -f "$f" ]] && la_copy "$f" "Logs"
        done
    done < <(read_config_array "raw_log_globs")
}

la_journal() {
    command -v journalctl >/dev/null 2>&1 || return 0
    local days
    days=$(la_config "raw_journal_days"); [[ "$days" =~ ^[0-9]+$ ]] || days=30
    mkdir -p "$LA_ROOT/Logs"
    journalctl --no-pager -o short-iso --since "-${days} days" >"$LA_ROOT/Logs/journal.log" 2>/dev/null
    la_register "Logs/journal.log" "systemd journal (last ${days} days, short-iso)" "journalctl"
}

# TSK bodyfile: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
la_bodyfile() {
    local paths=() p max
    while IFS= read -r p; do [[ -n "$p" && -e "$p" ]] && paths+=("$p"); done < <(read_config_array "raw_bodyfile_paths")
    [[ ${#paths[@]} -gt 0 ]] || return 0
    max=$(la_config "raw_bodyfile_max_entries"); [[ "$max" =~ ^[0-9]+$ ]] || max=200000
    local prune=() d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        [[ ${#prune[@]} -gt 0 ]] && prune+=(-o)
        prune+=(-name "$d")
    done < <(read_config_array "new_files_excluded_dir_names")
    mkdir -p "$LA_ROOT/Timeline"
    local out="$LA_ROOT/Timeline/bodyfile.txt"
    if [[ ${#prune[@]} -gt 0 ]]; then
        find "${paths[@]}" -xdev \( -type d \( "${prune[@]}" \) -prune \) -o -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n' 2>/dev/null
    else
        find "${paths[@]}" -xdev -printf '0|%p|%i|%M|%U|%G|%s|%A@|%T@|%C@|0\n' 2>/dev/null
    fi | sed -E 's/\|([0-9]+)\.[0-9]+/|\1/g' | head -n "$max" >"$out"
    la_register "Timeline/bodyfile.txt" "Filesystem timeline (bodyfile, up to ${max} entries)" "${paths[*]}"
}

la_write_manifest() {
    mkdir -p "$LA_ROOT/CollectionManifest"
    local out="$LA_ROOT/CollectionManifest/artifact-collection-manifest.json"
    { echo "["; sed '$!s/$/,/' "$LA_MANIFEST_LINES"; echo "]"; } >"$out"
    rm -f "$LA_MANIFEST_LINES"
}

raw_artifacts() {
    cyan "[*] Collecting raw Linux artifacts (-A)"
    LA_ROOT="$(hostname)/artifacts/LinuxArtifacts"
    mkdir -p "$LA_ROOT"
    LA_MANIFEST_LINES=$(mktemp)
    LA_SYMLINKS=$(mktemp)
    local max_mb
    max_mb=$(la_config "raw_max_file_mb"); [[ "$max_mb" =~ ^[0-9]+$ ]] || max_mb=500
    LA_MAX_FILE_BYTES=$(( max_mb * 1024 * 1024 ))

    if [[ $EUID -ne 0 ]]; then
        yellow "[!] Not running as root -- shadow, other users' files and some processes will be missing."
        la_record "Skipped" "Privilege" "" "" 0 "" "Collector not run as root: the collection is partial"
    fi

    cyan "    processes and sockets"
    la_processes
    la_commands
    cyan "    files"
    la_files
    la_journal
    cyan "    filesystem timeline"
    la_bodyfile
    mkdir -p "$LA_ROOT/Commands"
    { printf 'link\ttarget\tresolved\n'; cat "$LA_SYMLINKS"; } >"$LA_ROOT/Commands/symlinks.txt"
    rm -f "$LA_SYMLINKS"
    la_register "Commands/symlinks.txt" "Symlinks in collected locations (enabled systemd units, ...)" "collected locations"
    la_write_manifest

    local collected failed skipped
    collected=$(grep -c '"Status":"Collected"' "$LA_ROOT/CollectionManifest/artifact-collection-manifest.json")
    failed=$(grep -c '"Status":"Failed"' "$LA_ROOT/CollectionManifest/artifact-collection-manifest.json")
    skipped=$(grep -c '"Status":"Skipped"' "$LA_ROOT/CollectionManifest/artifact-collection-manifest.json")
    green "[!] Raw artifacts: ${collected} collected, ${skipped} skipped, ${failed} failed -> ${LA_ROOT}"
    green "[!] Upload the $(hostname)/artifacts folder to Forensicator Core: Host Artifacts -> Upload -> Collector folder"
}
