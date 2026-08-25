#Requires -Version 5.1
<#
Forensicator Artifact Knowledge Base
=====================================
Type-level DFIR content for every finding type produced by Forensicator.ps1,
consumed by New-ForensicatorFinding (ForensicatorFindingBuilder.ps1) to build
the full enriched finding object. Keyed by the artifact key used in each
finding_id (e.g. "dns-cache" for "dns-cache-001").

This file is DATA, not control flow: authored once, referenced by the builder.
Severity is derived from base_risk_score via Get-ForensicatorSeverityForScore,
not hardcoded per entry, so recalibrating a finding type's severity means
changing one number here rather than hunting through Forensicator.ps1.

CALIBRATING base_risk_score: most call sites in Forensicator.ps1 pass this
value through unchanged (no per-instance ScoreOverride) -- so it answers
"how suspicious is the bare fact that this finding has ANY evidence at all,
on a typical clean host?", not "how bad would this be if misused." For a
finding whose evidence is a blanket inventory/status listing (every host has
services, scheduled tasks, local admins, browser history, running
processes, etc. -- the collection is never empty), a high score here means
the overall case score is inflated on every single run regardless of actual
compromise. Score high (70+) only for finding types whose evidence is
inherently rare -- either genuinely filtered to a suspicious condition at
the collection site (a webshell pattern match, DCSync rights, a dangerous
SQL config actually enabled) or a real, uncommon event (credential vault
backup/restore). Score low (5-25) for routine inventory/config-listing
finding types, and moderate (30-55) for real but operationally-routine
events (account lifecycle changes, password resets, RDP logons) -- these
matter for investigation context, but shouldn't alone push a clean host's
overall score into High/Critical territory. See Get-ForensicatorCaseSummary
in ForensicatorFindingBuilder.ps1 for how base_risk_score drives the
overall case score.
#>

$Script:ArtifactKnowledgeBase = @{
    "dns-cache" = @{
        finding_type = 'DNS Cache Entries'
        category = 'Network Activity'
        subcategory = 'Network Recon'
        title = 'DNS Cache Entries'
        description = 'Resolved DNS names currently cached by the Windows DNS client resolver on the endpoint.'
        why_this_matters = 'DNS lookups precede almost every network action a process takes, so the cache is a low-cost window into domains the host recently contacted, including ones no longer reflected in active connections.'
        expected_normal_behaviour = 'A cache dominated by OS telemetry, update, and vendor domains, plus whatever internal/line-of-business domains the user''s normal workflow touches.'
        investigator_notes = 'Cache entries expire (TTL-bound) so this is a recent-activity snapshot, not a full history; correlate suspicious names against browser history and process network activity for corroboration.'
        what_is_this = 'A local, in-memory table the Windows DNS Client service (Dnscache) keeps of recently resolved hostname-to-IP mappings.'
        why_it_exists = 'Caching avoids re-querying a DNS server for every connection, speeding up repeat lookups and reducing DNS traffic.'
        normal_behaviour = 'Entries for OS/update/telemetry domains, the browsers and apps in daily use, and internal corporate domains.'
        suspicious_behaviour = 'Newly-registered or algorithmically-generated-looking domains (DGA patterns), domains associated with known C2 frameworks, or a burst of NXDOMAIN entries suggesting a beaconing implant probing for its C2.'
        common_attack_usage = 'Malware resolves C2 and staging domains before connecting; DGA-based malware families generate many pseudo-random domain lookups as they search for a live C2 endpoint.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Cross-reference cached domains against threat intel feeds and DGA-detection heuristics (entropy, n-gram scoring).'
        mitre_data_sources = @('Command Execution', 'DNS Client Cache')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('DNS cache may reveal recently contacted domains, useful for reconstructing pre-connection recon.')
        detection_logic = 'Static inventory collection — every entry present in the resolver cache at collection time is captured, no filtering applied.'
        detection_threshold = 'n/a — informational inventory, not a threshold-based detection.'
        false_positive_notes = 'The vast majority of entries are benign OS/application telemetry; suspicious classification requires correlation with threat intel, not the cache alone.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Cross-reference cached domains against current threat intelligence feeds.'; reason = 'Identifies known-malicious domains contacted recently by the host.' },
            @{ priority = 'Low'; action = 'Correlate with browser history and TCP connection findings.'; reason = 'Confirms whether a suspicious domain resolution was followed by an actual connection.' }
        )
        investigation_questions = @('Are any cached domains newly registered, DGA-like, or on a threat intel blocklist?', 'Do any suspicious cached domains correlate with an active or recent TCP connection?')
        findingtags = @('network-recon', 'live-response')
    }
    "net-adapter" = @{
        finding_type = 'Network Adapter Inventory'
        category = 'Network Activity'
        subcategory = 'Network Configuration'
        title = 'Network Adapter Inventory'
        description = 'Enumeration of all physical and virtual network adapters present on the endpoint, including status and MAC addresses.'
        why_this_matters = 'Unexpected adapters (virtual, tunnel, or Wi-Fi adapters that shouldn''t be present on a wired workstation) can indicate covert network paths, VPN/tunnel-based exfiltration, or a hypervisor/VM used to hide attacker tooling.'
        expected_normal_behaviour = 'The adapters the asset was provisioned with (typically one wired and/or one wireless NIC), all in an expected up/down state for the device''s normal use.'
        investigator_notes = 'Pay attention to adapter descriptions that suggest tunneling software (TAP-Windows, WireGuard, OpenVPN) or unexpected virtualization adapters on an endpoint not meant to run VMs.'
        what_is_this = 'A list of every network interface Windows has a driver instance for, reported by Get-NetAdapter.'
        why_it_exists = 'Windows needs an adapter abstraction to manage physical NICs, Wi-Fi radios, Bluetooth PAN, and virtual/tunnel adapters uniformly.'
        normal_behaviour = 'A small, stable set of adapters matching the device''s hardware and any sanctioned VPN client.'
        suspicious_behaviour = 'A new adapter appearing that wasn''t present in a prior baseline, especially tunnel/VPN-type adapters not matching approved software, or a disabled adapter that was previously active.'
        common_attack_usage = 'Attackers or insiders install unauthorized VPN/tunnel software to create an exfiltration or C2 channel that bypasses network monitoring bound to the primary adapter.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Diff the adapter list against an asset baseline; flag adapter descriptions matching known tunneling software.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Network adapter details help identify unauthorized or suspicious network interfaces such as rogue VPN/tunnel adapters.')
        detection_logic = 'Static inventory of all adapters returned by Get-NetAdapter at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Sanctioned corporate VPN clients and virtualization software both legitimately add adapters; validate against the asset''s approved software list.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Diff adapter list against the asset''s approved hardware/software baseline.'; reason = 'Surfaces unauthorized tunnel or virtualization adapters.' }
        )
        investigation_questions = @('Is every listed adapter accounted for by known hardware or approved software?', 'Does any adapter description match known VPN/tunneling tooling not on the approved list?')
        findingtags = @('network-recon', 'live-response')
    }
    "ip-config" = @{
        finding_type = 'IP Configuration'
        category = 'Network Activity'
        subcategory = 'Network Configuration'
        title = 'IP Configuration'
        description = 'Full IP configuration for every adapter: IP addresses, subnet masks, default gateways, and DHCP status.'
        why_this_matters = 'Reveals which network segments the host can reach and whether addressing has been tampered with (static IP set on a normally-DHCP host, rogue gateway, etc.), all of which shape lateral-movement and exfiltration options.'
        expected_normal_behaviour = 'DHCP-assigned addressing (unless the asset is a server with intentional static config) with a gateway matching the site''s known infrastructure.'
        investigator_notes = 'A rogue default gateway or DNS server pointed at an unexpected IP is a strong indicator of a man-in-the-middle or DNS-hijack condition.'
        what_is_this = 'The output of Get-NetIPConfiguration, combining adapter, IP address, and DNS/gateway configuration into one view.'
        why_it_exists = 'Windows networking splits configuration across several APIs; this cmdlet aggregates them for a human-readable picture of how the host is addressed.'
        normal_behaviour = 'DHCP-leased addresses on the expected VLAN/subnet with the site''s standard gateway and internal DNS servers.'
        suspicious_behaviour = 'A statically-assigned IP on a host that should be DHCP, a gateway or DNS server IP outside the known infrastructure range, or an unexpected secondary IP bound to an adapter.'
        common_attack_usage = 'An attacker with local admin may set a static IP/gateway/DNS to redirect traffic through an attacker-controlled host for interception or DNS-based C2.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Compare gateway/DNS server IPs against the known-good infrastructure list for the site/VLAN.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('IP configuration details reveal network ranges, gateways, and DHCP status useful for network mapping and detecting tampering.')
        detection_logic = 'Static snapshot of IP configuration for every adapter at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Servers and network appliances legitimately use static addressing; validate against the asset''s documented role.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Validate gateway and DNS server IPs against known-good site infrastructure.'; reason = 'Detects traffic-redirection tampering.' }
        )
        investigation_questions = @('Does the addressing mode (static vs DHCP) match the asset''s expected role?', 'Do the gateway and DNS server IPs match known-good infrastructure for this site?')
        findingtags = @('network-recon', 'live-response')
    }
    "net-ip-address" = @{
        finding_type = 'Net IP Address Information'
        category = 'Network Activity'
        subcategory = 'Network Configuration'
        title = 'Net IP Address Information'
        description = 'All active IPv4/IPv6 addresses currently bound to the host''s adapters.'
        why_this_matters = 'Shows every network segment the host is directly connected to, which bounds what an attacker pivoting from this host could reach.'
        expected_normal_behaviour = 'One or two addresses corresponding to the host''s normal wired/wireless connectivity, on expected subnets.'
        investigator_notes = 'An address on an unexpected subnet may indicate the host is dual-homed into a segment it shouldn''t be able to reach (e.g., a management VLAN).'
        what_is_this = 'The set of active IPv4 addresses reported by Get-NetIPAddress, filtered to the Preferred address state.'
        why_it_exists = 'A host can hold multiple addresses across adapters and address families simultaneously; this enumerates all of them.'
        normal_behaviour = 'Addresses on the site''s standard user/workstation subnets only.'
        suspicious_behaviour = 'An address on a segment the host has no business being connected to, or an unexpectedly large number of bound addresses.'
        common_attack_usage = 'Attackers who compromise a dual-homed host (e.g., jump box) use its second network segment as a pivot point for lateral movement into otherwise-isolated networks.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag addresses on subnets outside the host''s documented network zone.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Active IPv4 addresses show which network segments the host is connected to, bounding potential pivot paths.')
        detection_logic = 'Static snapshot of all preferred-state IPv4 addresses at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Multi-homed servers and hosts with legitimate VPN connections will show multiple subnets by design.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm each bound subnet matches the host''s documented network zone.'; reason = 'Flags unexpected pivot paths into other segments.' }
        )
        investigation_questions = @('Is the host bound to any subnet outside its documented network zone?')
        findingtags = @('network-recon', 'live-response')
    }
    "net-connect-profile" = @{
        finding_type = 'Network Connection Profiles'
        category = 'Network Activity'
        subcategory = 'Network Configuration'
        title = 'Network Connection Profiles'
        description = 'The Windows network category (Public/Private/Domain) assigned to each connected network.'
        why_this_matters = 'The category controls Windows Firewall default policy — a network misclassified as Private/Domain when it should be Public leaves file sharing and other services exposed.'
        expected_normal_behaviour = 'Domain category on the corporate LAN, Private/Public appropriately assigned for any other network the device connects to (e.g., home Wi-Fi, public hotspot).'
        investigator_notes = 'A misclassified network category is often a configuration drift issue, but on a host with recent unexplained network changes it should be verified as unintentional.'
        what_is_this = 'Windows'' per-network trust classification, retrieved via Get-NetConnectionProfile, that firewall and sharing rules key off of.'
        why_it_exists = 'Different networks warrant different default exposure — a laptop should not have SMB/file sharing open on a coffee-shop Wi-Fi the way it might on the corporate LAN.'
        normal_behaviour = 'Domain/Private category on trusted networks, Public on untrusted/open ones.'
        suspicious_behaviour = 'An untrusted network (e.g., a rogue access point) classified as Private/Domain, unlocking firewall exceptions that expose SMB or other services.'
        common_attack_usage = 'An attacker running a rogue Wi-Fi access point benefits if a victim''s device auto-classifies it as trusted, since that unlocks broader firewall exceptions for lateral discovery/exploitation.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any network profile category that doesn''t match the network''s expected trust level (e.g., an SSID not on the known-trusted list marked Private).'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 15
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Network category reveals trust level assigned to connected networks; misconfiguration may expose services to untrusted networks.')
        detection_logic = 'Static snapshot of each connected network profile''s category at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Legitimately trusted secondary networks (home office VPN endpoints) may correctly show as Private.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Verify each network''s category matches its actual trust level.'; reason = 'Prevents firewall exceptions being exposed to untrusted networks.' }
        )
        investigation_questions = @('Does any untrusted or unrecognized network show a Private/Domain trust category?')
        findingtags = @('network-recon', 'live-response')
    }
    "net-interface" = @{
        finding_type = 'Network Interfaces'
        category = 'Network Activity'
        subcategory = 'Network Configuration'
        title = 'Network Interfaces'
        description = 'Low-level interface status, link speed, and media type for each network interface on the host.'
        why_this_matters = 'Unexpected interface state changes (a normally-down interface now up, or an unusually low link speed) can indicate a rogue device plugged in or an attacker-attached network tap.'
        expected_normal_behaviour = 'Interfaces matching the host''s known hardware, in their expected operational state and link speed.'
        investigator_notes = 'Correlate with the adapter inventory finding — this view focuses on link-layer state rather than adapter identity.'
        what_is_this = 'Interface-level status detail (operational status, link speed, media type) from Get-NetAdapter/Get-NetIPInterface.'
        why_it_exists = 'Provides the physical/link-layer detail that sits underneath the higher-level IP configuration view.'
        normal_behaviour = 'Interfaces in the expected up/down state matching normal device usage patterns.'
        suspicious_behaviour = 'An interface that shouldn''t be active suddenly reporting Up, or a link speed inconsistent with the expected hardware (e.g., a Gigabit NIC suddenly negotiating at 10 Mbps, consistent with a cheap inline tap).'
        common_attack_usage = 'Physical implants (network taps, rogue USB-Ethernet adapters) attached inline to intercept traffic often introduce a detectable link speed or interface state anomaly.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Baseline expected interface states per asset and flag deviations.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Interface status and link speed help detect unusual or rogue network devices attached to the host.')
        detection_logic = 'Static snapshot of interface operational status and link speed at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Docking stations and USB-Ethernet adapters legitimately alter link speed/media type.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Baseline expected interface states per asset and review deviations.'; reason = 'Surfaces physically-attached rogue network devices.' }
        )
        investigation_questions = @('Does any interface show a state or link speed inconsistent with the host''s known hardware?')
        findingtags = @('network-recon', 'live-response')
    }
    "net-neighbor" = @{
        finding_type = 'Net Neighbour (ARP Cache)'
        category = 'Network Activity'
        subcategory = 'Network Recon'
        title = 'Net Neighbour (ARP Cache)'
        description = 'The host''s ARP cache, mapping recently-contacted local-segment IP addresses to MAC addresses.'
        why_this_matters = 'Shows exactly which hosts on the local segment this machine has communicated with at layer 2 — a direct map of local lateral-movement/discovery activity.'
        expected_normal_behaviour = 'Entries for the default gateway and a handful of frequently-used local resources (printers, file servers).'
        investigator_notes = 'A large number of ARP entries can indicate the host ran a local network scan (e.g., via a tool like nmap or an internal reconnaissance script).'
        what_is_this = 'The IPv4-to-MAC mapping table maintained by the OS for local-segment communication, from Get-NetNeighbor.'
        why_it_exists = 'Ethernet requires MAC addresses for delivery; ARP resolves IP-to-MAC on the local segment and the OS caches results to avoid re-resolving on every packet.'
        normal_behaviour = 'A small, stable set of entries for the gateway and routinely-used local peers.'
        suspicious_behaviour = 'An unusually large number of distinct MAC/IP pairs suggesting a sweep, or duplicate MAC addresses across different IPs suggesting ARP spoofing/poisoning.'
        common_attack_usage = 'Internal reconnaissance tools sweep the local subnet generating many ARP entries; ARP poisoning/spoofing attacks manifest as one MAC address claiming multiple IPs (including the gateway''s).'
        mitre_technique_id = 'T1049'
        mitre_technique = 'System Network Connections Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag ARP cache sizes far above baseline for the host''s normal role, and any MAC address mapped to more than one IP.'
        mitre_data_sources = @('Network Traffic', 'Command Execution')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('ARP cache reveals recently contacted local hosts; anomalous entries or an unusually large cache may indicate a local subnet sweep or ARP poisoning.')
        detection_logic = 'Static snapshot of the ARP cache at collection time; no active sweep is performed by the collector itself.'
        detection_threshold = 'A cache size significantly larger than the host''s normal baseline warrants review.'
        false_positive_notes = 'Hosts that legitimately interact with many local peers (file servers, jump boxes) will have larger baseline ARP caches.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Compare ARP cache size against the host''s historical baseline.'; reason = 'Flags likely local subnet reconnaissance.' },
            @{ priority = 'Medium'; action = 'Check for any MAC address resolving to multiple IPs, especially the gateway.'; reason = 'Confirms or rules out ARP spoofing/poisoning.' }
        )
        investigation_questions = @('Is the ARP cache significantly larger than this host''s normal baseline?', 'Does any MAC address map to more than one IP address, particularly the gateway''s?')
        findingtags = @('network-recon', 'lateral-movement', 'live-response')
    }
    "tcp-connections" = @{
        finding_type = 'TCP Connections'
        category = 'Network Activity'
        subcategory = 'Active Network Connections'
        title = 'TCP Connections'
        description = 'All active outbound and inbound TCP connections on the endpoint at collection time, with owning process.'
        why_this_matters = 'Active connections are the most direct evidence of ongoing C2 communication, lateral movement, or data exfiltration in progress.'
        expected_normal_behaviour = 'Connections to expected corporate/cloud services, update endpoints, and normal user applications, each owned by a recognizable process.'
        investigator_notes = 'Prioritize connections to non-standard ports, unfamiliar remote IPs/ASNs, or connections owned by processes running from unusual paths (temp folders, user profile directories).'
        what_is_this = 'A live snapshot of the TCP connection table from Get-NetTCPConnection, joined to the owning process.'
        why_it_exists = 'Reflects the actual network activity of running processes at the moment of collection, complementing static listening-port and log-based network findings.'
        normal_behaviour = 'A stable, explainable set of connections to known corporate and cloud infrastructure.'
        suspicious_behaviour = 'A connection to a rare or newly-seen external IP on an unusual port, especially one owned by a process with no legitimate reason to make network connections (e.g., notepad.exe, rundll32.exe).'
        common_attack_usage = 'Malware C2 beacons, reverse shells, and data-exfiltration channels all manifest as an active outbound TCP connection from an unexpected process to an unexpected remote host.'
        mitre_technique_id = 'T1049'
        mitre_technique = 'System Network Connections Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Cross-reference remote IPs against threat intel; flag connections owned by processes running from non-standard install paths.'
        mitre_data_sources = @('Network Traffic', 'Process', 'Command Execution')
        base_risk_score = 8
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Active TCP connections may reveal C2 communication, lateral movement, or data exfiltration currently in progress.')
        detection_logic = 'Point-in-time snapshot of all TCP connections and their owning process at collection time.'
        detection_threshold = 'n/a — every active connection is captured; suspicion is evaluated per-connection during triage.'
        false_positive_notes = 'Cloud-native applications and browsers legitimately hold many simultaneous connections to CDN/cloud IP ranges that can look unfamiliar without enrichment.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Enrich remote IPs with threat intelligence and ASN/geolocation data.'; reason = 'Separates benign cloud traffic from likely-malicious connections.' },
            @{ priority = 'Medium'; action = 'Validate the owning process''s binary path and signature for any connection to an unfamiliar remote host.'; reason = 'Confirms whether the connection originates from legitimate or attacker-controlled software.' }
        )
        investigation_questions = @('Which connections go to remote IPs not seen in this host''s historical baseline?', 'Does the owning process for any suspicious connection run from an unsigned binary or non-standard path?')
        findingtags = @('lateral-movement', 'data-exfiltration', 'malware', 'live-response')
    }
    "listening-ports" = @{
        finding_type = 'Listening Ports (TCP + UDP)'
        category = 'Network Activity'
        subcategory = 'Active Network Connections'
        title = 'Listening Ports (TCP + UDP)'
        description = 'All TCP and UDP ports the host is currently listening on, with the owning process for each.'
        why_this_matters = 'A listening port is an exposed attack surface — attacker-planted backdoors, reverse-shell listeners, and unauthorized remote-access tools all show up here.'
        expected_normal_behaviour = 'A small, well-known set of listeners belonging to the OS and sanctioned management/remote-access software (e.g., RDP, WinRM if enabled by policy).'
        investigator_notes = 'Any listener owned by a process outside the expected system/administrative set, or on an unusual high port, warrants direct investigation of that process.'
        what_is_this = 'The set of TCP/UDP ports in a listening state, from Get-NetTCPConnection (Listen state) and Get-NetUDPEndpoint, joined to owning process.'
        why_it_exists = 'Services that accept inbound connections must bind and listen on a port; enumerating listeners shows the host''s full inbound attack surface.'
        normal_behaviour = 'Listeners matching documented, sanctioned services only.'
        suspicious_behaviour = 'A new listener on a high/uncommon port owned by an unrecognized or unsigned binary, especially one that appeared recently relative to other findings'' timelines.'
        common_attack_usage = 'Backdoors and reverse-shell-style implants frequently open a listening port for direct attacker connection, or repurpose a legitimate-sounding process name to blend in.'
        mitre_technique_id = 'T1049'
        mitre_technique = 'System Network Connections Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Diff the listener set against a known-good baseline for the host''s role; flag unsigned or unrecognized owning processes.'
        mitre_data_sources = @('Network Traffic', 'Process', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'persistence'
        default_reasoning = @('Listening ports expose services that may be exploited by attackers for initial access, lateral movement, or as an attacker-planted backdoor.')
        detection_logic = 'Point-in-time snapshot of all listening TCP/UDP endpoints and their owning process at collection time.'
        detection_threshold = 'n/a — every listener is captured; suspicion is evaluated per-listener during triage.'
        false_positive_notes = 'Many legitimate enterprise applications (database servers, management agents) open non-standard listening ports by design.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Validate every listener''s owning process against the host''s documented/approved service list.'; reason = 'Identifies unauthorized backdoors or rogue services.' }
        )
        investigation_questions = @('Is every listening port accounted for by a documented, approved service?', 'Does any listener''s owning process fail signature validation or run from a non-standard path?')
        findingtags = @('lateral-movement', 'malware', 'live-response')
    }
    "wifi-passwords" = @{
        finding_type = 'Wi-Fi Saved Passwords'
        category = 'Credential Access'
        subcategory = 'Stored Credentials'
        title = 'Wi-Fi Saved Passwords'
        description = 'Pre-shared keys for every Wi-Fi network profile saved on the host, decoded in cleartext.'
        why_this_matters = 'A saved Wi-Fi PSK grants direct network access to anyone who obtains it — if the host is compromised, extracting these keys lets an attacker access every network the device has ever joined, including the corporate wireless network.'
        expected_normal_behaviour = 'A short list of legitimate networks the user has joined (office, home); presence of the key itself is normal, exfiltration/misuse of it is not.'
        investigator_notes = 'Treat extraction of this finding by any process other than the Forensicator collector itself as a high-confidence credential-theft indicator — attackers routinely run ''netsh wlan show profile key=clear'' for exactly this purpose.'
        what_is_this = 'Wi-Fi profiles Windows stores per-machine, decoded via ''netsh wlan show profile <name> key=clear'' to reveal the stored PSK.'
        why_it_exists = 'Windows persists Wi-Fi credentials so the device can auto-reconnect to known networks without the user re-entering the password each time.'
        normal_behaviour = 'Keys for networks the user is legitimately authorized to access.'
        suspicious_behaviour = 'Presence of keys for networks the user/asset has no business connecting to, or evidence that netsh wlan key-extraction commands were run by a process other than an authorized IT tool.'
        common_attack_usage = 'Attackers dump saved Wi-Fi PSKs to pivot onto the wireless network directly, bypassing endpoint-based network controls, or to access other devices on the same wireless segment.'
        mitre_technique_id = 'T1555'
        mitre_technique = 'Credentials from Password Stores'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Monitor for ''netsh wlan show profile ... key=clear'' command-line execution outside of authorized IT/collector tooling.'
        mitre_data_sources = @('Command Execution', 'Process Command-Line Parameters')
        base_risk_score = 12
        mitre_bucket = 'credential_access'
        default_reasoning = @('Saved Wi-Fi passwords expose pre-shared keys that can be used to access wireless networks or pivot to other segments if exfiltrated.')
        detection_logic = 'Enumerates all local Wi-Fi profiles and decodes each stored key via netsh; presence of any decoded key is reported.'
        detection_threshold = 'n/a — every stored profile is reported; risk is driven by whether extraction was authorized.'
        false_positive_notes = 'The Forensicator collector itself performs this exact extraction for legitimate IR purposes — corroborate with process-execution findings to rule out an unrelated, unauthorized extraction.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm no unauthorized process ran netsh wlan key-extraction commands prior to this collection.'; reason = 'Distinguishes legitimate IR collection from attacker credential theft.' },
            @{ priority = 'Medium'; action = 'Rotate any PSK confirmed to have been exfiltrated by an attacker.'; reason = 'Denies continued wireless access using the stolen key.' }
        )
        investigation_questions = @('Was this key extracted by the authorized Forensicator collector or by another process?', 'Do any saved networks belong to segments this asset should not have access to?')
        findingtags = @('credential-access', 'live-response')
    }
    "firewall-rules" = @{
        finding_type = 'Firewall Rules'
        category = 'Defense Evasion'
        subcategory = 'Host Firewall'
        title = 'Firewall Rules'
        description = 'All configured Windows Firewall rules, including their enabled/disabled state, direction, and action.'
        why_this_matters = 'Attackers with local admin frequently add permissive inbound-allow rules (for a backdoor listener) or disable rules protecting a service they intend to exploit — both are direct, high-confidence tampering indicators.'
        expected_normal_behaviour = 'A stable set of rules matching the OS default policy plus whatever the organization''s endpoint management deploys; changes should trace back to a change ticket or software install.'
        investigator_notes = 'Compare the current rule set against a known-good baseline for the asset; newly-added inbound-allow rules on unusual ports are the highest-value signal here.'
        what_is_this = 'The full Windows Defender Firewall rule set, retrieved via Get-NetFirewallRule.'
        why_it_exists = 'Windows Firewall enforces the host''s inbound/outbound network policy at the OS level; rules define what''s permitted through it.'
        normal_behaviour = 'Rules matching OS defaults and organizationally-deployed policy, all enabled/disabled as intended.'
        suspicious_behaviour = 'A new inbound-allow rule for an unusual port, a disabled rule that should be enabled (especially ones protecting a specific well-known service), or a rule with an unusually broad scope (Any/Any).'
        common_attack_usage = 'Attackers add an inbound-allow rule to expose a backdoor listener through the firewall, or disable rules to defeat defenses before deploying further tooling — a classic Impair Defenses action.'
        mitre_technique_id = 'T1562.004'
        mitre_technique = 'Impair Defenses: Disable or Modify System Firewall'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Disable or Modify System Firewall'
        mitre_detection_notes = 'Diff the current rule set against the asset''s known-good baseline; flag any newly-added inbound-allow rule and any newly-disabled rule.'
        mitre_data_sources = @('Windows Registry', 'Command Execution')
        base_risk_score = 12
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Modified firewall rules may indicate an attacker disabled defenses or opened inbound ports for persistence.')
        detection_logic = 'Static enumeration of every configured firewall rule and its state at collection time.'
        detection_threshold = 'n/a — every rule is captured; suspicion is evaluated by diffing against baseline.'
        false_positive_notes = 'Legitimate software installs (VPN clients, collaboration tools, printer sharing) routinely add their own firewall rules.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Diff the current rule set against the asset''s approved baseline.'; reason = 'Surfaces attacker-added or attacker-disabled rules quickly.' }
        )
        investigation_questions = @('Does any newly-added rule allow inbound traffic on an unusual port?', 'Is any rule that should protect a specific service currently disabled?')
        findingtags = @('defense-evasion', 'live-response')
    }
    "outbound-smb" = @{
        finding_type = 'Outbound SMB Sessions'
        category = 'Lateral Movement'
        subcategory = 'SMB Activity'
        title = 'Outbound SMB Sessions'
        description = 'SMB connections this host has initiated outbound to other hosts on the network.'
        why_this_matters = 'Outbound SMB is the transport for pass-the-hash, PsExec-style remote execution, and lateral file staging — this host actively reaching out over SMB to peers is a strong lateral-movement signal.'
        expected_normal_behaviour = 'Connections to known file servers/DFS shares as part of normal user or automated (backup, patching) workflows.'
        investigator_notes = 'Correlate destination hosts and timing against admin-group and logon-event findings to determine whether this reflects legitimate administration or attacker pivoting.'
        what_is_this = 'A record of SMB client sessions this host has established to remote SMB servers.'
        why_it_exists = 'SMB underlies Windows file sharing, printing, and many remote administration tools; outbound sessions reflect the host actively using those services against a remote peer.'
        normal_behaviour = 'Sessions to documented file servers, domain controllers (SYSVOL/NETLOGON), and print servers.'
        suspicious_behaviour = 'Outbound SMB to a peer workstation (rather than server infrastructure), especially one this host has no prior history of contacting, or SMB sessions immediately following a suspicious logon.'
        common_attack_usage = 'Lateral movement toolkits (PsExec, Impacket''s psexec.py/wmiexec.py, and pass-the-hash attacks) rely on outbound SMB to authenticate to and execute on remote hosts.'
        mitre_technique_id = 'T1021.002'
        mitre_technique = 'Remote Services: SMB/Windows Admin Shares'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = 'SMB/Windows Admin Shares'
        mitre_detection_notes = 'Flag outbound SMB sessions to peer workstations rather than known server infrastructure, and any session immediately following a Wi-Fi/VPN or otherwise anomalous logon.'
        mitre_data_sources = @('Network Traffic', 'Logon Session')
        base_risk_score = 20
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Outbound SMB connections may indicate lateral movement, pass-the-hash, or data exfiltration over SMB.')
        detection_logic = 'Enumerates active outbound SMB client sessions from the host at collection time.'
        detection_threshold = 'n/a — every active session is captured; suspicion driven by destination and correlated logon activity.'
        false_positive_notes = 'Normal file-server and print-server access from user workflows and backup/patch-management agents both look identical to this finding without destination context.'
        recommendations = @(
            @{ priority = 'High'; action = 'Identify the destination host(s) and confirm whether the access was performed by an authorized administrator.'; reason = 'Distinguishes legitimate administration from attacker lateral movement.' }
        )
        investigation_questions = @('Is the SMB destination a documented server or an unexpected peer workstation?', 'Did this session immediately follow a suspicious or newly-observed logon?')
        findingtags = @('lateral-movement', 'live-response')
    }
    "smb-sessions" = @{
        finding_type = 'Active SMB Sessions'
        category = 'Lateral Movement'
        subcategory = 'SMB Activity'
        title = 'Active SMB Sessions'
        description = 'Inbound SMB sessions currently established by remote hosts/users against this endpoint.'
        why_this_matters = 'Shows exactly who/what is currently connected to this host''s file shares — unauthorized inbound sessions indicate this host is being used as a staging point or accessed by an attacker who has already moved laterally to it.'
        expected_normal_behaviour = 'Sessions from known administrative tools or expected peer access to shared folders, if any are configured.'
        investigator_notes = 'Cross-reference the connecting username/host against the local Administrators group and current active-logon findings.'
        what_is_this = 'The set of inbound SMB sessions currently open against this host''s SMB server, from Get-SmbSession.'
        why_it_exists = 'Windows'' SMB server tracks each connected client session to manage share access and permissions.'
        normal_behaviour = 'No sessions, or sessions limited to known administrative/backup accounts from expected source hosts.'
        suspicious_behaviour = 'A session from an unfamiliar host or account, particularly one connecting to administrative shares (C$, ADMIN$) rather than an intentionally-shared folder.'
        common_attack_usage = 'After lateral movement to a host, attackers often pivot again by connecting to its administrative shares from their foothold, which shows up here as an inbound session from the attacker''s prior hop.'
        mitre_technique_id = 'T1021.002'
        mitre_technique = 'Remote Services: SMB/Windows Admin Shares'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = 'SMB/Windows Admin Shares'
        mitre_detection_notes = 'Flag sessions connecting to administrative shares (C$, ADMIN$, IPC$) from hosts/accounts with no documented reason to do so.'
        mitre_data_sources = @('Network Traffic', 'Logon Session')
        base_risk_score = 15
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Active inbound SMB sessions may indicate unauthorized access or lateral movement by an attacker already present on the network.')
        detection_logic = 'Enumerates active inbound SMB sessions on the host at collection time.'
        detection_threshold = 'n/a — every active session is captured; suspicion driven by source and share accessed.'
        false_positive_notes = 'Backup agents, EDR/management tooling, and legitimate administrators will show as normal inbound sessions.'
        recommendations = @(
            @{ priority = 'High'; action = 'Identify the connecting account/host and confirm authorization for the access.'; reason = 'Confirms whether this reflects legitimate administration or attacker lateral movement.' }
        )
        investigation_questions = @('Which account and source host established each session, and is that access authorized?', 'Is the session connecting to an administrative share (C$/ADMIN$) without a documented reason?')
        findingtags = @('lateral-movement', 'live-response')
    }
    "smb-shares" = @{
        finding_type = 'SMB Network Shares'
        category = 'Network Activity'
        subcategory = 'SMB Configuration'
        title = 'SMB Network Shares'
        description = 'All SMB shares currently configured and exposed by this host.'
        why_this_matters = 'Every share is an entry point for data access or staging; an unexpected or overly-permissive share is a direct exposure that both insiders and attackers can exploit.'
        expected_normal_behaviour = 'The default administrative shares (C$, ADMIN$, IPC$) plus any explicitly and intentionally configured shares for the asset''s role.'
        investigator_notes = 'Compare against a known-good baseline; a newly-created share, especially one on a workstation (which shouldn''t normally host shares), warrants investigation.'
        what_is_this = 'The output of Get-SmbShare, listing every share name, path, and description configured on the host.'
        why_it_exists = 'SMB shares are how Windows exposes folders for network access; some (administrative shares) are created automatically by the OS, others are user/admin-configured.'
        normal_behaviour = 'Default administrative shares plus documented, intentional shares only.'
        suspicious_behaviour = 'A newly-created share with a generic or suspicious name, a share pointing at an unusual path (e.g., a temp directory), or a share on an asset that shouldn''t be hosting any.'
        common_attack_usage = 'Attackers create a share as a staging area to move tooling or exfiltrate data, or to serve payloads to other hosts they intend to laterally move to.'
        mitre_technique_id = 'T1135'
        mitre_technique = 'Network Share Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Diff configured shares against the asset''s baseline; flag shares outside the default administrative set.'
        mitre_data_sources = @('Command Execution', 'Cloud Storage')
        base_risk_score = 10
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Exposed network shares may provide unauthorized access to sensitive data or be used as staging locations for tooling or exfiltration.')
        detection_logic = 'Static enumeration of every configured SMB share and its path at collection time.'
        detection_threshold = 'n/a — every share is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Print servers, file servers, and collaboration tools legitimately configure additional shares as part of normal operation.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Diff configured shares against the asset''s documented baseline.'; reason = 'Surfaces unauthorized or attacker-created shares.' }
        )
        investigation_questions = @('Is every non-administrative share accounted for by a documented business need?', 'Does any share point at an unusual path such as a temp or user-writable directory?')
        findingtags = @('lateral-movement', 'data-exfiltration', 'live-response')
    }
    "net-hops" = @{
        finding_type = 'Network Hops (Non-local Routes)'
        category = 'Network Activity'
        subcategory = 'Routing'
        title = 'Network Hops (Non-local Routes)'
        description = 'Configured routes to non-local network destinations found in the host''s routing table.'
        why_this_matters = 'Non-local routes reveal what other network segments this host can reach directly, which is directly relevant to lateral-movement/pivot potential.'
        expected_normal_behaviour = 'The default route plus any documented static routes for the asset''s role (e.g., a jump box with routes to a management network).'
        investigator_notes = 'A route to a segment not otherwise explained by the asset''s role may indicate manual tampering or an attacker-installed pivot route.'
        what_is_this = 'Non-default (non-0.0.0.0/0) routes present in the host''s IP routing table, from Get-NetRoute.'
        why_it_exists = 'Routes beyond the default gateway let a host reach specific remote networks directly, typically for multi-homed or specially-configured hosts.'
        normal_behaviour = 'No unexpected routes beyond the default route and any documented static routes for the host''s role.'
        suspicious_behaviour = 'A route to a segment the host''s normal role gives it no reason to reach.'
        common_attack_usage = 'An attacker who gains persistent access to a dual-homed or specially-routed host will use its existing routes as a ready-made pivot path into otherwise-isolated networks.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any non-default route to a segment outside the asset''s documented network role.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('Non-local routes may reveal unexpected network connectivity or attacker-injected routes for traffic redirection or pivoting.')
        detection_logic = 'Static enumeration of non-default routes present in the host''s routing table at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Multi-homed servers and jump boxes legitimately carry static routes to specific segments as part of their documented role.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm each non-default route matches the host''s documented network role.'; reason = 'Flags unexpected pivot paths.' }
        )
        investigation_questions = @('Does every non-default route correspond to the host''s documented network role?')
        findingtags = @('network-recon', 'live-response')
    }
    "adapter-hops" = @{
        finding_type = 'Adapter Hops (Adapters with Non-local Routes)'
        category = 'Network Activity'
        subcategory = 'Routing'
        title = 'Adapter Hops (Adapters with Non-local Routes)'
        description = 'Which network adapters carry non-local routes, mapping routing scope back to a specific physical/virtual interface.'
        why_this_matters = 'Ties non-local routing capability to a specific adapter, which is essential for confirming exactly which interface an attacker would use to pivot from this host.'
        expected_normal_behaviour = 'Non-local routes, if any, associated with the adapter matching the asset''s documented multi-homed role.'
        investigator_notes = 'Combine with the adapter inventory and IP configuration findings to build a complete picture of the host''s reachable network segments.'
        what_is_this = 'A correlation of the non-local routes finding to the specific adapter (interface index) each route is bound to.'
        why_it_exists = 'A route alone doesn''t show which physical path traffic would take; binding routes to adapters clarifies the actual pivot surface.'
        normal_behaviour = 'Non-local routing capability confined to the adapter(s) documented for the asset''s role.'
        suspicious_behaviour = 'Non-local routing capability on an adapter with no documented reason to carry it (e.g., the primary user-facing NIC rather than a dedicated management NIC).'
        common_attack_usage = 'Confirms which specific network interface an attacker could leverage as a pivot point once a dual-homed host is compromised.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag adapters carrying non-local routes outside the asset''s documented multi-homed configuration.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('Adapters with non-local routes indicate the host is connected to multiple network segments, which may be leveraged for pivoting.')
        detection_logic = 'Static cross-reference of non-local routes against their owning adapter at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Legitimately multi-homed servers will show this by design.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm the adapter carrying non-local routes matches the asset''s documented multi-homed role.'; reason = 'Clarifies the actual pivot surface for the host.' }
        )
        investigation_questions = @('Does the adapter carrying non-local routes match the host''s documented network role?')
        findingtags = @('network-recon', 'live-response')
    }
    "ip-hops" = @{
        finding_type = 'IP Hops (Infinite Lifetime Routes)'
        category = 'Network Activity'
        subcategory = 'Routing'
        title = 'IP Hops (Infinite Lifetime Routes)'
        description = 'Routes in the routing table configured with an infinite lifetime, i.e., persistent/static rather than DHCP/RA-assigned.'
        why_this_matters = 'Infinite-lifetime routes persist across reboots and DHCP renewals — they''re the kind an attacker would add for durable, sustained traffic redirection rather than a transient artifact.'
        expected_normal_behaviour = 'Persistent routes limited to those intentionally configured by IT for the asset''s documented role.'
        investigator_notes = 'Any persistent route not explained by IT documentation should be treated as a potential attacker-installed redirection route until confirmed otherwise.'
        what_is_this = 'Routes with ValidLifetime/PreferredLifetime set to Infinite, as opposed to routes learned dynamically (DHCP, router advertisement) that expire.'
        why_it_exists = 'Statically-added routes (via ''route add'' or netsh) default to a persistent, infinite lifetime so they survive reboots.'
        normal_behaviour = 'No infinite-lifetime routes beyond ones IT has intentionally and durably configured.'
        suspicious_behaviour = 'A persistent route with no corresponding IT change record, especially one redirecting traffic for a specific destination toward an unexpected next hop.'
        common_attack_usage = 'Attackers persist a manually-added route to durably redirect specific destination traffic through an attacker-controlled next hop, surviving reboots unlike a transient DHCP-learned route.'
        mitre_technique_id = 'T1016'
        mitre_technique = 'System Network Configuration Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any infinite-lifetime route without a corresponding documented IT change.'
        mitre_data_sources = @('Command Execution', 'Network Interface')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('Persistent routes with infinite lifetime may be attacker-injected for sustained traffic redirection surviving reboots.')
        detection_logic = 'Static enumeration of routes with infinite lifetime at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Legitimately and intentionally configured static routes will also show an infinite lifetime.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm every infinite-lifetime route has a corresponding IT change record.'; reason = 'Flags undocumented, potentially attacker-installed persistent routes.' }
        )
        investigation_questions = @('Does every infinite-lifetime route trace back to a documented IT change?')
        findingtags = @('network-recon', 'live-response')
    }
    "local-users" = @{
        finding_type = 'Local User Accounts'
        category = 'User Accounts'
        subcategory = 'Account Enumeration'
        title = 'Local User Accounts'
        description = 'All local user accounts on the host, including enabled/disabled state and last logon time.'
        why_this_matters = 'Rogue local accounts are a common, durable persistence mechanism — an attacker-created account survives password rotations and domain-level remediation that don''t touch local SAM accounts.'
        expected_normal_behaviour = 'Built-in accounts (Administrator, Guest, DefaultAccount — mostly disabled) plus any accounts the asset''s provisioning process intentionally created.'
        investigator_notes = 'Cross-reference against the account-creation event log findings to establish exactly when and by whom any unexpected account was created.'
        what_is_this = 'The full local SAM user account list from Get-LocalUser, independent of any domain accounts that may also log on to the host.'
        why_it_exists = 'Windows maintains a local Security Accounts Manager (SAM) database of accounts that can authenticate directly to the machine, separate from any domain.'
        normal_behaviour = 'Only expected built-in and provisioned accounts, correctly enabled/disabled per policy.'
        suspicious_behaviour = 'An enabled account not present in the asset''s provisioning baseline, an enabled built-in Administrator account (should normally be disabled on domain-joined hosts), or an account with a recent last-logon that doesn''t match any known user.'
        common_attack_usage = 'Attackers create a local account (or re-enable a disabled built-in one) as a low-visibility backdoor that persists independent of domain account management and password policies.'
        mitre_technique_id = 'T1087.001'
        mitre_technique = 'Account Discovery: Local Account'
        mitre_tactic = 'discovery'
        mitre_sub_technique = 'Local Account'
        mitre_detection_notes = 'Diff the local account list against the asset''s provisioning baseline; flag any newly-enabled or unrecognized account.'
        mitre_data_sources = @('User Account')
        base_risk_score = 8
        mitre_bucket = 'persistence'
        default_reasoning = @('Local user accounts reveal enabled/disabled accounts and last logon — useful for detecting rogue accounts used for persistence.')
        detection_logic = 'Static enumeration of all local SAM accounts and their state at collection time.'
        detection_threshold = 'n/a — every account is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Software installers occasionally create local service accounts as part of legitimate product installation.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every enabled local account is accounted for in the asset''s provisioning baseline.'; reason = 'Identifies rogue accounts used for persistence.' }
        )
        investigation_questions = @('Is every enabled local account explained by the asset''s provisioning baseline?', 'Is the built-in Administrator account enabled when policy says it should be disabled?')
        findingtags = @('persistence', 'insider-threat', 'live-response')
    }
    "admin-group" = @{
        finding_type = 'Local Administrators Group Members'
        category = 'Privilege Escalation'
        subcategory = 'Group Membership'
        title = 'Local Administrators Group Members'
        description = 'Every member — user or group — of the local Administrators group on the host.'
        why_this_matters = 'Local admin rights are the single most impactful privilege on a Windows host; unexpected membership is one of the highest-confidence privilege-escalation/persistence indicators available.'
        expected_normal_behaviour = 'The built-in Administrator account (usually disabled) plus whatever accounts/groups IT policy intentionally grants local admin to (e.g., a domain ''Workstation Admins'' group).'
        investigator_notes = 'Cross-reference any unexpected member against the group-membership-change event log finding to identify exactly when and by whom it was added.'
        what_is_this = 'The membership list of the built-in local Administrators (BUILTIN\Administrators) group, from Get-LocalGroupMember.'
        why_it_exists = 'Membership in this group grants full local administrative control over the host, including the ability to install software, access all files, and disable security controls.'
        normal_behaviour = 'Membership matching exactly what IT policy documents for the asset.'
        suspicious_behaviour = 'Any account or group present that isn''t in the documented baseline, particularly a standard user account or an unfamiliar service account.'
        common_attack_usage = 'Adding a compromised or attacker-controlled account to local Administrators is one of the most common privilege-escalation and persistence techniques, since it grants durable, full local control.'
        mitre_technique_id = 'T1078.001'
        mitre_technique = 'Valid Accounts: Default Accounts'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = 'Default Accounts'
        mitre_detection_notes = 'Diff group membership against the documented baseline and correlate any addition with event 4732 (member added to security-enabled local group).'
        mitre_data_sources = @('User Account', 'Active Directory')
        base_risk_score = 20
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('Unexpected members in the local Administrators group are a strong indicator of privilege escalation or persistence.')
        detection_logic = 'Static enumeration of local Administrators group membership at collection time.'
        detection_threshold = 'n/a — every member is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'IT-managed groups (e.g., a domain security group granting helpdesk staff local admin) are a legitimate and common membership pattern.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every member against the asset''s documented local-admin baseline.'; reason = 'Identifies unauthorized privilege escalation or persistence via group membership.' }
        )
        investigation_questions = @('Is every member of local Administrators accounted for in the documented baseline?', 'When was any unexpected member added, and by which account (see event 4732)?')
        findingtags = @('privilege-escalation', 'persistence', 'live-response')
    }
    "active-logon" = @{
        finding_type = 'Active Logon Sessions'
        category = 'User Accounts'
        subcategory = 'Session Enumeration'
        title = 'Active Logon Sessions'
        description = 'Currently active interactive and network logon sessions on the host.'
        why_this_matters = 'Shows exactly who is logged on right now — an unexpected concurrent session, especially from an account that shouldn''t be actively used, indicates unauthorized access in progress.'
        expected_normal_behaviour = 'The current interactive user''s session, plus any expected service/system sessions.'
        investigator_notes = 'Pay particular attention to sessions for service accounts or admin accounts showing an interactive logon type, which is atypical for their intended use.'
        what_is_this = 'Active logon sessions on the host as reported by query user / Get-CimInstance Win32_LogonSession, correlated to the account.'
        why_it_exists = 'Windows tracks active sessions to manage per-session resources, security tokens, and remote-desktop connections.'
        normal_behaviour = 'A small number of sessions matching expected interactive users and system/service accounts.'
        suspicious_behaviour = 'A concurrent session for an account not expected to be actively logged on, or multiple simultaneous sessions for the same account from different source contexts.'
        common_attack_usage = 'An attacker who has obtained valid credentials will show up here as an unexpected concurrent logon session while the legitimate user is unaware.'
        mitre_technique_id = 'T1033'
        mitre_technique = 'System Owner/User Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag sessions for accounts not expected to be actively logged on, particularly outside business hours.'
        mitre_data_sources = @('Logon Session', 'User Account')
        base_risk_score = 35
        mitre_bucket = 'credential_access'
        default_reasoning = @('Active interactive logon sessions may indicate unauthorized users currently logged in to the system.')
        detection_logic = 'Point-in-time snapshot of all active logon sessions at collection time.'
        detection_threshold = 'n/a — every active session is captured; suspicion driven by whether the account is expected to be active.'
        false_positive_notes = 'Shared/kiosk machines and hosts with legitimate remote-support sessions will naturally show multiple concurrent sessions.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Confirm every active session belongs to an account expected to be logged on right now.'; reason = 'Identifies unauthorized concurrent access.' }
        )
        investigation_questions = @('Is every active session accounted for by an expected user or service account?', 'Is any session for an account occurring outside its normal usage pattern (time, session type)?')
        findingtags = @('insider-threat', 'live-response')
    }
    "user-profiles" = @{
        finding_type = 'User Profiles (Historical Presence)'
        category = 'User Accounts'
        subcategory = 'Account History'
        title = 'User Profiles (Historical Presence)'
        description = 'Local user profile directories present on disk, showing every account that has ever logged on interactively to this host.'
        why_this_matters = 'Profile directories persist after an account is deleted or disabled, so this reveals historical account activity that the current local-users list alone would miss.'
        expected_normal_behaviour = 'Profiles for the asset''s known, historical set of users.'
        investigator_notes = 'A profile for an account no longer present in the local-users or domain-users findings is worth reconciling — it may indicate a deleted account, or a domain account that logged on once and is otherwise unaccounted for.'
        what_is_this = 'The set of user profile folders under C:\Users, each corresponding to an account that has logged on interactively at least once.'
        why_it_exists = 'Windows creates a profile directory the first time any account logs on interactively, and by default retains it after the account is removed unless explicitly cleaned up.'
        normal_behaviour = 'Profiles matching the asset''s known historical user base.'
        suspicious_behaviour = 'A profile for an unfamiliar account, especially one with no corresponding entry in current local or domain user listings, or a profile with a recent last-write time inconsistent with any known logon.'
        common_attack_usage = 'An attacker-created account that was later deleted to cover tracks will still leave behind a profile directory — this finding can recover evidence of accounts an attacker tried to erase.'
        mitre_technique_id = 'T1033'
        mitre_technique = 'System Owner/User Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Reconcile every profile directory against current local and domain account listings; investigate any orphaned profile.'
        mitre_data_sources = @('File', 'User Account')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('Historical user profiles reveal accounts that have logged on, including deleted or dormant accounts that may be evidence of attacker activity.')
        detection_logic = 'Static enumeration of all user profile directories present on disk at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Contractors, former employees, and legitimately-removed accounts all leave behind orphaned profiles as routine IT lifecycle debris.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Reconcile any orphaned profile against current account listings and offboarding records.'; reason = 'Distinguishes routine IT debris from evidence of a deleted attacker-created account.' }
        )
        investigation_questions = @('Does every profile correspond to a currently-known local or domain account?', 'Does any orphaned profile''s last-write time align with suspicious activity in other findings?')
        findingtags = @('insider-threat', 'live-response')
    }
    "local-groups" = @{
        finding_type = 'Important Local Group Members'
        category = 'Privilege Escalation'
        subcategory = 'Group Membership'
        title = 'Important Local Group Members'
        description = 'Membership of security-sensitive local groups beyond Administrators — Backup Operators, Remote Desktop Users, Power Users, and similar.'
        why_this_matters = 'Several of these groups grant privileges nearly as powerful as full admin (Backup Operators can read any file bypassing NTFS permissions; Remote Desktop Users grants interactive remote access) and are less scrutinized than Administrators membership.'
        expected_normal_behaviour = 'Membership matching the asset''s documented policy for each sensitive group, typically a short, well-known list.'
        investigator_notes = 'Backup Operators membership deserves the same scrutiny as Administrators membership — it''s a well-known privilege-escalation path (backup/restore privilege can be abused to read the SAM/SYSTEM hives).'
        what_is_this = 'Membership lists for locally-sensitive built-in groups (Backup Operators, Remote Desktop Users, Power Users, etc.), from Get-LocalGroupMember.'
        why_it_exists = 'Windows provides these groups as a way to delegate specific powerful capabilities without granting full Administrators membership.'
        normal_behaviour = 'Membership matching documented IT policy for each group.'
        suspicious_behaviour = 'An unexpected account added to Backup Operators or Remote Desktop Users, particularly one not otherwise privileged.'
        common_attack_usage = 'Attackers add an account to Backup Operators to gain a privilege-escalation path to SYSTEM (via SAM/SYSTEM hive backup) that''s less monitored than direct Administrators membership, or to Remote Desktop Users for persistent remote access.'
        mitre_technique_id = 'T1069.001'
        mitre_technique = 'Permission Groups Discovery: Local Groups'
        mitre_tactic = 'discovery'
        mitre_sub_technique = 'Local Groups'
        mitre_detection_notes = 'Diff membership of each sensitive group against documented baseline; flag any addition to Backup Operators specifically for priority review.'
        mitre_data_sources = @('User Account', 'Active Directory')
        base_risk_score = 15
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('Members of privileged groups such as Backup Operators may be leveraged for lateral movement, privilege escalation, or data access.')
        detection_logic = 'Static enumeration of membership for each security-sensitive local group at collection time.'
        detection_threshold = 'n/a — every member is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Help-desk and backup-operations staff are legitimately added to these groups per documented IT policy.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every member of each sensitive group against documented IT policy, prioritizing Backup Operators.'; reason = 'Identifies a less-scrutinized privilege-escalation path attackers commonly abuse.' }
        )
        investigation_questions = @('Is every member of Backup Operators and Remote Desktop Users accounted for by documented policy?')
        findingtags = @('privilege-escalation', 'live-response')
    }
    "os-info" = @{
        finding_type = 'Operating System Information'
        category = 'System Information'
        subcategory = 'System Baseline'
        title = 'Operating System Information'
        description = 'OS version, build number, and install date for the endpoint.'
        why_this_matters = 'Version/build directly determines which vulnerabilities and known exploits are applicable to this host, and end-of-life builds carry no vendor security patching at all.'
        expected_normal_behaviour = 'A currently-supported Windows version/build consistent with the organization''s patching baseline.'
        investigator_notes = 'Cross-reference the build number against currently-known, actively-exploited CVEs for that build when scoping an intrusion.'
        what_is_this = 'Core OS identification (edition, version, build number, install date) from Get-CimInstance Win32_OperatingSystem.'
        why_it_exists = 'Provides the baseline context needed to assess patch level and applicable vulnerability exposure for every other finding on this host.'
        normal_behaviour = 'A supported, patched OS version consistent with fleet policy.'
        suspicious_behaviour = 'An end-of-life or significantly out-of-date build relative to the organization''s patching SLA.'
        common_attack_usage = 'Attackers specifically target unpatched or end-of-life systems where known, weaponized exploits remain effective and no vendor patch will ever be issued.'
        mitre_technique_id = 'T1082'
        mitre_technique = 'System Information Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag builds beyond the organization''s patch SLA or past vendor end-of-life.'
        mitre_data_sources = @('Command Execution', 'Process')
        base_risk_score = 5
        mitre_bucket = 'impact'
        default_reasoning = @('OS version and build number help identify unpatched or end-of-life systems with known applicable vulnerabilities.')
        detection_logic = 'Static collection of OS version/build metadata at collection time.'
        detection_threshold = 'n/a — informational baseline.'
        false_positive_notes = 'n/a — purely descriptive.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm the build is within the organization''s patch SLA and not past vendor end-of-life.'; reason = 'Scopes which known vulnerabilities are applicable to this host.' }
        )
        investigation_questions = @('Is this build within the organization''s patch SLA and still vendor-supported?')
        findingtags = @('live-response')
    }
    "installed-apps" = @{
        finding_type = 'Installed Applications'
        category = 'System Information'
        subcategory = 'Software Inventory'
        title = 'Installed Applications'
        description = 'Full inventory of installed software on the endpoint.'
        why_this_matters = 'Both attacker-deployed utilities (remote-access tools, admin utilities repurposed for malicious use) and known-vulnerable software versions show up here.'
        expected_normal_behaviour = 'Software matching the organization''s approved application catalog for the asset''s role.'
        investigator_notes = 'Look specifically for dual-use admin/remote-access tools (e.g., AnyDesk, PsExec, Advanced IP Scanner) that aren''t part of the organization''s sanctioned toolset — these are common ''living off the land'' attacker installs.'
        what_is_this = 'The installed-software inventory pulled from registry Uninstall keys, matching what Programs and Features displays.'
        why_it_exists = 'Provides a full software bill-of-materials for the endpoint to support vulnerability and unauthorized-software assessment.'
        normal_behaviour = 'Applications matching the organization''s approved catalog.'
        suspicious_behaviour = 'Unsanctioned remote-access or network-scanning tools, or known-vulnerable application versions relevant to the current investigation.'
        common_attack_usage = 'Attackers frequently install legitimate, signed dual-use remote-access or admin tools (rather than custom malware) specifically because they''re less likely to be flagged by signature-based defenses.'
        mitre_technique_id = 'T1518'
        mitre_technique = 'Software Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Diff installed software against the organization''s approved catalog; flag any dual-use remote-access/admin tool not on the approved list.'
        mitre_data_sources = @('Windows Registry', 'Application Log')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('Installed applications may include known vulnerable software or attacker-deployed dual-use remote-access/admin utilities.')
        detection_logic = 'Static enumeration of installed software from the registry at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Legitimate IT and helpdesk tooling can overlap with the same dual-use category attackers favor; confirm authorization rather than assuming malice.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Diff installed software against the organization''s approved application catalog.'; reason = 'Surfaces unsanctioned dual-use remote-access/admin tools.' }
        )
        investigation_questions = @('Is any installed remote-access or network-scanning tool absent from the organization''s approved catalog?', 'Does any installed application version have a known, relevant CVE?')
        findingtags = @('live-response')
    }
    "logical-drives" = @{
        finding_type = 'Logical Drives (Storage)'
        category = 'System Information'
        subcategory = 'Storage'
        title = 'Logical Drives (Storage)'
        description = 'Logical drive inventory with capacity and free space for each volume.'
        why_this_matters = 'A sudden, large drop in free space can indicate mass file staging (archiving stolen data) or mass encryption by ransomware; unusually full drives may also indicate large exfiltration staging archives.'
        expected_normal_behaviour = 'Free space consistent with the host''s normal usage pattern and historical baseline.'
        investigator_notes = 'Compare against any prior collection for this host if available — a sharp, unexplained free-space delta is the key signal here, not the absolute value.'
        what_is_this = 'Per-volume capacity and free-space figures from Get-CimInstance Win32_LogicalDisk.'
        why_it_exists = 'Basic storage inventory needed to contextualize file-system-heavy findings (new files, downloads, ransomware indicators) elsewhere in the collection.'
        normal_behaviour = 'Free space consistent with the host''s historical usage pattern.'
        suspicious_behaviour = 'An unexplained sharp drop in free space, particularly correlating in time with ransomware or mass-staging indicators elsewhere in the investigation.'
        common_attack_usage = 'Ransomware encryption and large-scale exfiltration staging (archiving many files before upload) both cause a rapid free-space decrease that can corroborate other findings'' timing.'
        mitre_technique_id = 'T1082'
        mitre_technique = 'System Information Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag a free-space delta beyond the host''s normal historical variance.'
        mitre_data_sources = @('Command Execution')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Drive free space analysis may reveal large data deletions, mass file staging, or ransomware encryption activity.')
        detection_logic = 'Static per-volume capacity/free-space snapshot at collection time.'
        detection_threshold = 'n/a — informational inventory; suspicion requires a prior baseline for comparison.'
        false_positive_notes = 'Legitimate large software installs, VM disk provisioning, or scheduled archival jobs can also cause large free-space deltas.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Compare free space against a prior baseline collection for this host, if available.'; reason = 'Surfaces mass file staging or ransomware encryption activity by its storage footprint.' }
        )
        investigation_questions = @('Is there an unexplained, sharp drop in free space relative to this host''s historical baseline?')
        findingtags = @('ransomware', 'data-exfiltration', 'live-response')
    }
    "env-vars" = @{
        finding_type = 'Environment Variables'
        category = 'System Information'
        subcategory = 'System Configuration'
        title = 'Environment Variables'
        description = 'System and user environment variables configured on the endpoint.'
        why_this_matters = 'Attackers occasionally abuse environment variables (e.g., a tampered PATH prepending a directory containing a malicious binary that shadows a legitimate one) for stealthy execution persistence.'
        expected_normal_behaviour = 'Standard OS/application-set variables matching the host''s normal software configuration.'
        investigator_notes = 'A PATH variable with an unusual, user-writable directory prepended ahead of standard system directories is the highest-value thing to check here.'
        what_is_this = 'The full set of system and user environment variables from Get-ChildItem Env:.'
        why_it_exists = 'Environment variables configure process behavior (search paths, temp locations, default settings) at the OS and application level.'
        normal_behaviour = 'Variables matching the standard OS defaults plus expected application-specific additions.'
        suspicious_behaviour = 'An unexpected or newly-added variable, especially a PATH entry pointing to a user-writable or unusual directory placed ahead of system directories.'
        common_attack_usage = 'Search-order/PATH hijacking abuses a manipulated PATH variable to have a legitimate-looking process name resolve to an attacker-planted binary instead of the real one.'
        mitre_technique_id = 'T1574.007'
        mitre_technique = 'Hijack Execution Flow: Path Interception by PATH Environment Variable'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Path Interception by PATH Environment Variable'
        mitre_detection_notes = 'Flag any PATH entry pointing to a user-writable directory, particularly one ordered before standard system directories.'
        mitre_data_sources = @('Command Execution', 'Windows Registry')
        base_risk_score = 10
        mitre_bucket = 'persistence'
        default_reasoning = @('Environment variables, particularly PATH, may reveal search-order hijacking configured for stealthy persistence.')
        detection_logic = 'Static enumeration of all environment variables at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Many legitimate developer tools and applications add entries to PATH and other variables during normal installation.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Review PATH ordering for any user-writable directory placed ahead of system directories.'; reason = 'Surfaces PATH-hijacking persistence.' }
        )
        investigation_questions = @('Does the PATH variable contain a user-writable directory ordered before system directories?')
        findingtags = @('persistence', 'live-response')
    }
    "hotfixes" = @{
        finding_type = 'Installed Hotfixes'
        category = 'System Information'
        subcategory = 'Patch Level'
        title = 'Installed Hotfixes'
        description = 'Installed Windows updates/hotfixes (KB numbers) and their install dates.'
        why_this_matters = 'Directly shows the patch level of the host, which determines which known, publicly-documented vulnerabilities remain exploitable.'
        expected_normal_behaviour = 'Hotfixes consistent with the organization''s patch cadence and SLA for the asset''s OS build.'
        investigator_notes = 'Cross-reference missing security-relevant KBs against the CVE(s) suspected to be involved in the current investigation.'
        what_is_this = 'The installed hotfix/update list from Get-HotFix, showing KB identifiers and installation dates.'
        why_it_exists = 'Provides the granular patch-level detail needed to determine exposure to specific, publicly known vulnerabilities.'
        normal_behaviour = 'Regular, cadence-consistent hotfix installation matching the organization''s patch policy.'
        suspicious_behaviour = 'A gap in patch history beyond the organization''s SLA, particularly missing a specific security-critical KB relevant to the current investigation.'
        common_attack_usage = 'Attackers target specific, unpatched CVEs; the absence of the corresponding KB directly confirms exploitability on this host.'
        mitre_technique_id = 'T1082'
        mitre_technique = 'System Information Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Cross-reference installed KBs against the KB(s) that remediate any CVE under active investigation.'
        mitre_data_sources = @('Command Execution')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('Missing security hotfixes indicate the host remains exploitable via the corresponding known, publicly-documented vulnerability.')
        detection_logic = 'Static enumeration of installed hotfixes and their install dates at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Some hotfixes are optional/feature-related rather than security-critical; prioritize security-classified KBs.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Confirm the KB remediating any CVE under active investigation is installed.'; reason = 'Directly confirms or rules out exploitability of a specific known vulnerability.' }
        )
        investigation_questions = @('Is the host missing a security KB relevant to any CVE currently under investigation?')
        findingtags = @('live-response')
    }
    "win-defender" = @{
        finding_type = 'Windows Defender Status'
        category = 'Defense Evasion'
        subcategory = 'Security Controls'
        title = 'Windows Defender Status'
        description = 'Windows Defender real-time protection status, signature version, and exclusion list.'
        why_this_matters = 'Attackers routinely disable real-time protection or add exclusions covering their tooling before deploying malware — this is one of the most direct, high-confidence defense-evasion indicators available.'
        expected_normal_behaviour = 'Real-time protection enabled, signatures current, and exclusions limited to legitimate, documented software conflicts.'
        investigator_notes = 'Any exclusion path pointing to a temp directory, user-writable location, or unfamiliar folder is a near-certain sign of attacker tampering to shield their tooling from detection.'
        what_is_this = 'Windows Defender''s current configuration and status, from Get-MpComputerStatus and Get-MpPreference.'
        why_it_exists = 'Reports whether the host''s primary built-in AV/EDR-lite control is active and correctly configured, and what it''s been told to ignore.'
        normal_behaviour = 'Real-time protection enabled with only documented, legitimate exclusions.'
        suspicious_behaviour = 'Real-time protection disabled, tamper protection disabled, signatures significantly out of date, or an exclusion pointing at a temp/user-writable directory.'
        common_attack_usage = 'Disabling Defender or adding an exclusion for the directory a payload will be dropped into is a standard step in most intrusions before deploying malware or attacker tooling, to avoid immediate detection.'
        mitre_technique_id = 'T1562.001'
        mitre_technique = 'Impair Defenses: Disable or Modify Tools'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Disable or Modify Tools'
        mitre_detection_notes = 'Flag real-time protection disabled, and any exclusion path in a temp, user-writable, or otherwise unexpected directory.'
        mitre_data_sources = @('Windows Registry', 'Process', 'Sensor Health')
        base_risk_score = 15
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Disabled real-time protection or suspicious exclusions strongly indicate an attacker attempting to impair defenses ahead of deploying tooling.')
        detection_logic = 'Static snapshot of Defender''s protection status, signature age, and configured exclusions at collection time.'
        detection_threshold = 'Any disabled protection component or an exclusion in a non-standard location should be treated as high-priority.'
        false_positive_notes = 'IT-approved software conflicts (backup agents, some developer tools) legitimately require documented exclusions.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately investigate the reason for any disabled protection component or non-standard exclusion.'; reason = 'Confirms or rules out deliberate defense-evasion tampering by an attacker.' }
        )
        investigation_questions = @('Is real-time protection or tamper protection currently disabled, and if so by whom/when?', 'Does any configured exclusion point to a temp or user-writable directory?')
        findingtags = @('defense-evasion', 'malware', 'live-response')
    }
    "processes" = @{
        finding_type = 'Running Processes'
        category = 'Execution'
        subcategory = 'Process Enumeration'
        title = 'Running Processes'
        description = 'All currently running processes on the endpoint, including path, command line, and parent process.'
        why_this_matters = 'Live process listing is the single richest artifact for spotting an attacker''s active tooling — process name spoofing, unusual parent/child relationships, and suspicious command lines all surface here.'
        expected_normal_behaviour = 'A stable set of OS and application processes with expected parent/child relationships (e.g., explorer.exe spawning user applications, services.exe spawning service processes).'
        investigator_notes = 'Pay close attention to process name masquerading (e.g., ''svch0st.exe'' or a correctly-named binary running from the wrong path), unsigned binaries, and unusual parent processes (e.g., Office applications spawning cmd.exe/powershell.exe).'
        what_is_this = 'A live snapshot of every running process, its full command line, executable path, and parent process ID, from Get-CimInstance Win32_Process / Get-Process.'
        why_it_exists = 'Reflects exactly what code is actively executing on the host at the moment of collection.'
        normal_behaviour = 'Expected system and application processes with normal, explainable parent/child relationships.'
        suspicious_behaviour = 'A process running from a temp/user-writable directory, an unsigned binary claiming to be a system process, or an unusual parent/child relationship (e.g., winword.exe spawning powershell.exe).'
        common_attack_usage = 'Almost every stage of an intrusion — initial payload execution, living-off-the-land tooling, credential dumping, lateral movement — leaves a visible trace in the process list at the moment it runs.'
        mitre_technique_id = 'T1057'
        mitre_technique = 'Process Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag unsigned binaries, processes running from temp/user-writable paths, and known-suspicious parent/child relationships (Office apps spawning script interpreters).'
        mitre_data_sources = @('Process', 'Command Execution')
        base_risk_score = 8
        mitre_bucket = 'execution'
        default_reasoning = @('Running process list may reveal active attacker tooling, masquerading, or suspicious parent/child execution relationships.')
        detection_logic = 'Point-in-time snapshot of every running process, its command line, path, and parent at collection time.'
        detection_threshold = 'n/a — every process is captured; suspicion is evaluated per-process during triage.'
        false_positive_notes = 'Many legitimate applications run from AppData or other user-writable locations by design (Electron apps, browser updaters).'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Validate signature and path for any process flagged as unusual or unsigned.'; reason = 'Confirms or rules out active attacker tooling currently running on the host.' }
        )
        investigation_questions = @('Does any running process have an unusual parent/child relationship or run from a temp/user-writable path?', 'Is every process claiming to be a system binary correctly signed and running from its expected path?')
        findingtags = @('malware', 'live-response')
    }
    "startup-progs" = @{
        finding_type = 'Startup Programs'
        category = 'Persistence'
        subcategory = 'Autoruns'
        title = 'Startup Programs'
        description = 'Programs configured to run automatically at user logon via Startup folders and Run/RunOnce registry keys.'
        why_this_matters = 'This is one of the most commonly abused, simplest persistence mechanisms — an attacker-planted startup entry guarantees re-execution on every logon or reboot.'
        expected_normal_behaviour = 'A small set of known application updaters, sync clients, and IT-managed startup entries.'
        investigator_notes = 'Any entry pointing to a temp directory, an unfamiliar binary, or an encoded/obfuscated command line in a Run key value warrants immediate follow-up.'
        what_is_this = 'Entries from the Startup folders (per-user and all-users) and the Run/RunOnce registry keys that Windows executes automatically at logon.'
        why_it_exists = 'Provides applications a standard, OS-supported way to launch automatically without requiring the user to manually start them each session.'
        normal_behaviour = 'Entries limited to known, legitimate applications the user or IT has intentionally configured to auto-start.'
        suspicious_behaviour = 'A newly-added entry pointing to an unfamiliar binary, a script interpreter with an encoded/obfuscated argument, or an entry in a temp/user-writable path.'
        common_attack_usage = 'Run-key and Startup-folder persistence is one of the most common techniques across all attacker sophistication levels, since it''s simple, reliable, and survives reboots.'
        mitre_technique_id = 'T1547.001'
        mitre_technique = 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Registry Run Keys / Startup Folder'
        mitre_detection_notes = 'Diff startup entries against the asset''s baseline; flag any entry with an encoded/obfuscated command line or pointing to a non-standard path.'
        mitre_data_sources = @('Windows Registry', 'File', 'Command Execution')
        base_risk_score = 15
        mitre_bucket = 'persistence'
        default_reasoning = @('Unrecognized or newly-added startup entries are a strong indicator of attacker-installed persistence surviving reboot/logon.')
        detection_logic = 'Static enumeration of Startup folder contents and Run/RunOnce registry key values at collection time.'
        detection_threshold = 'n/a — every entry is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Many legitimate applications (cloud sync clients, chat apps, update checkers) add themselves to Run keys during normal installation.'
        recommendations = @(
            @{ priority = 'High'; action = 'Diff startup entries against the asset''s known-good baseline and validate any new entry''s binary/command line.'; reason = 'Identifies attacker-installed persistence surviving reboot.' }
        )
        investigation_questions = @('Is every startup entry accounted for by a known, legitimate application?', 'Does any entry contain an encoded, obfuscated, or otherwise suspicious command line?')
        findingtags = @('persistence', 'malware', 'live-response')
    }
    "services" = @{
        finding_type = 'Windows Services'
        category = 'Persistence'
        subcategory = 'Autoruns'
        title = 'Windows Services'
        description = 'All installed Windows services, their startup type, current state, and executable path.'
        why_this_matters = 'Service-based persistence runs with SYSTEM privileges by default and survives reboots — a common choice for durable, privileged attacker footholds.'
        expected_normal_behaviour = 'Services matching the OS default set plus organizationally-deployed software (EDR, management agents, drivers).'
        investigator_notes = 'Look for services with an unfamiliar or generic-sounding display name, a binary path in a temp/user-writable directory, or a recently-modified/created service.'
        what_is_this = 'The full Windows service inventory (name, display name, start mode, state, binary path) from Get-CimInstance Win32_Service.'
        why_it_exists = 'Services provide the standard OS mechanism for running background processes automatically, typically with elevated privileges, independent of any logged-on user.'
        normal_behaviour = 'Services matching the OS default set and the organization''s deployed software baseline.'
        suspicious_behaviour = 'A newly-installed service with a generic name, a binary path outside standard system directories, or a service configured to run as SYSTEM with no clear legitimate purpose.'
        common_attack_usage = 'Malicious services are a classic privileged, reboot-surviving persistence mechanism, and are also the execution vector for tools like PsExec when used for remote code execution.'
        mitre_technique_id = 'T1543.003'
        mitre_technique = 'Create or Modify System Process: Windows Service'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Windows Service'
        mitre_detection_notes = 'Diff installed services against the asset''s baseline; flag services with binaries in temp/user-writable paths or generic/spoofed display names.'
        mitre_data_sources = @('Windows Registry', 'Service', 'Process')
        base_risk_score = 10
        mitre_bucket = 'persistence'
        default_reasoning = @('Unrecognized or newly-installed services are a common, privileged persistence mechanism surviving reboot.')
        detection_logic = 'Static enumeration of all installed services and their configuration at collection time.'
        detection_threshold = 'n/a — every service is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Legitimate software (drivers, security agents, business applications) routinely installs its own services.'
        recommendations = @(
            @{ priority = 'High'; action = 'Diff installed services against the asset''s known-good baseline and validate any new service''s binary path/signature.'; reason = 'Identifies privileged, reboot-surviving attacker persistence.' }
        )
        investigation_questions = @('Is every installed service accounted for by a known, legitimate application or the OS default set?', 'Does any service''s binary path point to a temp or user-writable directory?')
        findingtags = @('persistence', 'malware', 'live-response')
    }
    "scheduled-tasks" = @{
        finding_type = 'Scheduled Tasks'
        category = 'Persistence'
        subcategory = 'Autoruns'
        title = 'Scheduled Tasks'
        description = 'All scheduled tasks configured on the host, including triggers and the action they execute.'
        why_this_matters = 'Scheduled Tasks is one of the most flexible persistence mechanisms available — it can trigger on logon, on a schedule, on system idle, or on nearly any system event, and can run with SYSTEM privileges.'
        expected_normal_behaviour = 'Tasks matching the OS default maintenance set plus organizationally-deployed software''s own scheduled maintenance tasks.'
        investigator_notes = 'Give particular scrutiny to tasks with an encoded PowerShell command as the action, a trigger designed to blend in (e.g., ''at logon''), or a task hidden from the standard Task Scheduler GUI view.'
        what_is_this = 'The full scheduled task inventory (name, triggers, action, author, last/next run) from Get-ScheduledTask.'
        why_it_exists = 'Task Scheduler provides Windows'' native mechanism for running code on a defined schedule or in response to system events, independent of user interaction.'
        normal_behaviour = 'Tasks matching the OS default set and organizationally-deployed software''s maintenance tasks.'
        suspicious_behaviour = 'A newly-created task with an encoded/obfuscated command line, a task action pointing to a script interpreter with suspicious arguments, or a task with an unusually generic or spoofed name mimicking a legitimate OS task.'
        common_attack_usage = 'Scheduled Tasks persistence is extremely common across ransomware, APT, and commodity malware alike, precisely because of its flexibility, privilege potential, and ability to blend in among the many legitimate tasks already present on a typical host.'
        mitre_technique_id = 'T1053.005'
        mitre_technique = 'Scheduled Task/Job: Scheduled Task'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Scheduled Task'
        mitre_detection_notes = 'Diff scheduled tasks against the asset''s baseline; flag tasks with encoded command-line arguments or a spoofed name closely resembling a legitimate OS task.'
        mitre_data_sources = @('Windows Registry', 'Scheduled Job', 'Command Execution')
        base_risk_score = 12
        mitre_bucket = 'persistence'
        default_reasoning = @('Unrecognized or newly-created scheduled tasks are a flexible, potentially privileged persistence mechanism commonly abused by attackers.')
        detection_logic = 'Static enumeration of all scheduled tasks, their triggers, and actions at collection time.'
        detection_threshold = 'n/a — every task is captured; suspicion driven by comparison against baseline.'
        false_positive_notes = 'Nearly every application and the OS itself installs its own maintenance/update-check scheduled tasks by default.'
        recommendations = @(
            @{ priority = 'High'; action = 'Diff scheduled tasks against the asset''s known-good baseline and validate any new task''s action/command line.'; reason = 'Identifies flexible, potentially-privileged attacker persistence.' }
        )
        investigation_questions = @('Is every scheduled task accounted for by a known, legitimate application or the OS default set?', 'Does any task''s action contain an encoded or obfuscated command line?')
        findingtags = @('persistence', 'malware', 'ransomware', 'live-response')
    }
    "link-files" = @{
        finding_type = 'Link Files (Shortcuts)'
        category = 'Persistence'
        subcategory = 'Autoruns'
        title = 'Link Files (Shortcuts)'
        description = 'Windows .lnk shortcut files found in locations relevant to persistence and recent-activity tracking (Startup, Recent, Desktop).'
        why_this_matters = 'LNK files can carry an arbitrary target command line independent of their displayed icon/name, making them both a persistence vector and a record of recently-accessed files/programs.'
        expected_normal_behaviour = 'Shortcuts to legitimate, expected applications and recently-opened documents.'
        investigator_notes = 'Inspect the LNK''s actual target/arguments, not just its display name — a shortcut can display as ''Report.docx.lnk'' while its real target launches PowerShell with an encoded payload.'
        what_is_this = 'Windows Shell Link (.lnk) files, which store a target path, arguments, working directory, and icon reference, automatically created by the OS when files are opened (Recent) or manually placed for persistence (Startup).'
        why_it_exists = 'Recent-items LNKs are auto-generated by Windows to power jump lists and the Recent Items view; Startup-folder LNKs are a standard, supported way to launch an application at logon.'
        normal_behaviour = 'Recent-items LNKs matching normal user file access; Startup LNKs matching known, legitimate applications.'
        suspicious_behaviour = 'A Startup-folder LNK whose target is a script interpreter with encoded/obfuscated arguments, or a LNK whose target path doesn''t match its filename/icon.'
        common_attack_usage = 'Malicious LNK files placed in the Startup folder are a well-known persistence technique, and LNKs are also a common initial-access delivery mechanism (e.g., a disguised LNK attachment that launches PowerShell when opened).'
        mitre_technique_id = 'T1547.009'
        mitre_technique = 'Boot or Logon Autostart Execution: Shortcut Modification'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Shortcut Modification'
        mitre_detection_notes = 'Parse each LNK''s actual target and arguments (not just display name) and flag any pointing to a script interpreter with encoded arguments.'
        mitre_data_sources = @('File', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'persistence'
        default_reasoning = @('Shortcut files whose actual target diverges from their apparent purpose may indicate persistence or a delivery vector, independent of their displayed name/icon.')
        detection_logic = 'Static enumeration of .lnk files in persistence-relevant and recent-activity locations at collection time.'
        detection_threshold = 'n/a — every LNK found is captured; suspicion driven by target/argument inspection.'
        false_positive_notes = 'The vast majority of Recent-items LNKs are normal, auto-generated Windows shell artifacts from routine file access.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Parse each LNK''s real target and arguments, especially any found in the Startup folder.'; reason = 'Distinguishes normal recent-file tracking from a disguised persistence or delivery mechanism.' }
        )
        investigation_questions = @('Does any Startup-folder LNK''s real target diverge from a legitimate application?', 'Does any LNK''s target invoke a script interpreter with encoded or obfuscated arguments?')
        findingtags = @('persistence', 'malware', 'live-response')
    }
    "ps-history" = @{
        finding_type = 'PowerShell Command History'
        category = 'Execution'
        subcategory = 'Command History'
        title = 'PowerShell Command History'
        description = 'PowerShell command history recovered from PSReadLine''s persisted history file and the current session''s Get-History.'
        why_this_matters = 'PowerShell is the dominant living-off-the-land execution tool in modern intrusions; its command history is often a direct, literal record of attacker actions including downloaded tooling, credential-dumping commands, and lateral-movement attempts.'
        expected_normal_behaviour = 'Commands consistent with the user''s normal administrative or scripting workflow.'
        investigator_notes = 'Look specifically for encoded (-EncodedCommand/-enc) invocations, download cradles (IEX, Invoke-WebRequest, Net.WebClient), and commands referencing credential-dumping tools or LOLBins.'
        what_is_this = 'The persisted PSReadLine history file (ConsoleHost_history.txt) plus the live session''s Get-History output, both capturing literal commands the user or an attacker typed or scripted into PowerShell.'
        why_it_exists = 'PSReadLine persists command history across sessions to support up-arrow recall and search, independent of the transcript/logging features that may or may not be enabled.'
        normal_behaviour = 'Routine administrative, scripting, or troubleshooting commands consistent with the user''s role.'
        suspicious_behaviour = 'Encoded command invocations, download-and-execute cradles, references to credential-dumping utilities (Mimikatz, LaZagne), or commands disabling security controls.'
        common_attack_usage = 'Attackers using PowerShell for execution, discovery, credential access, or lateral movement leave a direct, literal record of their commands here unless they specifically clear or evade history logging.'
        mitre_technique_id = 'T1059.001'
        mitre_technique = 'Command and Scripting Interpreter: PowerShell'
        mitre_tactic = 'execution'
        mitre_sub_technique = 'PowerShell'
        mitre_detection_notes = 'Flag encoded command invocations, download cradles, and any reference to known offensive tooling or credential-dumping utilities.'
        mitre_data_sources = @('Command Execution', 'PowerShell Logs')
        base_risk_score = 15
        mitre_bucket = 'execution'
        default_reasoning = @('PowerShell command history may reveal attacker activity including encoded commands, download cradles, and use of offensive tooling.')
        detection_logic = 'Recovers persisted PSReadLine history and current session history at collection time; content is not filtered, full history is reported.'
        detection_threshold = 'n/a — every recovered command is captured; suspicion evaluated per-command during triage.'
        false_positive_notes = 'Legitimate admins and developers routinely use encoded commands and web-request cmdlets for benign automation.'
        recommendations = @(
            @{ priority = 'High'; action = 'Decode any -EncodedCommand invocation and review its actual payload.'; reason = 'Reveals the true command an attacker attempted to obscure from casual review.' }
        )
        investigation_questions = @('Does the history contain any encoded command, and what does it decode to?', 'Does the history reference known offensive tooling, credential-dumping utilities, or a download-and-execute cradle?')
        findingtags = @('malware', 'credential-access', 'live-response')
    }
    "new-files" = @{
        finding_type = 'Recently Created Executables'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Recently Created Executables'
        description = 'Executable and script files recently created in common user-writable and staging locations.'
        why_this_matters = 'A newly-dropped executable in a user-writable location is one of the most direct available signals of payload delivery or attacker tool staging.'
        expected_normal_behaviour = 'Installer temp files, browser/application updater downloads, and other explainable, short-lived executables.'
        investigator_notes = 'Correlate creation timestamps against other findings (process execution, browser downloads, network connections) to reconstruct exactly how and when the file arrived.'
        what_is_this = 'Executable and script files (.exe, .dll, .ps1, .bat, .vbs, etc.) whose creation time falls within a recent lookback window, gathered from common user-writable directories.'
        why_it_exists = 'File-system creation timestamps provide a direct, hard-to-fully-suppress record of when new code first appeared on the host.'
        normal_behaviour = 'Short-lived installer/updater temp files that are typically cleaned up automatically.'
        suspicious_behaviour = 'An executable in a user-writable directory with no corresponding legitimate installer/updater context, especially one with a name mimicking a system binary or a random/generic filename.'
        common_attack_usage = 'Initial-access payloads, second-stage tooling, and ransomware binaries are all delivered as newly-created executable files before being executed.'
        mitre_technique_id = 'T1105'
        mitre_technique = 'Ingress Tool Transfer'
        mitre_tactic = 'execution'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate new executable creation timestamps with process-execution and network-connection findings to establish delivery method.'
        mitre_data_sources = @('File', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'execution'
        default_reasoning = @('Recently created executables may indicate malware staging or delivery of attacker tooling to the endpoint.')
        detection_logic = 'Enumerates files matching executable/script extensions with a creation timestamp inside the collector''s recent lookback window.'
        detection_threshold = 'Lookback window is configurable in the collector; any match within it is reported.'
        false_positive_notes = 'Legitimate software installers and application self-updaters routinely create short-lived executables in these same locations.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate each new executable''s creation time with process-execution and network findings to establish origin.'; reason = 'Distinguishes benign installer activity from attacker payload delivery.' }
        )
        investigation_questions = @('Does each new executable correspond to a known, legitimate installer or update process?', 'Does the creation timestamp correlate with a suspicious network connection or download event?')
        findingtags = @('malware', 'ransomware', 'live-response')
    }
    "downloads" = @{
        finding_type = 'Executable Downloads'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Executable Downloads'
        description = 'Executable and script files found in the user''s Downloads folder(s).'
        why_this_matters = 'The Downloads folder is the single most common landing zone for both legitimate software acquisition and malicious payload delivery via phishing, drive-by, or social engineering.'
        expected_normal_behaviour = 'A small number of installers/utilities the user intentionally downloaded, consistent with their normal workflow.'
        investigator_notes = 'Correlate against browser history to identify exactly which URL each executable was downloaded from — a mismatch between the claimed source site and the file''s actual origin is a red flag.'
        what_is_this = 'Executable and script files present in the Downloads directory for each user profile on the host.'
        why_it_exists = 'Browsers default to saving downloaded files here, making it the natural first landing point for anything a user (or a drive-by/phishing page) causes to be downloaded.'
        normal_behaviour = 'A modest set of legitimate installers/utilities matching the user''s normal software-acquisition patterns.'
        suspicious_behaviour = 'An executable with a name mismatched to its claimed file type (e.g., ''Invoice.pdf.exe''), a file downloaded from an unfamiliar or flagged domain, or an unusually large number of executables downloaded in a short window.'
        common_attack_usage = 'Phishing and drive-by-download campaigns rely on the victim executing a malicious file placed directly in Downloads, often disguised with a double extension or a filename mimicking a document.'
        mitre_technique_id = 'T1105'
        mitre_technique = 'Ingress Tool Transfer'
        mitre_tactic = 'initial_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate downloaded executables against browser-history download-source URLs and flag double-extension or document-mimicking filenames.'
        mitre_data_sources = @('File', 'Network Traffic')
        base_risk_score = 30
        mitre_bucket = 'execution'
        default_reasoning = @('Executables in the Downloads folder may represent user-initiated or phishing/drive-by-delivered malicious payloads.')
        detection_logic = 'Enumerates executable and script files present in each user''s Downloads directory at collection time.'
        detection_threshold = 'n/a — every matching file is captured; suspicion evaluated per-file during triage.'
        false_positive_notes = 'Most files here are legitimate, intentionally-downloaded software installers and utilities.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate each executable against browser history to confirm its download source.'; reason = 'Confirms whether the file was delivered via phishing/drive-by or legitimately acquired by the user.' }
        )
        investigation_questions = @('Does the filename use a double extension or otherwise mimic a document to disguise its true type?', 'What browser-history entry corresponds to this file''s download, and is that source domain trustworthy?')
        findingtags = @('malware', 'live-response')
    }
    "hidden-execs-temp" = @{
        finding_type = 'Executables in the Temp Folder'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Executables in the Temp Folder'
        description = 'Executable and script files found in the Temp Folder, a location not typically used to launch legitimate software.'
        why_this_matters = 'the Temp Folder is rarely a legitimate execution location for installed software, so an executable here is disproportionately likely to reflect attacker staging or unusual, deliberately-hidden activity.'
        expected_normal_behaviour = 'Little to no executable content in the Temp Folder under normal use.'
        investigator_notes = 'Treat any hit here with more suspicion than an equivalent file in Downloads, precisely because this location has fewer legitimate reasons to contain executables.'
        what_is_this = 'Executable and script files discovered under the Temp Folder during the collector''s file-system sweep.'
        why_it_exists = 'the Temp Folder exists for its documented OS/application purpose (temporary files, performance logs, or user documents), none of which normally involve hosting executable code.'
        normal_behaviour = 'Empty or containing only expected, non-executable content for the Temp Folder''s documented purpose.'
        suspicious_behaviour = 'Any executable or script present at all, particularly one with a randomized or generic filename.'
        common_attack_usage = 'Attackers stage payloads in less-monitored, less-expected locations like the Temp Folder specifically because analysts and default AV heuristics focus more scrutiny on Downloads/Desktop/Temp.'
        mitre_technique_id = 'T1036.005'
        mitre_technique = 'Masquerading: Match Legitimate Name or Location'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Match Legitimate Name or Location'
        mitre_detection_notes = 'Any executable found under the Temp Folder should be treated as high-priority given how rarely this location legitimately hosts executable content.'
        mitre_data_sources = @('File', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Executables in the Temp Folder are unusual and disproportionately likely to reflect deliberate attacker staging in a less-scrutinized location.')
        detection_logic = 'Enumerates executable and script files found under the Temp Folder at collection time.'
        detection_threshold = 'n/a — any match in this location is inherently notable given how rarely it legitimately hosts executables.'
        false_positive_notes = 'A small number of applications legitimately use these paths for temp/cache executables during install or update; verify against the specific vendor/process before concluding malice.'
        recommendations = @(
            @{ priority = 'High'; action = 'Submit any executable found here for hash reputation lookup and/or sandbox analysis.'; reason = 'Confirms or rules out malicious content staged in a deliberately low-visibility location.' }
        )
        investigation_questions = @('Is there a documented, legitimate reason for an executable to exist in the Temp Folder on this host?', 'Does the file''s hash match any known-malicious indicator?')
        findingtags = @('malware', 'live-response')
    }
    "hidden-execs-ctemp" = @{
        finding_type = 'Executables in C:\Temp'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Executables in C:\Temp'
        description = 'Executable and script files found in C:\Temp, a location not typically used to launch legitimate software.'
        why_this_matters = 'C:\Temp is rarely a legitimate execution location for installed software, so an executable here is disproportionately likely to reflect attacker staging or unusual, deliberately-hidden activity.'
        expected_normal_behaviour = 'Little to no executable content in C:\Temp under normal use.'
        investigator_notes = 'Treat any hit here with more suspicion than an equivalent file in Downloads, precisely because this location has fewer legitimate reasons to contain executables.'
        what_is_this = 'Executable and script files discovered under C:\Temp during the collector''s file-system sweep.'
        why_it_exists = 'C:\Temp exists for its documented OS/application purpose (temporary files, performance logs, or user documents), none of which normally involve hosting executable code.'
        normal_behaviour = 'Empty or containing only expected, non-executable content for C:\Temp''s documented purpose.'
        suspicious_behaviour = 'Any executable or script present at all, particularly one with a randomized or generic filename.'
        common_attack_usage = 'Attackers stage payloads in less-monitored, less-expected locations like C:\Temp specifically because analysts and default AV heuristics focus more scrutiny on Downloads/Desktop/Temp.'
        mitre_technique_id = 'T1036.005'
        mitre_technique = 'Masquerading: Match Legitimate Name or Location'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Match Legitimate Name or Location'
        mitre_detection_notes = 'Any executable found under C:\Temp should be treated as high-priority given how rarely this location legitimately hosts executable content.'
        mitre_data_sources = @('File', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Executables in C:\Temp are unusual and disproportionately likely to reflect deliberate attacker staging in a less-scrutinized location.')
        detection_logic = 'Enumerates executable and script files found under C:\Temp at collection time.'
        detection_threshold = 'n/a — any match in this location is inherently notable given how rarely it legitimately hosts executables.'
        false_positive_notes = 'A small number of applications legitimately use these paths for temp/cache executables during install or update; verify against the specific vendor/process before concluding malice.'
        recommendations = @(
            @{ priority = 'High'; action = 'Submit any executable found here for hash reputation lookup and/or sandbox analysis.'; reason = 'Confirms or rules out malicious content staged in a deliberately low-visibility location.' }
        )
        investigation_questions = @('Is there a documented, legitimate reason for an executable to exist in C:\Temp on this host?', 'Does the file''s hash match any known-malicious indicator?')
        findingtags = @('malware', 'live-response')
    }
    "hidden-execs-perflogs" = @{
        finding_type = 'Executables in C:\PerfLogs'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Executables in C:\PerfLogs'
        description = 'Executable and script files found in C:\PerfLogs, a location not typically used to launch legitimate software.'
        why_this_matters = 'C:\PerfLogs is rarely a legitimate execution location for installed software, so an executable here is disproportionately likely to reflect attacker staging or unusual, deliberately-hidden activity.'
        expected_normal_behaviour = 'Little to no executable content in C:\PerfLogs under normal use.'
        investigator_notes = 'Treat any hit here with more suspicion than an equivalent file in Downloads, precisely because this location has fewer legitimate reasons to contain executables.'
        what_is_this = 'Executable and script files discovered under C:\PerfLogs during the collector''s file-system sweep.'
        why_it_exists = 'C:\PerfLogs exists for its documented OS/application purpose (temporary files, performance logs, or user documents), none of which normally involve hosting executable code.'
        normal_behaviour = 'Empty or containing only expected, non-executable content for C:\PerfLogs''s documented purpose.'
        suspicious_behaviour = 'Any executable or script present at all, particularly one with a randomized or generic filename.'
        common_attack_usage = 'Attackers stage payloads in less-monitored, less-expected locations like C:\PerfLogs specifically because analysts and default AV heuristics focus more scrutiny on Downloads/Desktop/Temp.'
        mitre_technique_id = 'T1036.005'
        mitre_technique = 'Masquerading: Match Legitimate Name or Location'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Match Legitimate Name or Location'
        mitre_detection_notes = 'Any executable found under C:\PerfLogs should be treated as high-priority given how rarely this location legitimately hosts executable content.'
        mitre_data_sources = @('File', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Executables in C:\PerfLogs are unusual and disproportionately likely to reflect deliberate attacker staging in a less-scrutinized location.')
        detection_logic = 'Enumerates executable and script files found under C:\PerfLogs at collection time.'
        detection_threshold = 'n/a — any match in this location is inherently notable given how rarely it legitimately hosts executables.'
        false_positive_notes = 'A small number of applications legitimately use these paths for temp/cache executables during install or update; verify against the specific vendor/process before concluding malice.'
        recommendations = @(
            @{ priority = 'High'; action = 'Submit any executable found here for hash reputation lookup and/or sandbox analysis.'; reason = 'Confirms or rules out malicious content staged in a deliberately low-visibility location.' }
        )
        investigation_questions = @('Is there a documented, legitimate reason for an executable to exist in C:\PerfLogs on this host?', 'Does the file''s hash match any known-malicious indicator?')
        findingtags = @('malware', 'live-response')
    }
    "hidden-execs-docs" = @{
        finding_type = 'Executables in User Documents'
        category = 'Execution'
        subcategory = 'File System'
        title = 'Executables in User Documents'
        description = 'Executable and script files found in User Documents, a location not typically used to launch legitimate software.'
        why_this_matters = 'User Documents is rarely a legitimate execution location for installed software, so an executable here is disproportionately likely to reflect attacker staging or unusual, deliberately-hidden activity.'
        expected_normal_behaviour = 'Little to no executable content in User Documents under normal use.'
        investigator_notes = 'Treat any hit here with more suspicion than an equivalent file in Downloads, precisely because this location has fewer legitimate reasons to contain executables.'
        what_is_this = 'Executable and script files discovered under User Documents during the collector''s file-system sweep.'
        why_it_exists = 'User Documents exists for its documented OS/application purpose (temporary files, performance logs, or user documents), none of which normally involve hosting executable code.'
        normal_behaviour = 'Empty or containing only expected, non-executable content for User Documents''s documented purpose.'
        suspicious_behaviour = 'Any executable or script present at all, particularly one with a randomized or generic filename.'
        common_attack_usage = 'Attackers stage payloads in less-monitored, less-expected locations like User Documents specifically because analysts and default AV heuristics focus more scrutiny on Downloads/Desktop/Temp.'
        mitre_technique_id = 'T1036.005'
        mitre_technique = 'Masquerading: Match Legitimate Name or Location'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = 'Match Legitimate Name or Location'
        mitre_detection_notes = 'Any executable found under User Documents should be treated as high-priority given how rarely this location legitimately hosts executable content.'
        mitre_data_sources = @('File', 'Command Execution')
        base_risk_score = 35
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Executables in User Documents are unusual and disproportionately likely to reflect deliberate attacker staging in a less-scrutinized location.')
        detection_logic = 'Enumerates executable and script files found under User Documents at collection time.'
        detection_threshold = 'n/a — any match in this location is inherently notable given how rarely it legitimately hosts executables.'
        false_positive_notes = 'A small number of applications legitimately use these paths for temp/cache executables during install or update; verify against the specific vendor/process before concluding malice.'
        recommendations = @(
            @{ priority = 'High'; action = 'Submit any executable found here for hash reputation lookup and/or sandbox analysis.'; reason = 'Confirms or rules out malicious content staged in a deliberately low-visibility location.' }
        )
        investigation_questions = @('Is there a documented, legitimate reason for an executable to exist in User Documents on this host?', 'Does the file''s hash match any known-malicious indicator?')
        findingtags = @('malware', 'live-response')
    }
    "browser-history" = @{
        finding_type = 'Browser History'
        category = 'Collection'
        subcategory = 'Browser Artifacts'
        title = 'Browser History'
        description = 'Browsing history collected from all supported browsers (Chrome/Edge/Brave/Opera/Firefox/IE) across all user profiles.'
        why_this_matters = 'Browser history reveals attacker reconnaissance, phishing sites visited, tool-download sources, and C2 panel access — and is directly cross-referenced against threat intel in this collector''s own IOC-matching pipeline.'
        expected_normal_behaviour = 'Browsing consistent with the user''s normal work and personal use.'
        investigator_notes = 'This finding''s malicious_hits count is populated directly from the IOC URL matching pipeline — a non-zero count here is a strong, corroborated signal, not a guess.'
        what_is_this = 'URL, title, visit count, and last-visit-time history extracted from each browser''s local history database (SQLite for Chromium/Firefox, registry TypedURLs for IE).'
        why_it_exists = 'Browsers persist history locally to power autocomplete and the user''s own back-navigation/history features.'
        normal_behaviour = 'History consistent with the user''s normal work and personal browsing patterns.'
        suspicious_behaviour = 'Visits to known-malicious or newly-registered domains, C2 panel-style URLs, or paste-site/file-sharing URLs associated with tool download or data exfiltration.'
        common_attack_usage = 'Both attacker recon (checking IP reputation sites, searching for exploits) and victim-side compromise (phishing link clicks, drive-by download pages) leave a direct trace in browser history.'
        mitre_technique_id = 'T1217'
        mitre_technique = 'Browser Information Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Cross-reference every URL against current threat intelligence feeds; the collector already performs this via its IOC hit pipeline.'
        mitre_data_sources = @('Browser Extensions', 'Application Log', 'File')
        base_risk_score = 8
        mitre_bucket = 'impact'
        default_reasoning = @('Browser history can reveal attacker recon, C2 communication, phishing sites visited, and data exfiltration destinations; malicious URL hits confirm IOC contact.')
        detection_logic = 'Extracts full browsing history from every supported browser profile at collection time; malicious hits are separately flagged by the collector''s IOC matching pipeline.'
        detection_threshold = 'n/a — full history is captured; the ioc-url finding carries the threshold-based malicious-match logic.'
        false_positive_notes = 'The overwhelming majority of history entries are routine, benign browsing unrelated to any investigation.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Review the correlated ioc-url finding for confirmed malicious-URL matches within this history.'; reason = 'Focuses review on the subset of history already confirmed against threat intelligence.' }
        )
        investigation_questions = @('Does the history show visits to any domain on a current threat intelligence blocklist?', 'Does browsing activity immediately precede a suspicious download or new-executable finding?')
        findingtags = @('insider-threat', 'data-exfiltration', 'malware', 'live-response')
    }
    "group-enum" = @{
        finding_type = 'Group Membership Enumeration'
        category = 'Discovery'
        subcategory = 'Group Membership'
        title = 'Group Membership Enumeration'
        description = 'Enumeration of local and domain group memberships relevant to the host and current user context.'
        why_this_matters = 'Attackers routinely enumerate group membership early in an intrusion to identify privilege-escalation and lateral-movement targets; the presence of this activity itself, and its results, both matter.'
        expected_normal_behaviour = 'Standard group memberships consistent with the user''s documented role.'
        investigator_notes = 'If this enumeration reflects a live attacker action (rather than the collector''s own baseline query), correlate with process-execution findings for tools like net.exe, whoami /groups, or PowerShell AD cmdlets.'
        what_is_this = 'A structured view of group memberships for local and domain-relevant groups, supporting both baseline documentation and comparison against expected role-based access.'
        why_it_exists = 'Group membership determines effective privilege; enumerating it is necessary both for legitimate administration and for attacker targeting decisions.'
        normal_behaviour = 'Membership consistent with the user''s documented role and least-privilege expectations.'
        suspicious_behaviour = 'Membership in privileged groups inconsistent with the user''s documented role.'
        common_attack_usage = 'Group enumeration (via net group, PowerShell AD cmdlets, or BloodHound-style collectors) is a standard early-stage discovery action attackers perform to map privilege-escalation and lateral-movement paths.'
        mitre_technique_id = 'T1069.001'
        mitre_technique = 'Permission Groups Discovery: Local Groups'
        mitre_tactic = 'discovery'
        mitre_sub_technique = 'Local Groups'
        mitre_detection_notes = 'Correlate with process-execution findings for group/AD enumeration tooling (net.exe, dsquery, PowerShell AD/BloodHound cmdlets).'
        mitre_data_sources = @('User Account', 'Active Directory')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Group membership enumeration results help confirm whether privileged access is consistent with the user''s documented role.')
        detection_logic = 'Static enumeration of relevant group memberships at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Documented role-based access changes over time; validate against current HR/IT records rather than assuming staleness indicates compromise.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm privileged group memberships against the user''s current, documented role.'; reason = 'Identifies unauthorized privilege beyond what the role requires.' }
        )
        investigation_questions = @('Is any privileged group membership inconsistent with the user''s documented role?')
        findingtags = @('live-response')
    }
    "usb-devices" = @{
        finding_type = 'USB Devices'
        category = 'External Device'
        subcategory = 'Removable Storage'
        title = 'USB Devices'
        description = 'Currently and previously connected USB devices, from the plug-and-play device registry.'
        why_this_matters = 'USB storage is one of the most direct data-exfiltration and malware-introduction vectors that completely bypasses network-based controls.'
        expected_normal_behaviour = 'A small set of known, approved peripherals (keyboard, mouse, approved storage) consistent with the user''s role.'
        investigator_notes = 'Correlate device-connect timestamps against file-access and object-access findings to determine what, if anything, was copied to or from the device.'
        what_is_this = 'USB device connection history from the registry''s Enum\USBSTOR and related keys, including device serial numbers and first/last-connected times.'
        why_it_exists = 'Windows records every USB device ever connected (with vendor/product/serial identifiers) to support driver matching on reconnection, which incidentally creates a durable connection history.'
        normal_behaviour = 'Devices matching the user''s known, approved peripherals.'
        suspicious_behaviour = 'An unfamiliar storage device connected shortly before or after other suspicious activity (mass file access, ransomware indicators, insider-threat behavior).'
        common_attack_usage = 'Insider threats use USB storage to exfiltrate sensitive data directly, and it remains a classic initial-infection vector (e.g., an intentionally-dropped malicious USB drive).'
        mitre_technique_id = 'T1091'
        mitre_technique = 'Replication Through Removable Media'
        mitre_tactic = 'initial_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate USB connect timestamps with file-copy and object-access activity in the surrounding time window.'
        mitre_data_sources = @('Drive', 'Windows Registry')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('USB device connection history may reveal data exfiltration via removable storage or a malicious device used for initial infection.')
        detection_logic = 'Static enumeration of USB device connection history from the registry at collection time.'
        detection_threshold = 'n/a — every recorded device is captured; suspicion driven by correlation with surrounding activity.'
        false_positive_notes = 'Approved peripherals and storage devices used for legitimate business purposes will also appear here.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate USB connect times with file-access activity to determine what, if anything, was transferred.'; reason = 'Confirms or rules out data exfiltration via removable media.' }
        )
        investigation_questions = @('Is every connected device accounted for as an approved peripheral?', 'Does any device connection correlate in time with mass file access or other suspicious activity?')
        findingtags = @('data-exfiltration', 'insider-threat', 'live-response')
    }
    "image-devices" = @{
        finding_type = 'Imaging Devices'
        category = 'External Device'
        subcategory = 'Peripheral Devices'
        title = 'Imaging Devices'
        description = 'Cameras, scanners, and other imaging-class devices that have connected to the host.'
        why_this_matters = 'Imaging devices are a less common but real exfiltration vector (photographing screens/documents) and are also relevant to physical/insider-threat scenarios.'
        expected_normal_behaviour = 'No imaging devices, or a small set of approved peripherals for the user''s role (e.g., a scanner in a shared office).'
        investigator_notes = 'Primarily relevant in insider-threat or physical-security-adjacent investigations rather than typical malware/intrusion cases.'
        what_is_this = 'Imaging-class plug-and-play devices (webcams, scanners, card readers with imaging capability) recorded in the device registry.'
        why_it_exists = 'Windows tracks all plug-and-play device connections, including imaging-class devices, for driver management purposes.'
        normal_behaviour = 'No devices, or only approved peripherals matching the user''s role.'
        suspicious_behaviour = 'An unfamiliar imaging device connected around the time of a suspected insider-threat incident.'
        common_attack_usage = 'Rare as a direct attack vector, but relevant to insider-threat scenarios (photographing sensitive on-screen data to bypass DLP controls entirely).'
        mitre_technique_id = 'T1125'
        mitre_technique = 'Video Capture'
        mitre_tactic = 'collection'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate connection times against insider-threat-relevant activity windows.'
        mitre_data_sources = @('Drive', 'Windows Registry')
        base_risk_score = 15
        mitre_bucket = 'impact'
        default_reasoning = @('Imaging device connections are uncommon and may be relevant to insider-threat scenarios involving physical capture of sensitive data.')
        detection_logic = 'Static enumeration of imaging-class device connection history from the registry at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'Legitimate scanners/webcams for approved business use will also appear here.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Confirm any unfamiliar imaging device against the user''s approved peripheral list.'; reason = 'Rules out an undocumented device relevant to insider-threat scenarios.' }
        )
        investigation_questions = @('Is any imaging device unaccounted for by the user''s approved peripheral list?')
        findingtags = @('insider-threat', 'live-response')
    }
    "upnp-devices" = @{
        finding_type = 'Connected PnP Devices'
        category = 'External Device'
        subcategory = 'Peripheral Devices'
        title = 'Connected PnP Devices'
        description = 'All plug-and-play devices currently or previously connected to the host, beyond the USB-storage-specific finding.'
        why_this_matters = 'A broader device inventory can surface unexpected hardware (network adapters, HID devices used for BadUSB-style attacks) that the more specific USB-storage finding wouldn''t capture.'
        expected_normal_behaviour = 'Standard internal hardware plus the user''s known approved peripherals.'
        investigator_notes = 'A HID (keyboard/mouse-class) device with an unusual vendor ID connecting shortly before suspicious keyboard-driven activity can indicate a BadUSB-style attack.'
        what_is_this = 'The general plug-and-play device inventory from Get-PnpDevice, covering all device classes beyond storage-specific USB history.'
        why_it_exists = 'Windows maintains a unified device registry across all device classes to manage drivers regardless of device type.'
        normal_behaviour = 'Devices matching the host''s known hardware and the user''s approved peripherals.'
        suspicious_behaviour = 'An unfamiliar HID-class device, particularly one connecting shortly before anomalous rapid keystroke/command activity consistent with an automated BadUSB payload.'
        common_attack_usage = 'BadUSB-style attacks present as a HID device (keyboard) that types a malicious command sequence automatically the moment it''s plugged in.'
        mitre_technique_id = 'T1120'
        mitre_technique = 'Peripheral Device Discovery'
        mitre_tactic = 'discovery'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag unfamiliar HID-class devices and correlate their connection time with immediately-following command execution.'
        mitre_data_sources = @('Drive', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'execution'
        default_reasoning = @('Broader plug-and-play device inventory may surface unexpected HID devices consistent with BadUSB-style attacks.')
        detection_logic = 'Static enumeration of all plug-and-play devices at collection time.'
        detection_threshold = 'n/a — informational inventory.'
        false_positive_notes = 'The bulk of entries are internal hardware and legitimate peripherals irrelevant to any investigation.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Correlate any unfamiliar HID-class device''s connection time with immediately-following command execution.'; reason = 'Identifies BadUSB-style automated-keystroke attacks.' }
        )
        investigation_questions = @('Is there an unfamiliar HID-class device, and does its connection correlate with subsequent rapid command execution?')
        findingtags = @('live-response')
    }
    "unknown-drives" = @{
        finding_type = 'Historical USB Storage Devices'
        category = 'External Device'
        subcategory = 'Removable Storage'
        title = 'Historical USB Storage Devices'
        description = 'USB storage devices that have connected historically but are no longer currently attached, recovered from registry and setupapi log artifacts.'
        why_this_matters = 'This recovers evidence of removable storage a user or attacker may have deliberately disconnected and hidden — exactly the kind of artifact relevant to a deliberate data-exfiltration attempt.'
        expected_normal_behaviour = 'A documented history of approved storage devices used over time.'
        investigator_notes = 'Cross-reference serial numbers against any device the organization has issued or approved, and against any device recovered during a physical evidence collection.'
        what_is_this = 'Historical USB mass-storage connection records recovered from the SYSTEM registry hive (USBSTOR) and setupapi.dev.log, independent of whether the device is currently attached.'
        why_it_exists = 'Windows retains device installation history in the registry and setup logs long after a device is physically disconnected, to support driver reinstallation on reconnection.'
        normal_behaviour = 'Historical devices matching the organization''s approved storage device inventory.'
        suspicious_behaviour = 'An unfamiliar device with no corresponding approval record, particularly one whose connection window overlaps with a suspected exfiltration incident.'
        common_attack_usage = 'An insider or attacker who used USB storage to exfiltrate data and then removed the device relies on this history being overlooked — this finding specifically recovers that evidence.'
        mitre_technique_id = 'T1052.001'
        mitre_technique = 'Exfiltration Over Physical Medium: Exfiltration over USB'
        mitre_tactic = 'exfiltration'
        mitre_sub_technique = 'Exfiltration over USB'
        mitre_detection_notes = 'Cross-reference recovered device serial numbers against the organization''s approved/issued device inventory.'
        mitre_data_sources = @('Drive', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('Historical USB storage device records may reveal a data-exfiltration device the user or attacker later physically disconnected.')
        detection_logic = 'Recovers historical USB mass-storage connection records from the registry and setupapi logs at collection time, independent of current attachment state.'
        detection_threshold = 'n/a — every recovered historical record is captured; suspicion driven by correlation with the investigation timeline.'
        false_positive_notes = 'Most historical devices reflect ordinary, approved past use of removable storage.'
        recommendations = @(
            @{ priority = 'High'; action = 'Cross-reference every historical device against the organization''s approved/issued inventory.'; reason = 'Identifies an unapproved device potentially used for exfiltration.' }
        )
        investigation_questions = @('Is every historical device accounted for in the organization''s approved inventory?', 'Does any device''s connection window overlap with the suspected incident timeframe?')
        findingtags = @('data-exfiltration', 'insider-threat', 'live-response')
    }
    "rdp-logins" = @{
        finding_type = 'RDP Login Events'
        category = 'Lateral Movement'
        subcategory = 'Remote Desktop'
        title = 'RDP Login Events'
        description = 'Successful RDP logon events recorded on the host.'
        why_this_matters = 'RDP remains one of the most common lateral-movement and remote-access vectors used by attackers, both for interactive hands-on-keyboard activity and ransomware deployment.'
        expected_normal_behaviour = 'Logons from expected administrative sources during expected hours, consistent with documented remote-access policy.'
        investigator_notes = 'Cross-reference the source IP/hostname against the host''s known-good administrative source list, and check for logons outside business hours.'
        what_is_this = 'Successful RDP logon events recorded in the Security and TerminalServices event logs.'
        why_it_exists = 'Windows logs RDP logon activity to provide an audit trail of remote interactive access.'
        normal_behaviour = 'Logons from documented administrative sources during expected hours.'
        suspicious_behaviour = 'A logon from an unfamiliar source IP/host, an account not expected to use RDP, or a logon occurring outside business hours.'
        common_attack_usage = 'Attackers who obtain valid credentials frequently use RDP directly for hands-on-keyboard lateral movement, and many ransomware operators deploy their payload via an RDP session established with stolen or brute-forced credentials.'
        mitre_technique_id = 'T1021.001'
        mitre_technique = 'Remote Services: Remote Desktop Protocol'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = 'Remote Desktop Protocol'
        mitre_detection_notes = 'Flag RDP logons from source IPs outside the documented administrative range, and any logon occurring outside business hours.'
        mitre_data_sources = @('Logon Session', 'Windows Registry')
        base_risk_score = 30
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('RDP login events reveal all remote interactive sessions including those established by an attacker using stolen or brute-forced credentials.')
        detection_logic = 'Enumerates successful RDP logon events recorded on the host within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-logon.'
        false_positive_notes = 'IT/helpdesk staff performing legitimate remote support will also generate this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the source IP/host and account for each logon against documented administrative access policy.'; reason = 'Distinguishes legitimate remote administration from attacker lateral movement via RDP.' }
        )
        investigation_questions = @('Is the source IP/host for each logon on the documented administrative access list?', 'Did any logon occur outside business hours or from an account that doesn''t normally use RDP?')
        findingtags = @('lateral-movement', 'live-response')
    }
    "rdp-auths" = @{
        finding_type = 'RDP Authentication History'
        category = 'Lateral Movement'
        subcategory = 'Remote Desktop'
        title = 'RDP Authentication History'
        description = 'RDP authentication events (event 1149) recorded by the TerminalServices-RemoteConnectionManager operational log, including client IP and domain/user.'
        why_this_matters = 'This log specifically captures the network-layer authentication step of an RDP connection, providing corroborating source-IP detail that complements the Security-log RDP logon events.'
        expected_normal_behaviour = 'Authentication events matching the documented administrative access sources.'
        investigator_notes = 'Use this alongside the rdp-logins finding — event 1149 fires slightly earlier in the connection sequence and reliably captures the client''s source IP even in configurations where the Security log logon event''s source data is less complete.'
        what_is_this = 'Event ID 1149 from Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational, logged when a client successfully authenticates for an RDP session.'
        why_it_exists = 'Provides a dedicated, connection-manager-level audit trail of RDP authentication independent of the general Security event log.'
        normal_behaviour = 'Authentication events from documented administrative sources.'
        suspicious_behaviour = 'Authentication from an unfamiliar client IP or domain/user combination, especially inconsistent with the documented administrative access list.'
        common_attack_usage = 'Corroborates attacker RDP-based lateral movement or remote access with reliable source-IP evidence, useful when other logon-source data is incomplete.'
        mitre_technique_id = 'T1021.001'
        mitre_technique = 'Remote Services: Remote Desktop Protocol'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = 'Remote Desktop Protocol'
        mitre_detection_notes = 'Flag authentication events from client IPs outside the documented administrative range.'
        mitre_data_sources = @('Logon Session', 'Windows Registry')
        base_risk_score = 25
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('RDP authentication history reveals all remote sessions including those by attackers, with reliable source-IP evidence.')
        detection_logic = 'Enumerates event 1149 records from the TerminalServices-RemoteConnectionManager operational log within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'IT/helpdesk staff performing legitimate remote support will also generate this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the client IP for each authentication event against documented administrative access policy.'; reason = 'Corroborates or rules out attacker RDP-based access using reliable source-IP evidence.' }
        )
        investigation_questions = @('Is the client IP for each authentication event on the documented administrative access list?')
        findingtags = @('lateral-movement', 'credential-access', 'live-response')
    }
    "outgoing-rdp" = @{
        finding_type = 'Outgoing RDP Connections'
        category = 'Lateral Movement'
        subcategory = 'Remote Desktop'
        title = 'Outgoing RDP Connections'
        description = 'RDP client connection events (event 1102) showing this host initiating outbound RDP sessions to other hosts.'
        why_this_matters = 'Shows this host being used as a source for RDP-based lateral movement, which is exactly the behavior expected if this host is an attacker''s current foothold pivoting deeper into the environment.'
        expected_normal_behaviour = 'Outbound connections limited to documented administrative use (e.g., an IT admin''s workstation connecting to servers they manage).'
        investigator_notes = 'A non-admin user''s workstation showing outbound RDP connections to other hosts is a strong lateral-movement indicator warranting immediate follow-up.'
        what_is_this = 'Event ID 1102 from Microsoft-Windows-TerminalServices-RDPClient/Operational, logged when this host''s RDP client establishes an outbound connection.'
        why_it_exists = 'Provides an audit trail of this host''s own outbound RDP client activity, complementing the inbound-focused logon/authentication findings.'
        normal_behaviour = 'Outbound connections limited to documented administrative workflows.'
        suspicious_behaviour = 'Outbound RDP from a host/account with no documented administrative reason to initiate remote sessions to other machines.'
        common_attack_usage = 'Attackers who have compromised a host frequently use it as a pivot point, initiating outbound RDP to move laterally deeper into the environment — this finding directly evidences that behavior from the source side.'
        mitre_technique_id = 'T1021.001'
        mitre_technique = 'Remote Services: Remote Desktop Protocol'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = 'Remote Desktop Protocol'
        mitre_detection_notes = 'Flag outbound RDP connections from hosts/accounts with no documented administrative reason to initiate them.'
        mitre_data_sources = @('Logon Session', 'Network Traffic')
        base_risk_score = 35
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Outgoing RDP connections from endpoints indicate potential lateral movement or attacker pivoting deeper into the environment.')
        detection_logic = 'Enumerates event 1102 records from the TerminalServices-RDPClient operational log within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'IT administrators managing servers via RDP from their workstation will generate this event as routine, legitimate activity.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the account and target host for each outbound connection against documented administrative duties.'; reason = 'Distinguishes legitimate administration from attacker pivoting.' }
        )
        investigation_questions = @('Does the account initiating each outbound RDP connection have a documented administrative reason to do so?', 'Does the target host correlate with other lateral-movement indicators in the investigation?')
        findingtags = @('lateral-movement', 'live-response')
    }
    "created-users" = @{
        finding_type = 'User Creation Events'
        category = 'Persistence'
        subcategory = 'Account Lifecycle'
        title = 'User Creation Events'
        description = 'Event log records (4720) of new local or domain user accounts being created on/via this host.'
        why_this_matters = 'Account creation is a direct, unambiguous persistence action — unlike most findings that require interpretation, a 4720 event for an unrecognized account is close to definitive evidence.'
        expected_normal_behaviour = 'Creation events tied to documented IT provisioning activity.'
        investigator_notes = 'Immediately cross-reference the creating account (the ''Subject'' in the event) — if it''s not a known IT/admin account, this is a high-confidence attacker action.'
        what_is_this = 'Windows Security event 4720 (A user account was created), captured from the Security event log.'
        why_it_exists = 'Windows audits account-management operations to provide traceability over who created which account and when.'
        normal_behaviour = 'Creation events matching documented IT provisioning workflows.'
        suspicious_behaviour = 'A creation event with no corresponding IT provisioning record, or one performed by an account not authorized to create users.'
        common_attack_usage = 'Creating a new local or domain account is one of the most direct and durable persistence techniques, giving an attacker standing access independent of whatever initial-access vector was used.'
        mitre_technique_id = 'T1136.001'
        mitre_technique = 'Create Account: Local Account'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Local Account'
        mitre_detection_notes = 'Flag any 4720 event whose subject account is not a known, authorized IT/admin account.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 45
        mitre_bucket = 'persistence'
        default_reasoning = @('User account creation is a direct, high-confidence persistence action when performed by an unauthorized or unexpected account.')
        detection_logic = 'Enumerates event 4720 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'IT provisioning of new employee/contractor accounts is a routine, legitimate source of this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the creating account and the new account against documented IT provisioning records.'; reason = 'Confirms or rules out attacker-created persistence accounts.' }
        )
        investigation_questions = @('Is the account creation tied to a documented IT provisioning request?', 'Was the creating account authorized to create new users?')
        findingtags = @('insider-threat', 'persistence', 'live-response')
    }
    "pass-reset" = @{
        finding_type = 'Password Reset Events'
        category = 'Credential Access'
        subcategory = 'Account Lifecycle'
        title = 'Password Reset Events'
        description = 'Event log records of password reset/change operations performed on local or domain accounts via this host.'
        why_this_matters = 'Attackers reset an account''s password to lock out the legitimate owner and secure exclusive control, or to establish access to an account they''ve compromised via another route.'
        expected_normal_behaviour = 'Reset events tied to documented helpdesk/self-service password-reset activity.'
        investigator_notes = 'A password reset immediately followed by unusual logon activity for the same account is a strong account-takeover pattern.'
        what_is_this = 'Windows Security event(s) recording password reset/change operations, captured from the Security event log.'
        why_it_exists = 'Windows audits credential-management operations to provide traceability over account security-relevant changes.'
        normal_behaviour = 'Reset events matching documented helpdesk or self-service password-reset workflows.'
        suspicious_behaviour = 'A reset with no corresponding helpdesk ticket, performed by an unexpected account, or immediately followed by anomalous logon activity for the target account.'
        common_attack_usage = 'Resetting a target account''s password is a common step for both locking out the legitimate user (denial/disruption) and securing durable control over a compromised or newly-created account.'
        mitre_technique_id = 'T1098'
        mitre_technique = 'Account Manipulation'
        mitre_tactic = 'persistence'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate password reset events with subsequent logon activity for the same account to detect account-takeover patterns.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 45
        mitre_bucket = 'credential_access'
        default_reasoning = @('Password reset events may indicate an attacker securing control over a compromised account or locking out its legitimate owner.')
        detection_logic = 'Enumerates password reset/change event records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'Legitimate helpdesk-assisted and self-service password resets are a routine, frequent source of this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the reset against a documented helpdesk ticket, and check for anomalous logon activity immediately after.'; reason = 'Confirms or rules out an account-takeover pattern.' }
        )
        investigation_questions = @('Is the reset tied to a documented helpdesk ticket or legitimate self-service request?', 'Did anomalous logon activity for the target account follow immediately after the reset?')
        findingtags = @('credential-access', 'live-response')
    }
    "enabled-users" = @{
        finding_type = 'User Account Enabled Events'
        category = 'Persistence'
        subcategory = 'Account Lifecycle'
        title = 'User Account Enabled Events'
        description = 'Event log records (4722) of a previously-disabled user account being re-enabled.'
        why_this_matters = 'Re-enabling a dormant account (especially a stale, forgotten, or default account) is a stealthy persistence technique — it avoids the higher-visibility action of creating a brand-new account.'
        expected_normal_behaviour = 'Enable events tied to documented offboarding-reversal or role-change IT actions.'
        investigator_notes = 'Cross-reference the enabled account against the user-profiles and local-users findings for signs of a long-dormant, previously-forgotten account.'
        what_is_this = 'Windows Security event 4722 (A user account was enabled), captured from the Security event log.'
        why_it_exists = 'Windows audits account-state changes to provide traceability over who enabled a previously-disabled account and when.'
        normal_behaviour = 'Enable events matching documented IT role-change or rehire workflows.'
        suspicious_behaviour = 'Re-enabling of a long-dormant, default, or otherwise unexpected account with no documented IT justification.'
        common_attack_usage = 'Attackers re-enable a disabled but still-privileged built-in or legacy account as a lower-visibility alternative to creating a brand-new account, since a dormant existing account may draw less scrutiny.'
        mitre_technique_id = 'T1098'
        mitre_technique = 'Account Manipulation'
        mitre_tactic = 'persistence'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any 4722 event for a default, service, or otherwise long-dormant account without a documented IT justification.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 40
        mitre_bucket = 'persistence'
        default_reasoning = @('Re-enabling a previously-disabled account is a stealthy persistence technique that avoids the higher visibility of creating a new account.')
        detection_logic = 'Enumerates event 4722 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'Legitimate rehire and role-change scenarios routinely re-enable a previously-disabled account.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm the re-enabled account against documented IT role-change or rehire records.'; reason = 'Confirms or rules out stealthy attacker persistence via a dormant account.' }
        )
        investigation_questions = @('Is there a documented IT justification for re-enabling this specific account?', 'Was the account a default, built-in, or otherwise unusually-privileged account before being re-enabled?')
        findingtags = @('persistence', 'live-response')
    }
    "disabled-users" = @{
        finding_type = 'User Account Disabled Events'
        category = 'Defense Evasion'
        subcategory = 'Account Lifecycle'
        title = 'User Account Disabled Events'
        description = 'Event log records (4725) of a user account being disabled.'
        why_this_matters = 'Can reflect an attacker disabling a legitimate account (denial-of-access, or to prevent a security team member from responding) or, in a compromised-admin scenario, disabling their own tracks after use.'
        expected_normal_behaviour = 'Disable events tied to documented offboarding or security-response IT actions.'
        investigator_notes = 'Consider both interpretations: an attacker disabling someone else''s account (disruption) versus routine legitimate offboarding — the disabled account''s identity and role provide the key context.'
        what_is_this = 'Windows Security event 4725 (A user account was disabled), captured from the Security event log.'
        why_it_exists = 'Windows audits account-state changes to provide traceability over account lifecycle management.'
        normal_behaviour = 'Disable events matching documented offboarding or IT security-response workflows.'
        suspicious_behaviour = 'A disable event for an active, currently-employed user''s account with no corresponding offboarding record, especially one performed by an unexpected account.'
        common_attack_usage = 'Attackers occasionally disable a security team member''s or system administrator''s account to disrupt incident response, or disable an account used for an earlier stage of the intrusion once it''s no longer needed.'
        mitre_technique_id = 'T1531'
        mitre_technique = 'Account Access Removal'
        mitre_tactic = 'impact'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag disable events with no corresponding documented offboarding record, especially for privileged or security-team accounts.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 35
        mitre_bucket = 'impact'
        default_reasoning = @('Account disable events without a documented offboarding record may indicate an attacker disrupting response capability or covering tracks.')
        detection_logic = 'Enumerates event 4725 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'Legitimate offboarding and routine IT account-lifecycle management are a common, expected source of this event.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Confirm the disable event against a documented offboarding or security-response record.'; reason = 'Distinguishes routine IT lifecycle management from attacker disruption of response capability.' }
        )
        investigation_questions = @('Is the disable event tied to a documented offboarding record?', 'Was the disabled account a privileged or incident-response-relevant account?')
        findingtags = @('insider-threat', 'live-response')
    }
    "deleted-users" = @{
        finding_type = 'User Account Deleted Events'
        category = 'Defense Evasion'
        subcategory = 'Account Lifecycle'
        title = 'User Account Deleted Events'
        description = 'Event log records (4726) of a user account being deleted.'
        why_this_matters = 'Deleting an account is a common anti-forensic step attackers take to remove evidence of a persistence account they created earlier in the intrusion.'
        expected_normal_behaviour = 'Deletion events tied to documented offboarding/cleanup IT actions.'
        investigator_notes = 'Correlate against the user-creation and user-profiles findings — a create-then-delete pattern for the same account within a short window is a strong indicator of attacker cleanup.'
        what_is_this = 'Windows Security event 4726 (A user account was deleted), captured from the Security event log.'
        why_it_exists = 'Windows audits account-lifecycle operations to provide traceability over account deletion.'
        normal_behaviour = 'Deletion events matching documented offboarding or account-cleanup IT workflows.'
        suspicious_behaviour = 'Deletion of an account shortly after its creation, or deletion with no corresponding offboarding record.'
        common_attack_usage = 'Attackers delete a persistence account they created earlier in the intrusion as a final anti-forensic step, attempting to erase evidence of that persistence mechanism.'
        mitre_technique_id = 'T1531'
        mitre_technique = 'Account Access Removal'
        mitre_tactic = 'impact'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate deletion events against corresponding creation events for the same account name/SID to detect a create-then-delete cleanup pattern.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 40
        mitre_bucket = 'defense_evasion'
        default_reasoning = @('Account deletion, particularly shortly after creation, is a common anti-forensic step attackers take to remove evidence of persistence.')
        detection_logic = 'Enumerates event 4726 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'Legitimate account cleanup during offboarding is a routine, expected source of this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate this deletion against any prior creation event for the same account within the investigation timeframe.'; reason = 'Detects a create-then-delete attacker cleanup pattern.' }
        )
        investigation_questions = @('Was the deleted account created recently, and by whom?', 'Is the deletion tied to a documented offboarding or cleanup record?')
        findingtags = @('defense-evasion', 'live-response')
    }
    "account-lockout" = @{
        finding_type = 'Account Lockout Events'
        category = 'Credential Access'
        subcategory = 'Authentication'
        title = 'Account Lockout Events'
        description = 'Event log records (4740) of an account being locked out due to repeated failed logon attempts.'
        why_this_matters = 'Lockouts are a direct byproduct of brute-force or password-spray attacks reaching the account-lockout threshold, and can also indicate a compromised credential being tried from an unfamiliar source.'
        expected_normal_behaviour = 'Occasional lockouts tied to legitimate user typo/forgotten-password incidents.'
        investigator_notes = 'A cluster of lockouts across multiple accounts in a short window is a strong password-spray indicator; a single account locked out repeatedly may indicate targeted brute-forcing.'
        what_is_this = 'Windows Security event 4740 (A user account was locked out), captured from the Security event log, including the source computer that triggered the lockout.'
        why_it_exists = 'Windows enforces account lockout as a brute-force mitigation and audits when it triggers.'
        normal_behaviour = 'Isolated lockout events tied to an individual user''s own forgotten-password or typo incidents.'
        suspicious_behaviour = 'Multiple accounts locked out in a short time window (password spray), or repeated lockouts of the same account from an unfamiliar source computer.'
        common_attack_usage = 'Password-spray and brute-force credential attacks trigger the account-lockout threshold as a direct side effect, making lockout events a reliable, if lagging, indicator of an attack in progress.'
        mitre_technique_id = 'T1110'
        mitre_technique = 'Brute Force'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag clusters of lockout events across multiple accounts in a short window, and repeated lockouts of the same account from an unfamiliar source.'
        mitre_data_sources = @('User Account', 'Windows Registry')
        base_risk_score = 35
        mitre_bucket = 'credential_access'
        default_reasoning = @('Account lockout events are a direct byproduct of brute-force or password-spray attacks reaching the lockout threshold.')
        detection_logic = 'Enumerates event 4740 records within the collector''s lookback window.'
        detection_threshold = 'A cluster of lockouts across multiple distinct accounts within a short window is the key pattern distinguishing an attack from routine user error.'
        false_positive_notes = 'Individual users forgetting a recently-changed password is the most common, entirely benign source of a single lockout event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Check whether multiple accounts were locked out from the same source computer in a short window.'; reason = 'Confirms or rules out a password-spray attack in progress.' }
        )
        investigation_questions = @('Were multiple distinct accounts locked out in a short time window (password spray pattern)?', 'What source computer triggered the lockout, and is it recognized/expected?')
        findingtags = @('credential-access', 'live-response')
    }
    "credman-backup" = @{
        finding_type = 'Credential Manager Backup Events'
        category = 'Credential Access'
        subcategory = 'Credential Manager'
        title = 'Credential Manager Backup Events'
        description = 'Event log records of Windows Credential Manager vault backup operations.'
        why_this_matters = 'Backing up the Credential Manager vault is a documented technique to export all of a user''s saved credentials (web logins, RDP, network shares) for offline extraction — a legitimate admin operation is rare enough that this event deserves close scrutiny.'
        expected_normal_behaviour = 'Essentially never occurs as part of routine user activity; legitimate uses are limited to specific, documented IT migration scenarios.'
        investigator_notes = 'Treat any occurrence of this event with high suspicion absent a specific, documented IT migration reason — it is not a routine user or admin action.'
        what_is_this = 'A Windows event logged when the Credential Manager vault (rundll32.exe keymgr.dll,KRShowKeyMgr or equivalent vault export API) is backed up to a file.'
        why_it_exists = 'Windows provides vault backup/restore as a supported mechanism for migrating a user''s saved credentials between machines during a profile migration.'
        normal_behaviour = 'No occurrences under normal day-to-day use.'
        suspicious_behaviour = 'Any occurrence at all, absent a specific, documented IT profile-migration project.'
        common_attack_usage = 'Attackers export the Credential Manager vault to harvest every credential Windows has stored on the user''s behalf — a well-documented credential-theft technique that yields a broad set of reusable credentials in one action.'
        mitre_technique_id = 'T1555.004'
        mitre_technique = 'Credentials from Password Stores: Windows Credential Manager'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'Windows Credential Manager'
        mitre_detection_notes = 'Treat every occurrence as high-priority for review; there is essentially no benign baseline rate for this event.'
        mitre_data_sources = @('Command Execution', 'File', 'Windows Registry')
        base_risk_score = 50
        mitre_bucket = 'credential_access'
        default_reasoning = @('Credential Manager vault backup is a well-documented credential-theft technique with essentially no benign baseline occurrence rate.')
        detection_logic = 'Detects vault-backup event records or corresponding command-line invocations within the collector''s lookback window.'
        detection_threshold = 'n/a — any occurrence is inherently notable.'
        false_positive_notes = 'Documented IT-led profile migration projects are the only known legitimate source of this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm this event against a specific, documented IT migration project; if none exists, treat as confirmed credential theft.'; reason = 'Distinguishes the one legitimate use case from active credential theft.' }
        )
        investigation_questions = @('Is there a documented IT migration project explaining this vault backup?', 'What process and account performed the backup operation?')
        findingtags = @('credential-access', 'live-response')
    }
    "credman-restore" = @{
        finding_type = 'Credential Manager Restore Events'
        category = 'Credential Access'
        subcategory = 'Credential Manager'
        title = 'Credential Manager Restore Events'
        description = 'Event log records of Windows Credential Manager vault restore operations.'
        why_this_matters = 'A restore operation on a host other than the one the backup originated from indicates a stolen credential vault is being loaded elsewhere for use or offline extraction.'
        expected_normal_behaviour = 'Essentially never occurs outside a specific, documented IT profile-migration project.'
        investigator_notes = 'If a corresponding backup event (credman-backup) exists elsewhere in the investigation, correlate the two to establish the full theft-and-reuse chain.'
        what_is_this = 'A Windows event logged when a previously-exported Credential Manager vault file is restored/loaded on a host.'
        why_it_exists = 'Complements vault backup as the other half of Windows'' supported credential-migration mechanism.'
        normal_behaviour = 'No occurrences under normal day-to-day use.'
        suspicious_behaviour = 'Any occurrence at all, absent a specific, documented IT profile-migration project, especially on a host different from where the corresponding backup occurred.'
        common_attack_usage = 'Attackers restore a previously-exfiltrated Credential Manager vault onto an attacker-controlled host to load and reuse the harvested credentials.'
        mitre_technique_id = 'T1555.004'
        mitre_technique = 'Credentials from Password Stores: Windows Credential Manager'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'Windows Credential Manager'
        mitre_detection_notes = 'Treat every occurrence as high-priority for review and correlate against any related vault-backup event elsewhere in the investigation.'
        mitre_data_sources = @('Command Execution', 'File', 'Windows Registry')
        base_risk_score = 50
        mitre_bucket = 'credential_access'
        default_reasoning = @('Credential Manager vault restore is the reuse half of a well-documented credential-theft technique with essentially no benign baseline occurrence rate.')
        detection_logic = 'Detects vault-restore event records or corresponding command-line invocations within the collector''s lookback window.'
        detection_threshold = 'n/a — any occurrence is inherently notable.'
        false_positive_notes = 'Documented IT-led profile migration projects are the only known legitimate source of this event.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate against any related vault-backup event and confirm against a documented IT migration project.'; reason = 'Establishes the full credential theft-and-reuse chain, or rules it out.' }
        )
        investigation_questions = @('Is there a corresponding vault-backup event elsewhere in the investigation?', 'Is there a documented IT migration project explaining this restore?')
        findingtags = @('credential-access', 'live-response')
    }
    "logon-events" = @{
        finding_type = 'Successful Logon Events'
        category = 'Credential Access'
        subcategory = 'Authentication'
        title = 'Successful Logon Events'
        description = 'Successful logon events (4624) recorded on the host, across all logon types.'
        why_this_matters = 'Provides the base audit trail for confirming who accessed the host and when — the foundation for spotting logons from unusual accounts, sources, or times.'
        expected_normal_behaviour = 'Logons consistent with the host''s expected users, sources, and typical hours.'
        investigator_notes = 'Pay attention to logon type (interactive vs. network vs. RemoteInteractive vs. service) since each implies a different access method and risk profile.'
        what_is_this = 'Windows Security event 4624 (An account was successfully logged on), captured from the Security event log.'
        why_it_exists = 'Windows audits every successful logon to provide a foundational access-trail for security monitoring and forensic reconstruction.'
        normal_behaviour = 'Logons from expected accounts, sources, and hours consistent with the host''s normal use.'
        suspicious_behaviour = 'A logon from an unusual source IP, an account not expected to use this host, or activity at an unusual hour, especially combined with an unusual logon type.'
        common_attack_usage = 'Every attacker action that requires authenticating to a host generates a 4624 event — this is the base evidence layer nearly every credential-based intrusion touches.'
        mitre_technique_id = 'T1078'
        mitre_technique = 'Valid Accounts'
        mitre_tactic = 'initial_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Baseline expected accounts/sources/hours for this host and flag deviations, particularly around logon type.'
        mitre_data_sources = @('Logon Session', 'User Account')
        base_risk_score = 30
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Logon events provide the foundational audit trail; logons from unusual IPs, accounts, or hours indicate possible compromise.')
        detection_logic = 'Enumerates event 4624 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-logon against baseline.'
        false_positive_notes = 'This is a very high-volume, mostly benign event — meaningful signal requires baselining against the host''s normal usage pattern.'
        recommendations = @(
            @{ priority = 'Low'; action = 'Baseline expected accounts, sources, and hours; review deviations against other findings.'; reason = 'Surfaces access from unusual accounts, sources, or logon types worth deeper investigation.' }
        )
        investigation_questions = @('Does any logon come from a source IP or account outside this host''s normal baseline?', 'Does the logon type match what''s expected for the account/source combination?')
        findingtags = @('credential-access', 'insider-threat', 'live-response')
    }
    "logon-failed" = @{
        finding_type = 'Failed Logon Events'
        category = 'Credential Access'
        subcategory = 'Authentication'
        title = 'Failed Logon Events'
        description = 'Failed logon events (4625) recorded on the host.'
        why_this_matters = 'A pattern of failed logons is the direct evidence of a brute-force or password-guessing attack in progress, and precedes account-lockout events.'
        expected_normal_behaviour = 'Occasional, isolated failures tied to normal user typos.'
        investigator_notes = 'A high volume of failures against a single account (brute force) or many accounts from one source (spray) both merit immediate escalation, distinct from isolated user-error failures.'
        what_is_this = 'Windows Security event 4625 (An account failed to log on), captured from the Security event log, including the failure reason and source.'
        why_it_exists = 'Windows audits failed authentication attempts to support brute-force and unauthorized-access detection.'
        normal_behaviour = 'Isolated failures tied to normal user typo/forgotten-password incidents.'
        suspicious_behaviour = 'A high volume of failures in a short window against one account (brute force) or many accounts (password spray) from the same source.'
        common_attack_usage = 'Brute-force, password-spray, and credential-stuffing attacks all generate a distinctive pattern of failed logon events before any (if ever) succeed.'
        mitre_technique_id = 'T1110'
        mitre_technique = 'Brute Force'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag a high volume of failures against a single account (brute force) or across many accounts from one source (spray) within a short window.'
        mitre_data_sources = @('Logon Session', 'User Account')
        base_risk_score = 35
        mitre_bucket = 'credential_access'
        default_reasoning = @('Failed logon events may indicate brute-force attacks or credential stuffing/spraying in progress.')
        detection_logic = 'Enumerates event 4625 records within the collector''s lookback window.'
        detection_threshold = 'A high volume of failures in a short window (single-account brute force, or multi-account spray from one source) is the key suspicious pattern.'
        false_positive_notes = 'Individual users mistyping a password, and service accounts with an outdated cached credential, are common benign sources.'
        recommendations = @(
            @{ priority = 'High'; action = 'Quantify the volume and pattern of failures (single-account vs. multi-account) and cross-reference with any subsequent account-lockout events.'; reason = 'Confirms or rules out an active brute-force or password-spray attack.' }
        )
        investigation_questions = @('Is there a high volume of failures against a single account, or spread across many accounts from one source?', 'Did any of the failed-logon attempts eventually succeed?')
        findingtags = @('credential-access', 'malware', 'live-response')
    }
    "object-access" = @{
        finding_type = 'Object Access Events'
        category = 'Collection'
        subcategory = 'File Access Auditing'
        title = 'Object Access Events'
        description = 'File and object access events (4656/4663) recorded for audited objects on the host.'
        why_this_matters = 'Provides a direct record of exactly which files an account has read, modified, or deleted, which is essential for scoping data-exfiltration or insider-threat activity to specific files.'
        expected_normal_behaviour = 'Access patterns consistent with the account''s normal job function, limited to objects with audit policies configured.'
        investigator_notes = 'This finding is only as complete as the host''s object-level audit policy (SACLs) — its absence for a given file does not mean the file wasn''t accessed, only that auditing wasn''t configured for it.'
        what_is_this = 'Windows Security events 4656 (handle requested) and 4663 (attempt to access object made), generated for objects with a configured System Access Control List (SACL).'
        why_it_exists = 'Windows provides object-level access auditing as an opt-in mechanism to track access to specifically-flagged sensitive files, folders, or registry keys.'
        normal_behaviour = 'Access consistent with the account''s normal job function on the specific audited objects.'
        suspicious_behaviour = 'Access to a sensitive audited object by an account with no normal business reason to touch it, especially bulk/sequential access suggesting automated collection.'
        common_attack_usage = 'Attackers and insiders accessing sensitive files (financial records, source code, PII) as part of a data-theft operation generate this event wherever the relevant objects have audit policies configured.'
        mitre_technique_id = 'T1083'
        mitre_technique = 'File and Directory Discovery'
        mitre_tactic = 'collection'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag access to sensitive audited objects by accounts without a normal business reason, particularly bulk/sequential access patterns.'
        mitre_data_sources = @('File', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('Object access events reveal which files attackers or insiders have read, modified, or deleted from audited locations.')
        detection_logic = 'Enumerates events 4656/4663 within the collector''s lookback window, limited to objects with SACL-based auditing configured.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event/pattern.'
        false_positive_notes = 'Normal job-function access to audited business-critical files/folders is expected and benign.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Review access to each audited object against the accessing account''s normal job function.'; reason = 'Scopes potential data-exfiltration or insider-threat activity to specific files.' }
        )
        investigation_questions = @('Does the accessing account have a documented business reason to touch this object?', 'Does the access pattern suggest bulk/automated collection rather than normal individual use?')
        findingtags = @('data-exfiltration', 'insider-threat', 'live-response')
    }
    "process-exec" = @{
        finding_type = 'Process Execution Events'
        category = 'Execution'
        subcategory = 'Process Auditing'
        title = 'Process Execution Events'
        description = 'Process creation events (4688) recorded on the host, including full command line where auditing is configured to capture it.'
        why_this_matters = 'The command-line-inclusive process creation log is one of the highest-value forensic artifacts available on Windows — it''s a direct, timestamped record of exactly what executed and with what arguments.'
        expected_normal_behaviour = 'Execution consistent with the host''s normal application and administrative activity.'
        investigator_notes = 'This is the single richest source for reconstructing an attacker''s exact command-line actions when command-line auditing is enabled; correlate against the process listing and ps-history findings.'
        what_is_this = 'Windows Security event 4688 (A new process has been created), captured from the Security event log, including command-line arguments if ''Include command line in process creation events'' auditing is enabled.'
        why_it_exists = 'Windows audits process creation to provide a historical execution trail, unlike the live process-listing finding which only captures what''s running at collection time.'
        normal_behaviour = 'Execution consistent with the host''s normal application and administrative activity.'
        suspicious_behaviour = 'Execution of a script interpreter with an encoded/obfuscated command line, an unsigned or unexpected binary, or an unusual parent/child execution chain (e.g., an Office app spawning a script interpreter).'
        common_attack_usage = 'Nearly every stage of an intrusion — initial execution, discovery, credential access, lateral movement — leaves a 4688 record with the exact command line used, making this a primary artifact for reconstructing attacker tradecraft.'
        mitre_technique_id = 'T1059'
        mitre_technique = 'Command and Scripting Interpreter'
        mitre_tactic = 'execution'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag encoded/obfuscated command lines, unsigned binaries, and unusual parent/child execution chains (e.g., Office apps spawning script interpreters).'
        mitre_data_sources = @('Process', 'Command Execution')
        base_risk_score = 12
        mitre_bucket = 'execution'
        default_reasoning = @('Process creation events reveal which executables ran and their command lines — critical for malware and attacker tool identification and tradecraft reconstruction.')
        detection_logic = 'Enumerates event 4688 records within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'The vast majority of process creation events reflect normal, benign application and OS activity.'
        recommendations = @(
            @{ priority = 'High'; action = 'Reconstruct the full parent/child execution chain for any suspicious process and decode any encoded command line.'; reason = 'Confirms or rules out attacker tradecraft and reveals the true command executed.' }
        )
        investigation_questions = @('Does any process show an encoded/obfuscated command line, and what does it decode to?', 'Is there an unusual parent/child relationship in the execution chain (e.g., an Office app spawning a script interpreter)?')
        findingtags = @('malware', 'ransomware', 'live-response')
    }
    "added-users" = @{
        finding_type = 'Group Membership Change Events'
        category = 'Privilege Escalation'
        subcategory = 'Account Lifecycle'
        title = 'Group Membership Change Events'
        description = 'Event log records (4728/4732) of an account being added to a security-enabled group.'
        why_this_matters = 'This is the event-log corroboration for the admin-group/local-groups findings — it tells you exactly when and by whom a privileged group gained a new member, not just its current state.'
        expected_normal_behaviour = 'Additions tied to documented IT access-change requests.'
        investigator_notes = 'Correlate the adding account, the target group, and the timing against a documented change ticket; an addition to a highly-privileged group with no ticket is a high-confidence escalation indicator.'
        what_is_this = 'Windows Security events 4728 (member added to a security-enabled global group) and 4732 (member added to a security-enabled local group), captured from the Security event log.'
        why_it_exists = 'Windows audits group-membership changes to provide traceability over privilege-relevant access changes.'
        normal_behaviour = 'Additions matching documented IT access-change requests.'
        suspicious_behaviour = 'An addition to a privileged group with no corresponding change ticket, or performed by an account not authorized to manage that group.'
        common_attack_usage = 'Adding a compromised or attacker-controlled account to a privileged group (Administrators, Domain Admins, Backup Operators) is one of the most direct and common privilege-escalation and persistence techniques.'
        mitre_technique_id = 'T1098'
        mitre_technique = 'Account Manipulation'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag additions to privileged groups without a corresponding documented change ticket.'
        mitre_data_sources = @('User Account', 'Active Directory', 'Windows Registry')
        base_risk_score = 50
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('Adding users to privileged groups is a common privilege escalation and persistence technique, especially without a corresponding change record.')
        detection_logic = 'Enumerates events 4728/4732 within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-event.'
        false_positive_notes = 'Legitimate IT-driven access changes (role change, project onboarding) are a routine, expected source of these events.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every privileged-group addition against a documented IT change ticket.'; reason = 'Confirms or rules out unauthorized privilege escalation.' }
        )
        investigation_questions = @('Is there a documented change ticket authorizing this group membership addition?', 'Was the adding account authorized to manage the target group?')
        findingtags = @('insider-threat', 'privilege-escalation', 'credential-access', 'live-response')
    }
    "ad-ntds" = @{
        finding_type = 'NTDS Database Metadata'
        category = 'Active Directory'
        subcategory = 'Domain Controller'
        title = 'NTDS Database Metadata'
        description = 'Metadata about the NTDS.dit Active Directory database file on a domain controller, including size, location, and last-modified time.'
        why_this_matters = 'NTDS.dit contains every domain account''s password hash — any unexpected access to or copy of this file is one of the most severe possible credential-theft events, potentially compromising the entire domain.'
        expected_normal_behaviour = 'A stable file with modification activity limited to normal AD replication/write operations, located at its default path.'
        investigator_notes = 'An unexpected copy of NTDS.dit elsewhere on disk (e.g., in a temp directory) is a near-certain sign of a DCSync-adjacent or volume-shadow-copy-based credential dumping attempt (e.g., via ntdsutil or vssadmin).'
        what_is_this = 'The Active Directory database file (NTDS.dit) that stores all domain objects, including every account''s password hash, on a domain controller.'
        why_it_exists = 'NTDS.dit is the core data store for Active Directory itself; every domain controller must maintain a copy to serve authentication and directory queries.'
        normal_behaviour = 'Present only at its default path (%SystemRoot%\NTDS\ntds.dit), with modification activity from normal AD operation only.'
        suspicious_behaviour = 'A copy of the file (or an accompanying SYSTEM registry hive) found outside its default location, or evidence of a volume shadow copy being created and accessed around the same time.'
        common_attack_usage = 'Attackers extract NTDS.dit (often via a shadow copy to bypass the file lock) to obtain every domain account''s password hash offline, enabling mass credential cracking or pass-the-hash across the entire domain.'
        mitre_technique_id = 'T1003.003'
        mitre_technique = 'OS Credential Dumping: NTDS'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'NTDS'
        mitre_detection_notes = 'Flag any NTDS.dit-named file outside its default path, and correlate with volume-shadow-copy creation events around the same time.'
        mitre_data_sources = @('File', 'Volume', 'Process')
        base_risk_score = 20
        mitre_bucket = 'credential_access'
        default_reasoning = @('Unexpected NTDS.dit copies or access outside normal AD replication indicate a domain-wide credential dumping attempt.')
        detection_logic = 'Collects metadata (path, size, last-modified) for the NTDS database file(s) found on the host.'
        detection_threshold = 'n/a — presence of a copy outside the default path is itself the key signal.'
        false_positive_notes = 'Domain controller backup/recovery software may legitimately stage a temporary copy — verify against documented backup jobs before escalating.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm any NTDS.dit copy outside the default path against a documented backup/recovery job.'; reason = 'Confirms or rules out a domain-wide credential-dumping attempt.' }
        )
        investigation_questions = @('Does an NTDS.dit-named file exist outside its default path?', 'Was a volume shadow copy created and accessed around the same time as any unexpected copy?')
        findingtags = @('credential-access', 'live-response')
    }
    "ad-sysvol" = @{
        finding_type = 'SYSVOL Script Analysis'
        category = 'Active Directory'
        subcategory = 'Group Policy'
        title = 'SYSVOL Script Analysis'
        description = 'Analysis of logon/startup/shutdown scripts and Group Policy Preferences stored in the domain''s SYSVOL share.'
        why_this_matters = 'SYSVOL scripts execute automatically, domain-wide, on every affected machine — a malicious modification here is one of the most impactful persistence and lateral-movement mechanisms available in an AD environment (e.g., the historical Group Policy Preferences cpassword credential-exposure issue).'
        expected_normal_behaviour = 'Scripts matching documented, IT-managed logon/startup content only, with modification history tied to change management.'
        investigator_notes = 'Any script content referencing an unfamiliar external IP/domain, or a modification with no corresponding change ticket, should be treated as a domain-wide compromise indicator, not an isolated host issue.'
        what_is_this = 'PowerShell/batch/VBScript logon, startup, and shutdown scripts, plus Group Policy Preferences XML files, stored under the domain''s SYSVOL share and pushed to every applicable domain-joined machine.'
        why_it_exists = 'SYSVOL is the mechanism Active Directory uses to distribute Group Policy content, including scripts, to every domain-joined computer and user.'
        normal_behaviour = 'Script content and modification history matching documented, IT-managed change records only.'
        suspicious_behaviour = 'A script modification with no corresponding change ticket, script content referencing an external IP/domain or download-and-execute pattern, or a Group Policy Preferences XML containing a cpassword value.'
        common_attack_usage = 'Attackers with sufficient AD privilege modify a SYSVOL logon script to achieve domain-wide code execution on every machine that applies the affected Group Policy Object, and historically exploited GPP cpassword values to recover cleartext credentials.'
        mitre_technique_id = 'T1484.001'
        mitre_technique = 'Domain or Tenant Policy Modification: Group Policy Modification'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = 'Group Policy Modification'
        mitre_detection_notes = 'Diff SYSVOL script content against a known-good baseline; flag any GPP XML containing a cpassword attribute and any script referencing an external network destination.'
        mitre_data_sources = @('File', 'Active Directory')
        base_risk_score = 45
        mitre_bucket = 'persistence'
        default_reasoning = @('Modified SYSVOL scripts execute domain-wide and represent a high-impact persistence and lateral-movement mechanism if tampered with.')
        detection_logic = 'Enumerates and analyzes script/GPP content under SYSVOL for suspicious patterns and modification recency.'
        detection_threshold = 'n/a — any unexplained modification or cpassword presence is inherently notable.'
        false_positive_notes = 'Legitimate, IT-managed script updates as part of routine GPO maintenance are the expected normal source of changes here.'
        recommendations = @(
            @{ priority = 'High'; action = 'Diff every SYSVOL script/GPP against a known-good baseline and confirm recent changes against a change ticket.'; reason = 'Confirms or rules out domain-wide persistence via Group Policy tampering.' }
        )
        investigation_questions = @('Does any recently-modified script lack a corresponding change ticket?', 'Does any Group Policy Preferences XML file contain a cpassword attribute?')
        findingtags = @('privilege-escalation', 'persistence', 'live-response')
    }
    "ad-priv-groups" = @{
        finding_type = 'Privileged AD Group Membership'
        category = 'Active Directory'
        subcategory = 'Group Membership'
        title = 'Privileged AD Group Membership'
        description = 'Membership of the most privileged domain groups — Domain Admins, Enterprise Admins, Schema Admins, and similar.'
        why_this_matters = 'Membership in these groups grants effective control over the entire domain (or forest); this is the single highest-value target list for both attackers seeking to escalate and defenders auditing exposure.'
        expected_normal_behaviour = 'A small, well-documented list matching the organization''s tiered administration model.'
        investigator_notes = 'Any member outside the documented list, or any service/computer account present, deserves immediate escalation — this list should be short and well known to the security team.'
        what_is_this = 'Membership lists for the most sensitive built-in AD groups (Domain Admins, Enterprise Admins, Schema Admins, Account Operators, etc.).'
        why_it_exists = 'Active Directory provides these groups as the standard delegation mechanism for the highest levels of domain/forest administrative control.'
        normal_behaviour = 'Membership matching exactly the organization''s documented tiered-administration model.'
        suspicious_behaviour = 'Any account present that isn''t in the documented baseline, particularly a standard user account, service account, or computer account.'
        common_attack_usage = 'Gaining membership in Domain Admins or Enterprise Admins is often the ultimate objective of an AD-focused intrusion, since it grants complete control over the domain/forest.'
        mitre_technique_id = 'T1078.002'
        mitre_technique = 'Valid Accounts: Domain Accounts'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = 'Domain Accounts'
        mitre_detection_notes = 'Diff membership against the documented tiered-administration baseline; treat any deviation as high-priority.'
        mitre_data_sources = @('Active Directory', 'User Account')
        base_risk_score = 25
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('Unexpected membership in the most privileged domain groups represents effective compromise of the entire domain or forest.')
        detection_logic = 'Static enumeration of membership for the most privileged built-in AD groups at collection time.'
        detection_threshold = 'n/a — every member is captured; suspicion driven by comparison against the documented baseline.'
        false_positive_notes = 'Legitimate tiered-administration models will show a small, specific, well-known set of members here.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every member against the organization''s documented tiered-administration baseline.'; reason = 'Identifies domain/forest-wide compromise via the highest-value privilege escalation target.' }
        )
        investigation_questions = @('Is every member of Domain Admins/Enterprise Admins/Schema Admins accounted for in the documented baseline?', 'Is any service or computer account present in these groups?')
        findingtags = @('privilege-escalation', 'persistence', 'live-response')
    }
    "ad-krbtgt" = @{
        finding_type = 'KRBTGT Account Age'
        category = 'Active Directory'
        subcategory = 'Kerberos'
        title = 'KRBTGT Account Age'
        description = 'Age of the KRBTGT account''s current password, which determines how long a forged Kerberos ticket built from a stolen KRBTGT hash remains usable.'
        why_this_matters = 'The KRBTGT account signs every Kerberos ticket in the domain; a stale password directly bounds how long a Golden Ticket attack built from a previously-stolen hash remains viable, making this a critical, easily-overlooked exposure window metric.'
        expected_normal_behaviour = 'Rotated at least every ~180 days per Microsoft''s guidance (and twice, since the account keeps the prior password valid for one more rotation cycle).'
        investigator_notes = 'This finding''s severity is dynamically scored based on the actual measured account age at scan time, not a fixed value — treat the score/level the collector computed as authoritative for this run.'
        what_is_this = 'The KRBTGT domain account''s password-last-set timestamp, used to derive how long ago the Kerberos ticket-granting-ticket signing key was last rotated.'
        why_it_exists = 'Every Kerberos TGT in the domain is encrypted/signed using the KRBTGT account''s key; Microsoft recommends periodic rotation to limit the blast radius of any KRBTGT hash compromise.'
        normal_behaviour = 'Password age within the organization''s rotation policy (typically under ~180 days).'
        suspicious_behaviour = 'A password age far exceeding rotation policy, especially in combination with any other AD compromise indicator in the same investigation.'
        common_attack_usage = 'An attacker who has stolen the KRBTGT hash (via DCSync or NTDS extraction) can forge Golden Tickets granting domain-wide access as any user, valid for as long as that specific KRBTGT password remains unrotated.'
        mitre_technique_id = 'T1558.001'
        mitre_technique = 'Steal or Forge Kerberos Tickets: Golden Ticket'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'Golden Ticket'
        mitre_detection_notes = 'Flag KRBTGT password age beyond the organization''s rotation policy, especially alongside any DCSync or NTDS-access finding in the same investigation.'
        mitre_data_sources = @('Active Directory')
        base_risk_score = 40
        mitre_bucket = 'credential_access'
        default_reasoning = @('KRBTGT password age directly bounds how long a forged Golden Ticket built from a stolen KRBTGT hash remains valid.')
        detection_logic = 'Computes the KRBTGT account''s password age at collection time and classifies risk dynamically based on the measured value against rotation-policy thresholds.'
        detection_threshold = 'Password age beyond the organization''s rotation policy (Microsoft recommends resetting twice at least every ~180 days) is the suspicious threshold.'
        false_positive_notes = 'A stale KRBTGT password alone is a hygiene/exposure-window issue, not proof of an active Golden Ticket attack — it must be paired with an actual credential-theft indicator to confirm exploitation.'
        recommendations = @(
            @{ priority = 'High'; action = 'Rotate the KRBTGT password twice (following Microsoft''s documented procedure) if age exceeds policy.'; reason = 'Invalidates any previously-forged Golden Ticket and closes the exposure window.' },
            @{ priority = 'High'; action = 'If any DCSync or NTDS-extraction finding is also present, treat KRBTGT compromise as confirmed and rotate immediately regardless of measured age.'; reason = 'Golden Ticket risk is realized the moment the hash is stolen, independent of password age at time of theft.' }
        )
        investigation_questions = @('Does the measured KRBTGT password age exceed the organization''s rotation policy?', 'Is there any DCSync or NTDS-extraction finding elsewhere in this investigation that would confirm the hash was actually stolen?')
        findingtags = @('credential-access', 'persistence', 'live-response')
    }
    "ad-ldap-smb-signing" = @{
        finding_type = 'LDAP / SMB Signing Configuration'
        category = 'Active Directory'
        subcategory = 'Domain Hardening'
        title = 'LDAP / SMB Signing Configuration'
        description = 'Whether LDAP signing/channel binding and SMB signing are enforced on the domain controller.'
        why_this_matters = 'Without signing enforced, LDAP and SMB traffic to the domain controller is vulnerable to relay attacks (NTLM relay to LDAP/LDAPS) that can lead directly to domain compromise.'
        expected_normal_behaviour = 'Both LDAP signing/channel binding and SMB signing enforced (required, not merely negotiated) per current Microsoft hardening guidance.'
        investigator_notes = 'This is a configuration-hardening finding rather than direct evidence of exploitation — treat it as an exposure/risk finding to prioritize for remediation, and check other findings for signs it has actually been exploited (e.g., unexpected LDAP binds).'
        what_is_this = 'The domain controller''s LDAP server signing/channel-binding policy and SMB server signing requirement, both queryable via registry/policy settings.'
        why_it_exists = 'These settings control whether the domain controller requires cryptographic integrity protection on LDAP and SMB connections, closing a well-known NTLM-relay attack path if enforced.'
        normal_behaviour = 'Both protections set to Required/Enforced per current Microsoft hardening guidance.'
        suspicious_behaviour = 'Either protection set to Negotiate/Optional or disabled, leaving the domain controller exposed to NTLM relay attacks.'
        common_attack_usage = 'NTLM relay attacks against an unsigned LDAP or SMB listener on a domain controller can lead directly to domain compromise (e.g., relaying a captured NTLM authentication to create a computer account or modify AD objects via LDAP).'
        mitre_technique_id = 'T1557'
        mitre_technique = 'Adversary-in-the-Middle'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag either signing requirement set to anything other than Required/Enforced.'
        mitre_data_sources = @('Windows Registry', 'Active Directory')
        base_risk_score = 30
        mitre_bucket = 'credential_access'
        default_reasoning = @('LDAP or SMB signing not enforced on a domain controller leaves an NTLM-relay attack path open to domain compromise.')
        detection_logic = 'Queries the domain controller''s LDAP and SMB signing/channel-binding policy settings at collection time.'
        detection_threshold = 'Any setting other than Required/Enforced is the suspicious condition.'
        false_positive_notes = 'Some legacy line-of-business applications historically required relaxed signing settings; verify against current compatibility requirements before hardening.'
        recommendations = @(
            @{ priority = 'High'; action = 'Enforce LDAP signing/channel binding and require SMB signing per current Microsoft hardening guidance.'; reason = 'Closes a well-known NTLM-relay path to domain compromise.' }
        )
        investigation_questions = @('Is LDAP signing/channel binding set to Required, or merely Negotiated/Optional?', 'Is SMB signing required on the domain controller?')
        findingtags = @('defense-evasion', 'live-response')
    }
    "ad-spn" = @{
        finding_type = 'Service Principal Names (Kerberoasting Exposure)'
        category = 'Active Directory'
        subcategory = 'Kerberos'
        title = 'Service Principal Names (Kerberoasting Exposure)'
        description = 'Accounts with a registered Service Principal Name, particularly user (non-computer) accounts, which are directly targetable via Kerberoasting.'
        why_this_matters = 'Any account with an SPN can have its Kerberos service ticket requested and cracked offline without triggering a failed-logon event — user accounts with weak passwords and an SPN are a well-known, easy privilege-escalation path.'
        expected_normal_behaviour = 'SPNs limited to their intended service accounts, ideally using long, randomly-generated (Kerberoasting-resistant) passwords or Group Managed Service Accounts.'
        investigator_notes = 'Prioritize SPN-bearing accounts that are also members of privileged groups — a Kerberoastable Domain Admin service account is a critical-severity finding regardless of the base scoring.'
        what_is_this = 'Active Directory accounts with a Service Principal Name registered, enumerable via any authenticated domain user without special privilege (setspn -T domain -Q */* or equivalent LDAP query).'
        why_it_exists = 'SPNs let Kerberos clients request a service ticket for a specific service instance; any domain account can register or be assigned one to represent a service.'
        normal_behaviour = 'SPNs limited to legitimate service accounts, using strong/randomized credentials or gMSA where possible.'
        suspicious_behaviour = 'A user account (rather than a computer/gMSA account) holding an SPN, particularly one with weak/guessable password history or privileged group membership.'
        common_attack_usage = 'Kerberoasting requests a service ticket for any SPN-bearing account and attempts to crack its encrypted portion offline to recover the account''s plaintext password, entirely without triggering an authentication failure.'
        mitre_technique_id = 'T1558.003'
        mitre_technique = 'Steal or Forge Kerberos Tickets: Kerberoasting'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'Kerberoasting'
        mitre_detection_notes = 'Flag user (non-computer) accounts holding an SPN, especially those also in a privileged group; monitor for TGS-REQ event 4769 with RC4 encryption type as a live-exploitation indicator.'
        mitre_data_sources = @('Active Directory', 'Windows Registry')
        base_risk_score = 25
        mitre_bucket = 'credential_access'
        default_reasoning = @('User accounts with a registered SPN are directly targetable via Kerberoasting for offline password cracking.')
        detection_logic = 'Enumerates all accounts with a registered SPN and flags user-type accounts specifically.'
        detection_threshold = 'n/a — every SPN-bearing account is captured; user-type accounts are the higher-priority subset.'
        false_positive_notes = 'Computer accounts and Group Managed Service Accounts legitimately and safely hold SPNs by design.'
        recommendations = @(
            @{ priority = 'High'; action = 'Migrate SPN-bearing user accounts to Group Managed Service Accounts or enforce a long, randomized password.'; reason = 'Removes or substantially raises the bar against Kerberoasting exploitation.' }
        )
        investigation_questions = @('Are any SPN-bearing accounts user (not computer/gMSA) accounts?', 'Do any SPN-bearing user accounts also hold privileged group membership?')
        findingtags = @('credential-access', 'privilege-escalation', 'live-response')
    }
    "ad-delegation" = @{
        finding_type = 'Kerberos Delegation'
        category = 'Active Directory'
        subcategory = 'Kerberos'
        title = 'Kerberos Delegation'
        description = 'Accounts configured for unconstrained, constrained, or resource-based constrained Kerberos delegation.'
        why_this_matters = 'Unconstrained delegation in particular is one of the most severe AD misconfigurations possible — compromising a host trusted for unconstrained delegation lets an attacker capture and reuse the TGT of any user who authenticates to it, including a Domain Admin.'
        expected_normal_behaviour = 'Delegation limited to specific, documented service accounts using constrained (ideally resource-based constrained) delegation only; unconstrained delegation should be essentially absent outside domain controllers themselves.'
        investigator_notes = 'Any account other than a domain controller configured for unconstrained delegation should be treated as an Important-severity finding requiring immediate remediation, independent of whether exploitation evidence exists yet.'
        what_is_this = 'The Kerberos delegation configuration (userAccountControl flags / msDS-AllowedToDelegateTo attributes) for computer and service accounts in the domain.'
        why_it_exists = 'Delegation lets a trusted service impersonate a user to access a second-hop resource on that user''s behalf, supporting legitimate multi-tier application architectures.'
        normal_behaviour = 'Constrained or resource-based constrained delegation limited to specific, documented service accounts; no unconstrained delegation outside domain controllers.'
        suspicious_behaviour = 'Any non-domain-controller account configured for unconstrained delegation, or a constrained-delegation target list broader than the documented service architecture requires.'
        common_attack_usage = 'An attacker who compromises a host trusted for unconstrained delegation can coerce or wait for a privileged account (ideally a Domain Admin) to authenticate to it, capture that account''s TGT from memory, and impersonate them domain-wide.'
        mitre_technique_id = 'T1187'
        mitre_technique = 'Forced Authentication'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any non-domain-controller account with unconstrained delegation enabled; review constrained-delegation target lists against documented service architecture.'
        mitre_data_sources = @('Active Directory')
        base_risk_score = 50
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Unconstrained Kerberos delegation on a non-domain-controller host is a critical misconfiguration allowing domain-wide credential theft via TGT capture.')
        detection_logic = 'Enumerates all accounts with any form of Kerberos delegation configured and specifically flags unconstrained delegation on non-domain-controller accounts.'
        detection_threshold = 'Any non-domain-controller account with unconstrained delegation is treated as a critical finding regardless of other context.'
        false_positive_notes = 'Legacy application architectures sometimes require unconstrained delegation for compatibility reasons — this remains a genuine risk even when intentional and should still be flagged for remediation planning.'
        recommendations = @(
            @{ priority = 'High'; action = 'Migrate any non-domain-controller unconstrained-delegation account to constrained or resource-based constrained delegation.'; reason = 'Eliminates the domain-wide TGT-capture exposure this misconfiguration creates.' }
        )
        investigation_questions = @('Is any non-domain-controller account configured for unconstrained delegation?', 'Does any constrained-delegation target list exceed what the documented service architecture requires?')
        findingtags = @('privilege-escalation', 'lateral-movement', 'live-response')
    }
    "ad-dcsync" = @{
        finding_type = 'DCSync Rights'
        category = 'Active Directory'
        subcategory = 'Replication Rights'
        title = 'DCSync Rights'
        description = 'Accounts holding the Active Directory replication rights (Replicating Directory Changes / Replicating Directory Changes All) required to perform a DCSync attack.'
        why_this_matters = 'Any non-domain-controller account with these rights can extract the password hash of any account in the domain — including Domain Admins and the KRBTGT account — without ever touching a domain controller''s disk, making this one of the single most critical AD findings possible.'
        expected_normal_behaviour = 'These rights held only by domain controllers themselves and a small, explicitly-documented set of directory-synchronization service accounts (e.g., Azure AD Connect).'
        investigator_notes = 'Treat any unexpected principal holding these rights as a confirmed critical-severity finding requiring immediate investigation — this is not a heuristic or probabilistic indicator, it is a direct capability check.'
        what_is_this = 'The extended rights ''Replicating Directory Changes'' and ''Replicating Directory Changes All'' on the domain object, normally held only by domain controllers and directory-sync services, checked via the domain''s access control list.'
        why_it_exists = 'These rights exist to let domain controllers replicate directory data amongst themselves, and to let services like Azure AD Connect synchronize password hashes for hybrid identity scenarios.'
        normal_behaviour = 'Held exclusively by domain controller computer accounts and documented directory-sync service accounts.'
        suspicious_behaviour = 'Any user account, or any computer account that isn''t a domain controller, holding either right.'
        common_attack_usage = 'DCSync abuses these legitimate replication rights to request password hash data for any account directly from a domain controller, impersonating a peer DC — no code execution on a DC and no NTDS.dit file access is required, making it exceptionally stealthy.'
        mitre_technique_id = 'T1003.006'
        mitre_technique = 'OS Credential Dumping: DCSync'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = 'DCSync'
        mitre_detection_notes = 'Enumerate the domain object''s ACL for the two replication extended rights and flag any principal beyond domain controllers and documented sync services; monitor for event 4662 with the corresponding GUIDs as a live-exploitation indicator.'
        mitre_data_sources = @('Active Directory', 'Windows Registry')
        base_risk_score = 55
        mitre_bucket = 'credential_access'
        default_reasoning = @('Any non-domain-controller principal holding DCSync replication rights can extract the password hash of any domain account, including Domain Admins and KRBTGT, without touching a domain controller''s disk.')
        detection_logic = 'Enumerates the domain object''s access control list for the Replicating Directory Changes / Replicating Directory Changes All extended rights and identifies every principal holding them.'
        detection_threshold = 'Any principal beyond domain controllers and an explicitly documented directory-sync service account is the suspicious condition.'
        false_positive_notes = 'Azure AD Connect and similar directory-synchronization services legitimately and necessarily require these rights — confirm the holder against documented sync service accounts before escalating.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately investigate and remove replication rights from any principal not a domain controller or a documented sync service.'; reason = 'Closes a stealthy, direct path to extracting any domain account''s password hash including Domain Admins and KRBTGT.' },
            @{ priority = 'High'; action = 'If an unauthorized principal is confirmed, treat the entire domain''s credential material as compromised and plan a KRBTGT double-reset and broad credential rotation.'; reason = 'DCSync rights held even briefly by an attacker are sufficient to have already exfiltrated all domain hashes.' }
        )
        investigation_questions = @('Does any principal beyond domain controllers and documented sync services hold DCSync replication rights?', 'Is there any event 4662 evidence that these rights were actually exercised?')
        findingtags = @('credential-access', 'privilege-escalation', 'live-response')
    }
    "ad-priv-events" = @{
        finding_type = 'Privileged & Kerberos Security Events'
        category = 'Active Directory'
        subcategory = 'Kerberos'
        title = 'Privileged & Kerberos Security Events'
        description = 'Security events related to privileged logons and Kerberos ticket operations on the domain controller (e.g., special-privilege assignment, TGT/TGS requests with notable properties).'
        why_this_matters = 'These events corroborate whether AD misconfigurations found elsewhere (delegation, SPNs, DCSync rights) are actively being exploited, not just theoretically present.'
        expected_normal_behaviour = 'Privileged logon and ticket-request activity consistent with known administrative accounts and documented service usage.'
        investigator_notes = 'Cross-reference against the ad-spn, ad-delegation, and ad-dcsync findings — a spike in relevant ticket-request activity for a flagged account is the corroborating evidence that turns a configuration risk into a confirmed exploitation event.'
        what_is_this = 'A curated set of Security event log entries relevant to Kerberos ticket operations and privileged logon (e.g., 4672 special privileges assigned, 4768/4769 TGT/TGS requests) on the domain controller.'
        why_it_exists = 'Domain controllers audit Kerberos and privileged-logon activity to provide the event-level evidence needed to detect ticket-based attacks and privilege misuse.'
        normal_behaviour = 'Ticket-request and privileged-logon patterns consistent with known administrative and service accounts.'
        suspicious_behaviour = 'A spike in TGS requests for a specific SPN-bearing account (Kerberoasting), TGT requests with anomalous encryption types (RC4 downgrade), or special-privilege assignment to an unexpected account.'
        common_attack_usage = 'Kerberoasting, Golden/Silver Ticket use, and privilege-escalation activity all leave a distinctive pattern in these events that corroborates and dates exploitation of a related AD misconfiguration.'
        mitre_technique_id = 'T1558'
        mitre_technique = 'Steal or Forge Kerberos Tickets'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Correlate ticket-request spikes and encryption-type anomalies against accounts flagged in the ad-spn and ad-delegation findings.'
        mitre_data_sources = @('Active Directory', 'Logon Session')
        base_risk_score = 30
        mitre_bucket = 'credential_access'
        default_reasoning = @('Privileged and Kerberos-related security events corroborate whether AD misconfigurations found elsewhere are actively being exploited.')
        detection_logic = 'Enumerates relevant privileged-logon and Kerberos ticket-operation events within the collector''s lookback window.'
        detection_threshold = 'A volume/pattern spike for a specific account, especially one flagged by a related AD finding, is the key suspicious signal.'
        false_positive_notes = 'Normal domain authentication traffic generates a high baseline volume of Kerberos ticket events; meaningful signal requires correlation with specific flagged accounts.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Correlate any ticket-request spike against accounts already flagged in the SPN or delegation findings.'; reason = 'Confirms whether a configuration risk has actually been exploited.' }
        )
        investigation_questions = @('Does any account flagged in the SPN or delegation findings show a corresponding spike in ticket requests?', 'Is there evidence of an RC4 encryption-type downgrade in TGT/TGS requests?')
        findingtags = @('credential-access', 'lateral-movement', 'live-response')
    }
    "ad-object-changes" = @{
        finding_type = 'Directory Object Changes'
        category = 'Active Directory'
        subcategory = 'Change Auditing'
        title = 'Directory Object Changes'
        description = 'Recent changes to Active Directory objects (users, groups, computers, GPOs) captured from AD change-auditing events.'
        why_this_matters = 'Provides a general-purpose change trail across all of AD, catching modifications that don''t fall neatly into the more specific findings (e.g., an attribute change enabling a new attack path, or a GPO link change).'
        expected_normal_behaviour = 'Changes tied to documented IT administrative activity.'
        investigator_notes = 'Use this as a catch-all cross-check against the other, more specific AD findings — an unexplained change here that doesn''t map to any documented ticket deserves the same scrutiny as a specific privileged-group or delegation change.'
        what_is_this = 'AD object-modification events (e.g., 5136 directory service object was modified) captured from the Security event log on the domain controller.'
        why_it_exists = 'Windows audits directory service changes to provide traceability over modifications to AD objects and their attributes.'
        normal_behaviour = 'Changes matching documented IT administrative activity and normal AD operational churn.'
        suspicious_behaviour = 'A change with no corresponding documented ticket, particularly one touching a security-relevant attribute (userAccountControl, group membership, GPO links) performed by an unexpected account.'
        common_attack_usage = 'Attackers with sufficient AD privilege make direct object modifications (e.g., setting a user''s userAccountControl to enable delegation, or altering a GPO link) as a lower-visibility alternative to more heavily-monitored actions like group membership changes.'
        mitre_technique_id = 'T1098'
        mitre_technique = 'Account Manipulation'
        mitre_tactic = 'persistence'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any security-relevant attribute change without a corresponding documented change ticket.'
        mitre_data_sources = @('Active Directory', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'persistence'
        default_reasoning = @('Undocumented changes to security-relevant AD object attributes may indicate attacker manipulation of the directory.')
        detection_logic = 'Enumerates AD object-modification events within the collector''s lookback window.'
        detection_threshold = 'n/a — every recorded event within the lookback window is captured; suspicion evaluated per-change.'
        false_positive_notes = 'AD generates a high baseline volume of routine, benign object changes as part of normal operation; meaningful signal requires filtering to security-relevant attributes.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Filter to security-relevant attribute changes and confirm each against a documented change ticket.'; reason = 'Surfaces lower-visibility attacker manipulation of AD objects.' }
        )
        investigation_questions = @('Does any security-relevant attribute change lack a corresponding documented ticket?', 'Was the change performed by an account without a normal administrative reason to modify that object?')
        findingtags = @('persistence', 'live-response')
    }
    "ad-wmi-subs" = @{
        finding_type = 'WMI Permanent Event Subscriptions'
        category = 'Active Directory'
        subcategory = 'Persistence'
        title = 'WMI Permanent Event Subscriptions'
        description = 'Permanent WMI event subscriptions (filter, consumer, and binding) configured on the host or domain, a well-known fileless persistence mechanism.'
        why_this_matters = 'WMI permanent event subscriptions execute code automatically in response to a system event, entirely fileless (config lives in the WMI repository, not on disk) and are frequently missed by traditional autoruns-style tooling.'
        expected_normal_behaviour = 'No permanent subscriptions, or a small, documented set installed by legitimate management/monitoring software.'
        investigator_notes = 'Give particular scrutiny to any CommandLineEventConsumer or ActiveScriptEventConsumer, since these directly execute attacker-supplied code, unlike the more benign LogFileEventConsumer.'
        what_is_this = 'Persistent WMI __EventFilter, __EventConsumer, and __FilterToConsumerBinding objects stored in the WMI repository, which cause specified code/commands to run automatically whenever their filter condition is met.'
        why_it_exists = 'WMI eventing provides a legitimate, supported mechanism for management software to react automatically to system events (e.g., triggering an action when a new process starts).'
        normal_behaviour = 'No subscriptions, or a small, documented set tied to legitimate management/monitoring software.'
        suspicious_behaviour = 'Any subscription not accounted for by known, legitimate software, especially a CommandLineEventConsumer or ActiveScriptEventConsumer with an encoded/obfuscated command.'
        common_attack_usage = 'WMI permanent event subscriptions are a well-documented, stealthy, fileless persistence technique that survives reboots and evades traditional file-based and Run-key-based detection entirely.'
        mitre_technique_id = 'T1546.003'
        mitre_technique = 'Event Triggered Execution: Windows Management Instrumentation Event Subscription'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Windows Management Instrumentation Event Subscription'
        mitre_detection_notes = 'Enumerate all __EventFilter/__EventConsumer/__FilterToConsumerBinding objects and flag any not accounted for by known management software, prioritizing CommandLineEventConsumer/ActiveScriptEventConsumer.'
        mitre_data_sources = @('WMI Objects')
        base_risk_score = 40
        mitre_bucket = 'persistence'
        default_reasoning = @('Unrecognized permanent WMI event subscriptions are a well-known, stealthy, fileless persistence mechanism that evades traditional autoruns-based detection.')
        detection_logic = 'Enumerates all permanent WMI event filter/consumer/binding objects present in the WMI repository at collection time.'
        detection_threshold = 'n/a — every subscription is captured; suspicion driven by comparison against known legitimate software.'
        false_positive_notes = 'Legitimate management, monitoring, and some antivirus software install their own permanent WMI subscriptions as part of normal operation.'
        recommendations = @(
            @{ priority = 'High'; action = 'Validate every subscription''s consumer type and command/script content against known, legitimate software.'; reason = 'Identifies stealthy, fileless attacker persistence that evades traditional detection.' }
        )
        investigation_questions = @('Is every WMI event subscription accounted for by known, legitimate management software?', 'Does any CommandLineEventConsumer or ActiveScriptEventConsumer contain an encoded or obfuscated command?')
        findingtags = @('persistence', 'malware', 'live-response')
    }
    "ad-suspicious-proc" = @{
        finding_type = 'Known AD Attack Tooling (Process Cross-Check)'
        category = 'Active Directory'
        subcategory = 'Tooling Detection'
        title = 'Known AD Attack Tooling (Process Cross-Check)'
        description = 'Cross-check of the running/recent process list against known AD-attack tool names and signatures (Mimikatz, Rubeus, DCSync tools, BloodHound collectors, etc.).'
        why_this_matters = 'Direct execution of a recognized AD-attack tool is close to definitive evidence of an active, ongoing AD compromise attempt, independent of whether the attempt succeeded.'
        expected_normal_behaviour = 'No matches, except in a documented, authorized penetration test or red-team engagement.'
        investigator_notes = 'Confirm whether an authorized penetration test or red-team exercise is scheduled before escalating — otherwise treat any match as a confirmed, active attack.'
        what_is_this = 'A cross-reference of running and recently-executed process names/hashes against a curated list of well-known offensive AD tooling.'
        why_it_exists = 'Provides a fast, high-confidence tripwire for the specific, well-known tools most commonly used to exploit the AD misconfigurations detected by the other findings in this category.'
        normal_behaviour = 'No matches under normal operation.'
        suspicious_behaviour = 'Any match at all, absent a documented, currently-active authorized penetration test or red-team engagement.'
        common_attack_usage = 'Tools like Mimikatz, Rubeus, and various DCSync/BloodHound-style collectors are the standard toolkit for exploiting the exact AD weaknesses (credential dumping, Kerberos ticket abuse, privilege-path discovery) this collector''s other AD findings are designed to detect.'
        mitre_technique_id = 'T1003'
        mitre_technique = 'OS Credential Dumping'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Treat every match as high-priority; confirm against any documented, currently-scheduled authorized security testing before treating as a confirmed attack.'
        mitre_data_sources = @('Process', 'Command Execution')
        base_risk_score = 55
        mitre_bucket = 'credential_access'
        default_reasoning = @('Direct execution of a recognized AD-attack tool is close to definitive evidence of an active, ongoing domain compromise attempt.')
        detection_logic = 'Cross-references running and recently-executed process names and known indicators against a curated list of well-known offensive AD tooling.'
        detection_threshold = 'n/a — any match is inherently high-priority.'
        false_positive_notes = 'Authorized penetration testing and red-team engagements are the only known legitimate source of a match; confirm against the current testing schedule.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm whether a match corresponds to an authorized, currently-scheduled penetration test or red-team engagement.'; reason = 'Distinguishes authorized security testing from an active, ongoing AD compromise attempt.' },
            @{ priority = 'High'; action = 'If no authorized engagement is confirmed, treat as an active incident and immediately investigate related AD findings for evidence of successful exploitation.'; reason = 'This process match is the strongest available corroboration that a related configuration weakness is actively being exploited right now.' }
        )
        investigation_questions = @('Is there a documented, currently-active authorized penetration test or red-team engagement that would explain this match?', 'Do the ad-spn, ad-delegation, or ad-dcsync findings show corroborating evidence of successful exploitation?')
        findingtags = @('credential-access', 'privilege-escalation', 'lateral-movement', 'live-response')
    }
    "mssql-services" = @{
        finding_type = 'SQL Server Service Inventory'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Service Inventory'
        description = 'Inventory of installed SQL Server services, their instance names, versions, and the account each service runs as.'
        why_this_matters = 'Establishes the baseline for every other MSSQL finding — the service account''s privilege level in particular determines the blast radius if the SQL Server instance itself is compromised.'
        expected_normal_behaviour = 'Documented SQL Server instances running as a dedicated, least-privileged service account (not LocalSystem or a Domain Admin account).'
        investigator_notes = 'A SQL Server service running as a highly-privileged domain account is a force-multiplier for every other MSSQL finding in this category — note it up front when scoping the investigation.'
        what_is_this = 'The set of installed SQL Server-related Windows services (Database Engine, Agent, Browser, Reporting Services, etc.) and their configuration.'
        why_it_exists = 'SQL Server installs as one or more Windows services; enumerating them establishes what database infrastructure is present on the host.'
        normal_behaviour = 'Documented instances running as a dedicated, least-privileged service account.'
        suspicious_behaviour = 'An undocumented SQL Server instance, or any instance running as LocalSystem or an overly-privileged domain account.'
        common_attack_usage = 'Attackers target SQL Server both as a data-theft objective in its own right and as a privilege-escalation/lateral-movement pivot when its service account is over-privileged.'
        mitre_technique_id = 'T1078'
        mitre_technique = 'Valid Accounts'
        mitre_tactic = 'persistence'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any SQL Server service account with LocalSystem or elevated domain privilege beyond least-privilege requirements.'
        mitre_data_sources = @('Service', 'Windows Registry')
        base_risk_score = 15
        mitre_bucket = 'persistence'
        default_reasoning = @('The SQL Server service account''s privilege level determines the blast radius if the database engine itself is compromised.')
        detection_logic = 'Static enumeration of installed SQL Server-related services and their run-as accounts at collection time.'
        detection_threshold = 'n/a — informational inventory establishing baseline for other MSSQL findings.'
        false_positive_notes = 'Some legacy or vendor-supplied SQL Server deployments still run as LocalSystem by design; verify against documented architecture before escalating.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Confirm each SQL Server service runs as a dedicated, least-privileged account rather than LocalSystem or an over-privileged domain account.'; reason = 'Limits the blast radius if the database engine is later compromised.' }
        )
        investigation_questions = @('Does any SQL Server service run as LocalSystem or an overly-privileged domain account?', 'Is every installed instance accounted for in documented database infrastructure?')
        findingtags = @('live-response')
    }
    "mssql-config" = @{
        finding_type = 'SQL Server Dangerous Configuration Options'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Dangerous Configuration Options'
        description = 'SQL Server configuration options known to enable OS-level code execution or other high-risk capability (xp_cmdshell, OLE Automation Procedures, Ad Hoc Distributed Queries, etc.).'
        why_this_matters = 'These options are the specific mechanisms that let a SQL injection or compromised-credential attack escalate from database access to full operating-system command execution on the server.'
        expected_normal_behaviour = 'All of these options disabled unless a specific, documented application requires one and compensating controls are in place.'
        investigator_notes = 'xp_cmdshell enabled is the single highest-priority item here — it provides direct, trivial OS command execution to anyone with sufficient SQL privilege.'
        what_is_this = 'A set of sp_configure options (xp_cmdshell, Ole Automation Procedures, Ad Hoc Distributed Queries, etc.) that extend SQL Server''s capability beyond pure database operations into OS-level interaction.'
        why_it_exists = 'These options exist to support specific, legitimate advanced use cases (running OS commands from a stored procedure, executing distributed queries), but each significantly expands SQL Server''s attack surface when enabled.'
        normal_behaviour = 'All disabled by default; enabled only where a specific, documented application need exists.'
        suspicious_behaviour = 'xp_cmdshell or another dangerous option enabled with no documented business justification.'
        common_attack_usage = 'Once an attacker has sufficient SQL privilege (via SQL injection, weak sa credentials, or a compromised application account), xp_cmdshell provides direct, immediate OS command execution as the SQL Server service account.'
        mitre_technique_id = 'T1505.001'
        mitre_technique = 'Server Software Component: SQL Stored Procedures'
        mitre_tactic = 'execution'
        mitre_sub_technique = 'SQL Stored Procedures'
        mitre_detection_notes = 'Flag xp_cmdshell or any other dangerous configuration option enabled without documented business justification.'
        mitre_data_sources = @('Application Log', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'execution'
        default_reasoning = @('Dangerous SQL Server configuration options like xp_cmdshell provide a direct path from database access to full OS command execution.')
        detection_logic = 'Queries sp_configure for the status of known dangerous configuration options at collection time.'
        detection_threshold = 'Any dangerous option enabled without documented business justification is the suspicious condition.'
        false_positive_notes = 'Some legacy applications genuinely require xp_cmdshell or another flagged option; verify against documented architecture before disabling.'
        recommendations = @(
            @{ priority = 'High'; action = 'Disable xp_cmdshell and any other dangerous configuration option lacking documented business justification.'; reason = 'Removes a direct path from database access to full OS command execution.' }
        )
        investigation_questions = @('Is xp_cmdshell enabled, and if so, is there a documented business justification?', 'Is there evidence of xp_cmdshell having been invoked (via SQL Server audit logs or resulting process creation events)?')
        findingtags = @('live-response')
    }
    "mssql-sysadmin" = @{
        finding_type = 'SQL Server sysadmin Role Members'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server sysadmin Role Members'
        description = 'Logins holding the sysadmin fixed server role, which grants unrestricted control over the entire SQL Server instance.'
        why_this_matters = 'sysadmin is to SQL Server what Domain Admin is to Active Directory — unrestricted control including the ability to enable xp_cmdshell and pivot to OS-level access.'
        expected_normal_behaviour = 'A small, well-documented list of DBA accounts only.'
        investigator_notes = 'Any application service account holding sysadmin (rather than the specific, scoped permissions it actually needs) is a common but serious over-privilege finding worth flagging even absent direct evidence of compromise.'
        what_is_this = 'The membership list of the sysadmin fixed server role, queryable via sys.server_role_members or sp_helpsrvrolemember.'
        why_it_exists = 'SQL Server provides sysadmin as the highest level of instance-wide administrative delegation.'
        normal_behaviour = 'Membership matching exactly the organization''s documented DBA list.'
        suspicious_behaviour = 'Any login present that isn''t a documented DBA, particularly an application service account or a login with a weak/shared password.'
        common_attack_usage = 'An attacker who compromises or brute-forces a sysadmin-privileged login gains complete control over the SQL Server instance, including the ability to enable xp_cmdshell for OS-level pivot.'
        mitre_technique_id = 'T1078'
        mitre_technique = 'Valid Accounts'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Diff sysadmin membership against the documented DBA baseline; flag any application service account present.'
        mitre_data_sources = @('Application Log', 'User Account')
        base_risk_score = 25
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('Unexpected sysadmin role membership grants unrestricted SQL Server control and a potential pivot to OS-level access.')
        detection_logic = 'Static enumeration of sysadmin fixed server role membership at collection time.'
        detection_threshold = 'n/a — every member is captured; suspicion driven by comparison against documented DBA baseline.'
        false_positive_notes = 'Some legacy applications are configured (against best practice) to connect using a sysadmin login rather than a scoped one; this is a real finding worth flagging even when ''expected'' by a poorly-architected app.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every sysadmin member against the documented DBA list and de-privilege any application service account found.'; reason = 'Limits the blast radius of a compromised login to something less than full instance control.' }
        )
        investigation_questions = @('Is every sysadmin member a documented DBA account?', 'Does any application service account hold sysadmin rather than a scoped permission set?')
        findingtags = @('live-response')
    }
    "mssql-linked" = @{
        finding_type = 'SQL Server Linked Servers'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Linked Servers'
        description = 'Configured linked server connections from this SQL Server instance to other database servers.'
        why_this_matters = 'Linked servers configured with stored credentials let an attacker who compromises this instance pivot directly to another database server, often with elevated privilege on the remote end.'
        expected_normal_behaviour = 'A small, documented set of linked servers required for legitimate cross-database application functionality.'
        investigator_notes = 'Check the authentication configuration for each link — a link using a stored sysadmin-equivalent credential on the remote server is a significant pivot risk even if this instance itself is only lightly compromised.'
        what_is_this = 'Server-to-server database connections configured via sp_addlinkedserver, allowing distributed queries to another SQL Server (or other) instance.'
        why_it_exists = 'Linked servers support legitimate cross-database application architectures that need to query or update data across multiple database instances.'
        normal_behaviour = 'A small, documented set of linked servers required for legitimate application functionality.'
        suspicious_behaviour = 'An undocumented linked server, or one configured with a stored credential that grants elevated privilege on the remote instance.'
        common_attack_usage = 'Attackers abuse a compromised instance''s linked servers (particularly via OPENQUERY/EXECUTE AT with an impersonation context) to pivot to and execute commands on the remote database server.'
        mitre_technique_id = 'T1210'
        mitre_technique = 'Exploitation of Remote Services'
        mitre_tactic = 'lateral_movement'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any undocumented linked server and review the privilege level of any stored remote credential.'
        mitre_data_sources = @('Application Log')
        base_risk_score = 25
        mitre_bucket = 'lateral_movement'
        default_reasoning = @('Linked server configurations may enable an attacker to pivot from this SQL Server instance to another database server.')
        detection_logic = 'Static enumeration of configured linked servers and their authentication configuration at collection time.'
        detection_threshold = 'n/a — every linked server is captured; suspicion driven by comparison against documented architecture.'
        false_positive_notes = 'Legitimate cross-database application architectures routinely and intentionally use linked servers.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Confirm each linked server against documented application architecture and review the remote credential''s privilege level.'; reason = 'Limits the lateral-pivot potential of a compromised instance.' }
        )
        investigation_questions = @('Is every configured linked server accounted for by documented application architecture?', 'What privilege level does the stored credential for each link hold on the remote server?')
        findingtags = @('lateral-movement', 'live-response')
    }
    "mssql-trustworthy" = @{
        finding_type = 'SQL Server TRUSTWORTHY Databases'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server TRUSTWORTHY Databases'
        description = 'Databases on the instance with the TRUSTWORTHY property set to ON.'
        why_this_matters = 'TRUSTWORTHY ON combined with a database owner mapped to a sysadmin-equivalent login is a well-known, direct privilege-escalation chain from db_owner-level access to full instance sysadmin.'
        expected_normal_behaviour = 'TRUSTWORTHY OFF for all databases except where a specific, documented feature (e.g., certain CLR integration scenarios) requires it.'
        investigator_notes = 'Check the database owner for any TRUSTWORTHY database — if the owner is sysadmin-equivalent, any db_owner-level user in that database can escalate to full sysadmin via a signed stored procedure.'
        what_is_this = 'The TRUSTWORTHY database property, which when ON allows database objects to access resources outside the database under the context of the database owner.'
        why_it_exists = 'Certain SQL Server features (cross-database ownership chaining, some CLR scenarios) require TRUSTWORTHY to be enabled to function.'
        normal_behaviour = 'TRUSTWORTHY OFF for all user databases unless a specific documented feature requires otherwise.'
        suspicious_behaviour = 'TRUSTWORTHY ON for any database with no documented feature requirement, especially when the database owner is a sysadmin-equivalent login.'
        common_attack_usage = 'An attacker with db_owner privilege in a TRUSTWORTHY database owned by a sysadmin-equivalent login can create a maliciously-signed stored procedure to escalate to full instance sysadmin — a well-documented SQL Server privilege-escalation chain.'
        mitre_technique_id = 'T1078'
        mitre_technique = 'Valid Accounts'
        mitre_tactic = 'privilege_escalation'
        mitre_sub_technique = ''
        mitre_detection_notes = 'For every TRUSTWORTHY database, check whether the database owner is a sysadmin-equivalent login.'
        mitre_data_sources = @('Application Log')
        base_risk_score = 40
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('TRUSTWORTHY ON combined with a sysadmin-equivalent database owner is a well-known privilege-escalation chain to full instance sysadmin.')
        detection_logic = 'Queries sys.databases for the is_trustworthy_on property across all databases at collection time.'
        detection_threshold = 'Any TRUSTWORTHY database owned by a sysadmin-equivalent login is the highest-priority condition.'
        false_positive_notes = 'Some legitimate CLR integration scenarios require TRUSTWORTHY ON; verify against documented application requirements.'
        recommendations = @(
            @{ priority = 'High'; action = 'Set TRUSTWORTHY OFF for any database without a specific documented feature requirement, or change the database owner to a non-privileged account.'; reason = 'Closes a well-known privilege-escalation chain from db_owner to instance sysadmin.' }
        )
        investigation_questions = @('Is any TRUSTWORTHY database owned by a sysadmin-equivalent login?', 'Is there a specific documented feature requiring TRUSTWORTHY to remain ON for this database?')
        findingtags = @('live-response')
    }
    "mssql-agent-jobs" = @{
        finding_type = 'SQL Server Agent Jobs (Risky Step Types)'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Agent Jobs (Risky Step Types)'
        description = 'SQL Server Agent jobs configured with a step type capable of OS-level execution (CmdExec, PowerShell, ActiveX Script).'
        why_this_matters = 'SQL Server Agent jobs run with the privilege of the job owner (or the SQL Server Agent service account), making a risky step type in an attacker-created job a direct, schedulable OS-execution and persistence mechanism.'
        expected_normal_behaviour = 'Job steps limited to T-SQL, with CmdExec/PowerShell/ActiveX steps limited to specific, documented maintenance jobs.'
        investigator_notes = 'A newly-created job with a CmdExec or PowerShell step and an encoded/obfuscated command is functionally equivalent to a scheduled-task-based persistence mechanism, and should be investigated with the same priority.'
        what_is_this = 'SQL Server Agent job steps configured with a subsystem type (CmdExec, PowerShell, ActiveX Script) capable of executing code outside the T-SQL engine.'
        why_it_exists = 'SQL Server Agent provides job scheduling for database maintenance and automation, and supports OS-level step types for legitimate operational scripting needs.'
        normal_behaviour = 'Risky step types limited to specific, documented maintenance jobs.'
        suspicious_behaviour = 'A newly-created job with a CmdExec/PowerShell/ActiveX step and no documented maintenance purpose, especially with an encoded or obfuscated command.'
        common_attack_usage = 'Attackers with sufficient SQL Server Agent privilege create or modify a job with a CmdExec/PowerShell step as a scheduled, potentially-privileged persistence and execution mechanism, functionally parallel to a Windows Scheduled Task.'
        mitre_technique_id = 'T1053.005'
        mitre_technique = 'Scheduled Task/Job: Scheduled Task'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Scheduled Task'
        mitre_detection_notes = 'Flag any job with a CmdExec/PowerShell/ActiveX step lacking a documented maintenance purpose, especially with an encoded command.'
        mitre_data_sources = @('Application Log', 'Scheduled Job')
        base_risk_score = 55
        mitre_bucket = 'persistence'
        default_reasoning = @('SQL Server Agent jobs with an OS-execution step type are a schedulable, potentially privileged persistence and execution mechanism when undocumented.')
        detection_logic = 'Enumerates all SQL Server Agent job steps and flags those using a CmdExec/PowerShell/ActiveX Script subsystem.'
        detection_threshold = 'n/a — every risky-type step is captured; suspicion driven by comparison against documented maintenance jobs.'
        false_positive_notes = 'Legitimate database maintenance automation routinely uses CmdExec/PowerShell steps for backup, ETL, and similar operational tasks.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm every CmdExec/PowerShell/ActiveX job step against documented maintenance purposes and decode any suspicious command.'; reason = 'Identifies attacker-scheduled, potentially privileged persistence disguised as a database maintenance job.' }
        )
        investigation_questions = @('Is every CmdExec/PowerShell/ActiveX job step accounted for by a documented maintenance purpose?', 'Does any flagged job step contain an encoded or obfuscated command?')
        findingtags = @('persistence', 'live-response')
    }
    "mssql-logins" = @{
        finding_type = 'SQL Server Logins (sa Status + Recency Review)'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Logins (sa Status + Recency Review)'
        description = 'All configured SQL Server logins, with specific attention to the built-in sa account''s status and each login''s recent usage.'
        why_this_matters = 'sa is the single most commonly targeted SQL Server login for brute-force and credential-stuffing attacks; its status (enabled/disabled, password age) is a critical baseline security control.'
        expected_normal_behaviour = 'The sa account disabled or renamed per hardening guidance, with all other logins accounted for by documented application/DBA needs.'
        investigator_notes = 'An enabled sa account is a standing risk independent of any other finding — check specifically whether it''s been used recently (last login time) as the strongest signal of active exploitation attempts.'
        what_is_this = 'The full SQL Server login inventory (SQL and Windows-authenticated), including the built-in sa account''s enabled/disabled state and last-login time.'
        why_it_exists = 'SQL Server maintains its own login store (for SQL-authenticated logins) alongside support for Windows-authenticated logins, all of which must be enumerated to assess the instance''s authentication attack surface.'
        normal_behaviour = 'sa disabled/renamed, and all other logins accounted for by documented need.'
        suspicious_behaviour = 'sa enabled with a recent last-login time inconsistent with any known legitimate DBA activity, or an unfamiliar SQL-authenticated login present.'
        common_attack_usage = 'Automated scanning and brute-force tools specifically target the well-known sa login on internet-reachable or improperly-segmented SQL Server instances as a primary initial-access vector.'
        mitre_technique_id = 'T1136'
        mitre_technique = 'Create Account'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag an enabled sa account and review its last-login time against known legitimate DBA activity windows.'
        mitre_data_sources = @('Application Log', 'User Account')
        base_risk_score = 25
        mitre_bucket = 'credential_access'
        default_reasoning = @('An enabled sa account is a standing, commonly-targeted risk; its recent usage pattern indicates whether active exploitation attempts have occurred.')
        detection_logic = 'Enumerates all configured SQL Server logins and specifically checks the sa account''s enabled state and last-login time.'
        detection_threshold = 'An enabled sa account is inherently notable; a recent, unexplained last-login further elevates priority.'
        false_positive_notes = 'Some legacy applications still require sa for compatibility; this remains a genuine risk worth flagging for remediation planning even when currently relied upon.'
        recommendations = @(
            @{ priority = 'High'; action = 'Disable or rename the sa account per SQL Server hardening guidance if not required by a documented legacy application.'; reason = 'Removes the single most commonly targeted SQL Server authentication attack surface.' }
        )
        investigation_questions = @('Is the sa account enabled, and if so, when was it last used?', 'Is any unfamiliar SQL-authenticated login present without a documented business need?')
        findingtags = @('live-response')
    }
    "mssql-login-failures" = @{
        finding_type = 'SQL Server Login Failures'
        category = 'Database'
        subcategory = 'SQL Server'
        title = 'SQL Server Login Failures'
        description = 'Failed SQL Server authentication attempts recorded in the SQL Server error log.'
        why_this_matters = 'A pattern of failed logins is direct evidence of a brute-force or credential-guessing attack against the database, often targeting sa or another high-value login specifically.'
        expected_normal_behaviour = 'Occasional, isolated failures tied to application misconfiguration or user typos.'
        investigator_notes = 'A high volume of failures concentrated against sa or another specific login, especially from an unfamiliar source IP, is the key pattern distinguishing an attack from routine application connectivity issues.'
        what_is_this = 'Login-failure entries recorded in the SQL Server error log, including the target login name and, where available, the source.'
        why_it_exists = 'SQL Server logs authentication failures by default to support troubleshooting and security monitoring of the instance''s authentication attempts.'
        normal_behaviour = 'Isolated failures tied to application misconfiguration or occasional user typos.'
        suspicious_behaviour = 'A high volume of failures in a short window against a single login (brute force), especially sa, or from an unfamiliar/external source.'
        common_attack_usage = 'Automated SQL Server brute-force and credential-stuffing tools generate a high volume of login failures as they attempt to guess valid credentials, most commonly targeting the well-known sa login.'
        mitre_technique_id = 'T1110'
        mitre_technique = 'Brute Force'
        mitre_tactic = 'credential_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag a high volume of login failures concentrated against a single login (especially sa) within a short window.'
        mitre_data_sources = @('Application Log')
        base_risk_score = 30
        mitre_bucket = 'credential_access'
        default_reasoning = @('A high volume of SQL Server login failures against a specific login indicates a brute-force or credential-guessing attack against the database.')
        detection_logic = 'Enumerates login-failure entries from the SQL Server error log within the collector''s lookback window.'
        detection_threshold = 'A high volume of failures in a short window against a single login is the key suspicious pattern.'
        false_positive_notes = 'Misconfigured application connection strings are a common, entirely benign source of a moderate volume of login failures.'
        recommendations = @(
            @{ priority = 'High'; action = 'Quantify failure volume and pattern against a specific login, especially sa, and cross-reference with any subsequent successful login.'; reason = 'Confirms or rules out an active brute-force attack, and whether it eventually succeeded.' }
        )
        investigation_questions = @('Is there a high volume of failures concentrated against a single login within a short window?', 'Did any of the failed attempts eventually succeed?')
        findingtags = @('live-response')
    }
    "sp-accounts" = @{
        finding_type = 'SharePoint Service & App Pool Accounts'
        category = 'Web Application'
        subcategory = 'SharePoint'
        title = 'SharePoint Service & App Pool Accounts'
        description = 'Service and IIS application pool accounts used by the SharePoint farm, with their privilege level.'
        why_this_matters = 'Establishes the baseline privilege that a successful web-shell or exploit against SharePoint would inherit — an over-privileged app pool account turns a web-layer compromise directly into a broader AD compromise.'
        expected_normal_behaviour = 'Dedicated, least-privileged managed service accounts, not highly-privileged domain accounts.'
        investigator_notes = 'Cross-reference each account''s AD group membership — a SharePoint app pool account that''s also a Domain Admin is a critical force-multiplier for any SharePoint-layer compromise.'
        what_is_this = 'The set of Windows accounts configured to run SharePoint''s Windows services and IIS application pools.'
        why_it_exists = 'SharePoint, like any IIS-hosted application, requires service and app pool identities to run under, ideally following least-privilege managed-account practice.'
        normal_behaviour = 'Dedicated, least-privileged managed service accounts.'
        suspicious_behaviour = 'A service or app pool account holding privileged AD group membership (Domain Admins or similar) with no documented justification.'
        common_attack_usage = 'Attackers who achieve code execution in the context of an over-privileged SharePoint service/app pool account inherit that same excessive privilege, turning a web-application compromise directly into broader domain compromise.'
        mitre_technique_id = 'T1078'
        mitre_technique = 'Valid Accounts'
        mitre_tactic = 'persistence'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Cross-reference each SharePoint service/app pool account against privileged AD group membership.'
        mitre_data_sources = @('Service', 'Active Directory')
        base_risk_score = 20
        mitre_bucket = 'privilege_escalation'
        default_reasoning = @('An over-privileged SharePoint service or app pool account turns a web-layer compromise directly into broader domain compromise.')
        detection_logic = 'Static enumeration of SharePoint service and IIS application pool run-as accounts at collection time.'
        detection_threshold = 'n/a — every account is captured; suspicion driven by AD group membership cross-reference.'
        false_positive_notes = 'Some legacy SharePoint farms use a single, broadly-privileged farm account by design, against current best practice but not necessarily indicating compromise.'
        recommendations = @(
            @{ priority = 'High'; action = 'Confirm no SharePoint service or app pool account holds unnecessary privileged AD group membership.'; reason = 'Limits the blast radius if the web application layer is later compromised.' }
        )
        investigation_questions = @('Does any SharePoint service or app pool account hold privileged AD group membership?')
        findingtags = @('live-response')
    }
    "sp-w3wp-children" = @{
        finding_type = 'Suspicious IIS Worker Process Children'
        category = 'Web Application'
        subcategory = 'SharePoint'
        title = 'Suspicious IIS Worker Process Children'
        description = 'Unexpected child processes spawned by the IIS worker process (w3wp.exe) hosting SharePoint.'
        why_this_matters = 'w3wp.exe should almost never spawn a shell or script interpreter — when it does, it is one of the strongest, most direct available indicators of successful web-shell or remote-code-execution exploitation against the web application.'
        expected_normal_behaviour = 'w3wp.exe with no child processes, or only children matching known, legitimate SharePoint/IIS internal operations.'
        investigator_notes = 'Treat any cmd.exe, powershell.exe, or similar interpreter spawned as a child of w3wp.exe as a confirmed, active web-shell/RCE compromise requiring immediate escalation — this is not a probabilistic indicator.'
        what_is_this = 'Process-tree analysis identifying child processes of the w3wp.exe (IIS worker process) instance(s) hosting SharePoint.'
        why_it_exists = 'Monitoring the process tree beneath a web application''s worker process is one of the most reliable ways to detect successful exploitation, since legitimate web application code essentially never needs to spawn a command shell.'
        normal_behaviour = 'No child processes, or only children matching known, legitimate internal SharePoint/IIS operations.'
        suspicious_behaviour = 'Any command shell, script interpreter, or unexpected binary spawned as a child of w3wp.exe.'
        common_attack_usage = 'A web shell or direct remote-code-execution exploit against SharePoint executes attacker commands in the context of the IIS worker process, which manifests as w3wp.exe spawning cmd.exe, powershell.exe, or a similar interpreter to run the attacker''s actual payload.'
        mitre_technique_id = 'T1505.003'
        mitre_technique = 'Server Software Component: Web Shell'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Web Shell'
        mitre_detection_notes = 'Alert immediately on any command shell or script interpreter spawned as a child of w3wp.exe.'
        mitre_data_sources = @('Process', 'Command Execution')
        base_risk_score = 55
        mitre_bucket = 'execution'
        default_reasoning = @('A command shell or script interpreter spawned as a child of the IIS worker process is close to definitive evidence of successful web-shell or RCE exploitation.')
        detection_logic = 'Analyzes the process tree for any child process of w3wp.exe and flags any command shell or script interpreter.'
        detection_threshold = 'n/a — any command shell/script interpreter child is inherently critical.'
        false_positive_notes = 'Extremely rare legitimate cause; some third-party SharePoint add-ins with poor architecture may shell out for specific functionality — verify against known, documented add-in behavior before ruling out compromise.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately capture the full command line and any dropped files associated with the spawned process.'; reason = 'Preserves the evidence needed to scope and remediate confirmed web-shell/RCE exploitation.' },
            @{ priority = 'High'; action = 'Isolate the affected server from the network pending investigation.'; reason = 'Prevents further attacker action while the confirmed compromise is investigated.' }
        )
        investigation_questions = @('What command line did the spawned interpreter execute, and what files did it read/write?', 'Can the initial exploitation vector (which SharePoint endpoint/vulnerability) be identified from IIS logs around this timestamp?')
        findingtags = @('malware', 'live-response')
    }
    "sp-webshell" = @{
        finding_type = 'SharePoint Webshell / Dropped File Scan'
        category = 'Web Application'
        subcategory = 'SharePoint'
        title = 'SharePoint Webshell / Dropped File Scan'
        description = 'Scan of SharePoint/IIS web-accessible directories for dropped web shell files.'
        why_this_matters = 'A web shell file gives an attacker persistent, authenticated-free remote code execution through the web application itself, independent of any other foothold — finding one is a confirmed, critical compromise.'
        expected_normal_behaviour = 'No unrecognized files in web-accessible content directories; only files that are part of the documented SharePoint deployment/customizations.'
        investigator_notes = 'Treat any match as a confirmed, critical-severity finding — this scan specifically targets file signatures/patterns associated with known web shell families, not a heuristic guess.'
        what_is_this = 'A signature and heuristic scan of SharePoint''s web-accessible content directories (LAYOUTS, wpresources, and similar) for files matching known web shell patterns.'
        why_it_exists = 'Web shells are commonly dropped directly into a web application''s content directories to blend in among legitimate application files while providing attacker remote access.'
        normal_behaviour = 'No matches — only recognized, documented application files present.'
        suspicious_behaviour = 'Any file matching a known web shell signature or exhibiting web-shell-like characteristics (e.g., dynamic code execution from a request parameter).'
        common_attack_usage = 'Attackers drop a web shell (often through an unpatched SharePoint deserialization or file-upload vulnerability) to establish durable, direct remote code execution through the web application layer, frequently as a follow-on from or alongside the w3wp.exe child-process finding.'
        mitre_technique_id = 'T1505.003'
        mitre_technique = 'Server Software Component: Web Shell'
        mitre_tactic = 'persistence'
        mitre_sub_technique = 'Web Shell'
        mitre_detection_notes = 'Any file matching a known web shell signature in a web-accessible directory should be treated as a confirmed critical finding.'
        mitre_data_sources = @('File')
        base_risk_score = 58
        mitre_bucket = 'persistence'
        default_reasoning = @('A file matching a known web shell signature in a web-accessible directory is confirmed evidence of persistent, unauthenticated remote code execution capability.')
        detection_logic = 'Signature- and heuristic-based scan of web-accessible SharePoint/IIS content directories for known web shell patterns.'
        detection_threshold = 'n/a — any signature match is inherently critical.'
        false_positive_notes = 'Legitimate diagnostic or admin utility pages occasionally trigger heuristic (non-signature) matches; prioritize confirmed signature matches over heuristic-only hits.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately preserve, isolate, and analyze the identified file, then remove it and identify the underlying vulnerability that allowed it to be dropped.'; reason = 'Removes confirmed attacker remote-access capability and prevents recurrence via the same vulnerability.' },
            @{ priority = 'High'; action = 'Review IIS logs for the earliest access to this file to establish a timeline and scope of compromise.'; reason = 'Determines how long the attacker has had this access and what else may have occurred during that window.' }
        )
        investigation_questions = @('When was the identified file first written, and what IIS log entries correspond to its earliest access?', 'What underlying vulnerability or misconfiguration allowed this file to be uploaded/written?')
        findingtags = @('malware', 'live-response')
    }
    "sp-webconfig" = @{
        finding_type = 'SharePoint web.config ViewState/machineKey Review'
        category = 'Web Application'
        subcategory = 'SharePoint'
        title = 'SharePoint web.config ViewState/machineKey Review'
        description = 'Review of SharePoint''s web.config ViewState and machineKey settings, which govern ASP.NET ViewState integrity/encryption.'
        why_this_matters = 'A leaked or weak machineKey enables the well-documented ViewState deserialization remote-code-execution attack chain against ASP.NET applications like SharePoint — this is a specific, high-impact configuration exposure.'
        expected_normal_behaviour = 'A unique, properly-randomized, non-default machineKey with ViewState MAC validation enabled.'
        investigator_notes = 'If the machineKey matches any publicly-known leaked/default key (several have been published and are actively scanned for by attackers), treat this as a critical, confirmed exposure requiring immediate remediation.'
        what_is_this = 'The <machineKey> and ViewState-related settings in SharePoint''s web.config, which control the cryptographic keys ASP.NET uses to validate and encrypt ViewState data.'
        why_it_exists = 'ASP.NET uses the machineKey to protect ViewState (client-side serialized page state) from tampering; SharePoint, like other ASP.NET applications, depends on this being properly and uniquely configured.'
        normal_behaviour = 'A unique, properly-randomized machineKey with ViewState MAC validation enabled.'
        suspicious_behaviour = 'A machineKey matching a known publicly-leaked/default value, or ViewState validation disabled.'
        common_attack_usage = 'If an attacker obtains or guesses the machineKey (several default/leaked keys are publicly known and actively scanned for), they can craft a malicious serialized ViewState payload that ASP.NET will deserialize and execute — a well-documented, critical RCE chain against SharePoint and other ASP.NET applications.'
        mitre_technique_id = 'T1190'
        mitre_technique = 'Exploit Public-Facing Application'
        mitre_tactic = 'initial_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Compare the configured machineKey against the list of publicly-known leaked/default keys.'
        mitre_data_sources = @('File', 'Application Log')
        base_risk_score = 45
        mitre_bucket = 'execution'
        default_reasoning = @('A leaked or default machineKey enables the well-documented ViewState deserialization RCE chain against SharePoint.')
        detection_logic = 'Parses web.config for the machineKey and ViewState validation settings, and compares the key against known publicly-leaked values.'
        detection_threshold = 'A match against any publicly-known leaked/default key is a critical, confirmed exposure.'
        false_positive_notes = 'A properly-randomized, unique machineKey with validation enabled is the expected, secure configuration and should not be flagged.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately rotate the machineKey to a newly-generated, unique value if it matches a known leaked/default key.'; reason = 'Closes a critical, actively-exploited RCE chain against the SharePoint application.' },
            @{ priority = 'High'; action = 'Review IIS/ULS logs for evidence of ViewState deserialization exploitation attempts.'; reason = 'Determines whether the exposure has already been exploited.' }
        )
        investigation_questions = @('Does the configured machineKey match any publicly-known leaked or default value?', 'Is there log evidence of ViewState deserialization exploitation attempts?')
        findingtags = @('live-response')
    }
    "sp-iis-exploit-uri" = @{
        finding_type = 'SharePoint Exploit URI Pattern Matches (IIS Logs)'
        category = 'Web Application'
        subcategory = 'SharePoint'
        title = 'SharePoint Exploit URI Pattern Matches (IIS Logs)'
        description = 'IIS log entries matching known SharePoint exploit URI patterns (e.g., ToolPane.aspx, specific CVE-associated request paths).'
        why_this_matters = 'This is the network-log-level corroboration for a SharePoint compromise — a matching request in the IIS logs provides an exact timestamp and source IP for when exploitation was attempted, which is essential for scoping.'
        expected_normal_behaviour = 'No matches against known exploit URI patterns; normal SharePoint traffic patterns only.'
        investigator_notes = 'Correlate the matched request''s source IP and timestamp directly against the w3wp.exe child-process and web-shell findings to build a complete exploitation timeline.'
        what_is_this = 'A pattern-matching scan of IIS log files for request URIs and parameters known to be associated with published SharePoint CVEs and exploit chains.'
        why_it_exists = 'IIS logs every HTTP request by default, providing a durable record of exactly which URIs were requested, by whom, and when — directly relevant when a specific request path is known to be associated with an exploit.'
        normal_behaviour = 'No matches; normal application traffic patterns only.'
        suspicious_behaviour = 'Any request matching a known SharePoint exploit URI pattern, especially from an unfamiliar or external source IP.'
        common_attack_usage = 'Attackers exploiting a specific SharePoint CVE send a request to a known-vulnerable endpoint (e.g., ToolPane.aspx in several published exploit chains) with a crafted payload — this leaves an exact, timestamped record in the IIS logs.'
        mitre_technique_id = 'T1190'
        mitre_technique = 'Exploit Public-Facing Application'
        mitre_tactic = 'initial_access'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Pattern-match IIS log request URIs against known SharePoint exploit paths and correlate the matching timestamp/source IP with other findings.'
        mitre_data_sources = @('Web Logs', 'Network Traffic')
        base_risk_score = 50
        mitre_bucket = 'execution'
        default_reasoning = @('A matching request in the IIS logs for a known SharePoint exploit URI pattern provides an exact timestamp and source for scoping exploitation.')
        detection_logic = 'Scans IIS log files for request URIs matching a curated list of known SharePoint exploit patterns.'
        detection_threshold = 'n/a — any pattern match is inherently notable and should be correlated with other findings.'
        false_positive_notes = 'Some exploit-pattern URIs overlap with legitimate SharePoint administrative functionality; correlate with actual exploitation evidence (web shell, w3wp.exe child processes) before concluding successful compromise.'
        recommendations = @(
            @{ priority = 'High'; action = 'Correlate the matched request''s timestamp and source IP with the sp-webshell and sp-w3wp-children findings.'; reason = 'Builds a complete exploitation timeline from initial request through any resulting code execution.' }
        )
        investigation_questions = @('What source IP made the matching request, and is it associated with known-malicious infrastructure?', 'Does the request''s timestamp align with the sp-w3wp-children or sp-webshell findings?')
        findingtags = @('live-response')
    }
    "bitlocker" = @{
        finding_type = 'BitLocker Encryption Status'
        category = 'Defense Evasion'
        subcategory = 'Disk Encryption'
        title = 'BitLocker Encryption Status'
        description = 'BitLocker encryption status and recovery key material for every volume on the host.'
        why_this_matters = 'An unencrypted volume on a device that should be encrypted is a direct data-exposure risk if the device is lost/stolen; recovery keys are also required for forensic disk access when a volume is encrypted.'
        expected_normal_behaviour = 'All volumes fully encrypted with protection on, per the organization''s device-encryption policy.'
        investigator_notes = 'Recovery keys collected here are sensitive material in their own right — handle and store this finding''s evidence with the same care as any other credential material.'
        what_is_this = 'Per-volume BitLocker status (encryption method, percentage, protection status, lock status) and recovery key/protector information from Get-BitLockerVolume/manage-bde.'
        why_it_exists = 'BitLocker provides full-volume encryption to protect data at rest against physical theft/loss of the device; this finding reports whether that protection is actually active.'
        normal_behaviour = 'All volumes fully encrypted with protection on, per organizational policy.'
        suspicious_behaviour = 'A volume that should be encrypted per policy showing as unencrypted or with protection suspended/off.'
        common_attack_usage = 'Unencrypted volumes directly expose data to anyone with physical access; attackers may also deliberately suspend BitLocker protection as a precursor to offline tampering with the volume.'
        mitre_technique_id = 'T1486'
        mitre_technique = 'Data Encrypted for Impact'
        mitre_tactic = 'defense_evasion'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Flag any policy-required volume showing as unencrypted or with protection suspended.'
        mitre_data_sources = @('Drive', 'Windows Registry')
        base_risk_score = 20
        mitre_bucket = 'impact'
        default_reasoning = @('Unencrypted volumes expose data to physical theft/loss; extracting recovery keys is also critical for forensic access to encrypted drives.')
        detection_logic = 'Static per-volume BitLocker status and recovery key inventory at collection time.'
        detection_threshold = 'Any policy-required volume not fully encrypted with protection on is the suspicious condition.'
        false_positive_notes = 'Some non-OS data volumes are legitimately excluded from encryption policy by design; verify against documented policy scope.'
        recommendations = @(
            @{ priority = 'Medium'; action = 'Enable and complete encryption for any policy-required volume currently unencrypted or with suspended protection.'; reason = 'Closes a direct data-exposure risk for lost/stolen devices.' },
            @{ priority = 'High'; action = 'Store recovery keys collected by this finding with the same access controls applied to other credential material.'; reason = 'Prevents this evidence itself from becoming a new credential-exposure risk.' }
        )
        investigation_questions = @('Is any policy-required volume unencrypted or showing suspended protection?', 'Was BitLocker protection recently suspended, and if so, by whom and for what documented reason?')
        findingtags = @('ransomware', 'data-exfiltration', 'live-response')
    }
    "sigma" = @{
        finding_type = 'Sigma Rule Matches'
        category = 'Detection'
        subcategory = 'Rule-Based Detection'
        title = 'Sigma Rule Matches'
        description = 'Event log matches against the collector''s loaded Sigma detection rule set, covering a broad range of known attack techniques.'
        why_this_matters = 'Sigma rules encode community-vetted detection logic for specific, known-malicious behaviors across the event logs; each match is the product of purpose-built detection engineering rather than generic anomaly scoring.'
        expected_normal_behaviour = 'No matches, or only matches against low-severity rules that reflect benign administrative activity the specific rule author noted as a common false-positive source.'
        investigator_notes = 'Severity for this finding type should be driven by the specific rule that matched (its own documented level), not a blanket value — a match against a critical-level rule (e.g., credential dumping) deserves materially higher priority than a match against an informational-level rule.'
        what_is_this = 'Matches produced by running the collector''s embedded Sigma detection engine against the host''s collected event logs, where each rule encodes a specific, documented detection pattern for a known technique.'
        why_it_exists = 'Sigma is a widely-adopted, community-maintained generic signature format for log-based detection, letting the collector apply a broad, continuously-updated library of known-attack detection logic without custom-coding each one.'
        normal_behaviour = 'No matches, or only expected matches against rules with documented common false-positive sources relevant to this environment.'
        suspicious_behaviour = 'A match against any medium-or-higher severity rule, particularly rules covering credential access, lateral movement, or defense evasion.'
        common_attack_usage = 'Sigma''s rule library specifically encodes detection logic for the most common attacker techniques observed across the community — a match indicates behavior matching one of these well-documented patterns occurred in the collected logs.'
        mitre_technique_id = 'T1059'
        mitre_technique = 'Command and Scripting Interpreter'
        mitre_tactic = 'execution'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Severity should be derived from the specific matched rule''s own documented level field, not a single blanket value across all matches.'
        mitre_data_sources = @('Command Execution', 'Process', 'Windows Registry')
        base_risk_score = 10
        mitre_bucket = 'execution'
        default_reasoning = @('Sigma findings can indicate potential security threats based on predefined, community-vetted detection rules; per-match severity should reflect the specific rule''s documented level.')
        detection_logic = 'Runs the collector''s embedded Sigma rule set against collected event logs and reports every match with its source rule''s ID, title, and documented level.'
        detection_threshold = 'Any rule match is reported; downstream severity/priority should scale with the specific rule''s own level rather than a fixed value.'
        false_positive_notes = 'Individual Sigma rules vary widely in false-positive rate; consult the specific matched rule''s own documentation/known-FPs for context before escalating.'
        recommendations = @(
            @{ priority = 'High'; action = 'Prioritize triage by the matched rule''s own documented severity level rather than treating all matches uniformly.'; reason = 'Focuses limited analyst time on the highest-confidence, highest-impact matches first.' }
        )
        investigation_questions = @('What is the documented severity level of the specific rule(s) that matched?', 'Does the matched event correlate with other findings in the same investigation timeframe?')
        findingtags = @('malware', 'ransomware', 'credential-access', 'lateral-movement', 'live-response')
    }
    "hash-match" = @{
        finding_type = 'Malicious Hash Matches'
        category = 'Defense Evasion'
        subcategory = 'File Reputation'
        title = 'Malicious Hash Matches'
        description = 'Files on the endpoint whose MD5/SHA256 hash matched a known-malicious hash from the collector''s threat intelligence feed.'
        why_this_matters = 'A hash match is definitive, not probabilistic — it confirms the exact file present is byte-for-byte identical to a previously-catalogued malicious sample, making this one of the highest-confidence finding types in the entire collector.'
        expected_normal_behaviour = 'No matches under normal, uncompromised operation.'
        investigator_notes = 'Severity should scale with the number of distinct matches — a single match may be an isolated artifact, while multiple distinct malicious files present is a strong signal of a broader, more developed compromise.'
        what_is_this = 'A comparison of every scanned file''s cryptographic hash against the collector''s loaded threat intelligence hash database (md5hashes.txt / sha256hashes.txt).'
        why_it_exists = 'Hash-based matching provides a fast, zero-ambiguity way to identify known-malicious files without needing to analyze their behavior or content.'
        normal_behaviour = 'No matches.'
        suspicious_behaviour = 'Any match at all is inherently suspicious by construction of this finding.'
        common_attack_usage = 'Confirmed malware, previously-catalogued attacker tooling, and known exploit binaries are all directly identified by this mechanism whenever the exact same file (not just a variant) is present on the endpoint.'
        mitre_technique_id = 'T1204'
        mitre_technique = 'User Execution'
        mitre_tactic = 'execution'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Every match is definitive; scale downstream severity/priority with the number of distinct matches found.'
        mitre_data_sources = @('File')
        base_risk_score = 10
        mitre_bucket = 'execution'
        default_reasoning = @('Files matching known malicious hashes indicate the confirmed presence of previously-catalogued malware or threat tools on the endpoint, with severity scaling by match count.')
        detection_logic = 'Computes MD5/SHA256 for scanned files and checks each against the loaded threat intelligence hash database.'
        detection_threshold = 'Any single match is confirmed-malicious by definition; the collector scales severity by the number of distinct files matched.'
        false_positive_notes = 'Hash-based matching against a well-maintained, high-confidence threat intel feed has an extremely low false-positive rate by design.'
        recommendations = @(
            @{ priority = 'High'; action = 'Immediately isolate the affected file(s) and the host pending full investigation.'; reason = 'Prevents further execution or spread of a confirmed-malicious file.' },
            @{ priority = 'High'; action = 'Identify how the file arrived (download, email attachment, USB, lateral transfer) using the new-files/downloads and network findings.'; reason = 'Establishes the initial-access or propagation vector for remediation.' }
        )
        investigation_questions = @('How many distinct malicious files were matched, and does the count suggest a broader compromise?', 'How did each matched file arrive on the endpoint (correlate with downloads, new-files, and network findings)?')
        findingtags = @('malware', 'ransomware', 'live-response')
    }
    "ioc-url" = @{
        finding_type = 'Malicious URL / IOC Hits'
        category = 'Command and Control'
        subcategory = 'Threat Intelligence Matching'
        title = 'Malicious URL / IOC Hits'
        description = 'Browser history entries matching a known-malicious URL from the collector''s threat intelligence feed.'
        why_this_matters = 'Confirms actual browser contact with a previously-catalogued malicious URL, corroborating phishing, C2 panel access, or malware-download activity with a specific, timestamped visit rather than just the presence of the URL in general history.'
        expected_normal_behaviour = 'No matches under normal browsing activity.'
        investigator_notes = 'Severity should scale with the number of distinct hits — a single visit may reflect an accidental click, while multiple hits across sessions suggests sustained C2 communication or repeated malicious redirection.'
        what_is_this = 'A comparison of every browser history URL against the collector''s loaded threat intelligence URL feed (malicious_URLs.txt and custom_iocs.txt).'
        why_it_exists = 'URL-based matching provides direct confirmation of contact with previously-catalogued malicious infrastructure, complementing the broader, unfiltered browser-history finding.'
        normal_behaviour = 'No matches.'
        suspicious_behaviour = 'Any match at all is inherently suspicious by construction of this finding.'
        common_attack_usage = 'Phishing link clicks, drive-by download pages, and browser-based C2 panel access all leave a directly-matchable entry in browser history when the destination URL is present in threat intelligence.'
        mitre_technique_id = 'T1071'
        mitre_technique = 'Application Layer Protocol'
        mitre_tactic = 'command_and_control'
        mitre_sub_technique = ''
        mitre_detection_notes = 'Every match is definitive; scale downstream severity/priority with the number of distinct hits and their recency.'
        mitre_data_sources = @('Network Traffic', 'Browser Extensions')
        base_risk_score = 10
        mitre_bucket = 'impact'
        default_reasoning = @('Browser visits to known malicious URLs confirm phishing, C2 communication, or malware download activity, with severity scaling by hit count.')
        detection_logic = 'Compares every browser history URL against the loaded threat intelligence URL feed and reports every match.'
        detection_threshold = 'Any single match is confirmed-malicious by definition; the collector scales severity by the number of distinct hits.'
        false_positive_notes = 'URL-based matching against a well-maintained, high-confidence threat intel feed has a low false-positive rate, though URL shorteners/redirectors can occasionally cause benign overlap — verify the final landing page where relevant.'
        recommendations = @(
            @{ priority = 'High'; action = 'Identify the browser, profile, and exact visit timestamp for each hit and correlate with any resulting download or new-file findings.'; reason = 'Establishes whether the visit resulted in a follow-on compromise (malware download, credential entry on a phishing page).' },
            @{ priority = 'High'; action = 'Block the matched URL/domain at the network perimeter if not already blocked.'; reason = 'Prevents further contact with confirmed-malicious infrastructure from this or other hosts.' }
        )
        investigation_questions = @('How many distinct malicious URL hits occurred, and over what time span?', 'Did any hit correlate with a subsequent malicious file download or new-executable finding?')
        findingtags = @('malware', 'data-exfiltration', 'lateral-movement', 'live-response')
    }
}
