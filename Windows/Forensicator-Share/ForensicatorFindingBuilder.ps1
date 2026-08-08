# ═══════════════════════════════════════════════════════════════════════════
# ForensicatorFindingBuilder.ps1
#
# Single source of truth for turning a raw collection result into a fully
# enriched finding JSON object: severity/risk scoring, MITRE ATT&CK mapping,
# IOC/relationship extraction, and evidence-derived timestamps.
#
# Get-ForensicatorRiskAssessment is the one place a 0-100 score becomes both
# `severity` (Important/Notable/Interesting/Informational) and `risk.level`
# (Critical/High/Medium/Low) — every finding type derives both from the same
# score instead of each collection block picking its own pair by hand, which
# previously let the two vocabularies drift out of sync for a given finding.
#
# New-ForensicatorFinding assembles the full finding object in one place so
# every finding type gets the same schema by construction. Existing fields
# (finding_id, category, host, source, summary, evidence, ai_analysis,
# metadata, timeline, risk.level, risk.reason, mitre) keep their established
# shape; everything else here is additive.
# ═══════════════════════════════════════════════════════════════════════════

# ── Risk assessment: the one place severity/risk.level get derived ─────────

# Score → (severity, risk.level) boundaries. Every finding type derives both
# vocabularies from this one mapping instead of picking them independently.
function Get-ForensicatorSeverityForScore {
    param([Parameter(Mandatory)][int]$Score)
    if ($Score -ge 80) { return @{ severity = "Important";     level = "Critical"; likelihood = "Likely";   impact = "High" } }
    if ($Score -ge 60) { return @{ severity = "Notable";       level = "High";     likelihood = "Possible"; impact = "Medium" } }
    if ($Score -ge 35) { return @{ severity = "Interesting";   level = "Medium";   likelihood = "Possible"; impact = "Low" } }
    return                     @{ severity = "Informational"; level = "Low";      likelihood = "Unlikely"; impact = "Low" }
}

# The 7 tactic buckets used in risk_scoring. A finding's score is assigned
# to the single closest bucket rather than spread across all 7, even when it
# doesn't cleanly map to one attack technique (most routine inventory/
# discovery artifacts don't) — score should concentrate where the evidence
# actually points, not get diluted evenly.
$Script:ForensicatorRiskBuckets = @(
    "execution", "persistence", "credential_access", "lateral_movement",
    "privilege_escalation", "defense_evasion", "impact"
)

<#
.SYNOPSIS
    Derives severity, risk, and risk_scoring from one 0-100 score — the
    single source of truth every finding type calls into instead of
    hand-picking severity and risk.level separately.
.PARAMETER Score
    0-100. Higher = more severe.
.PARAMETER MitreBucket
    Which of the 7 risk_scoring buckets this finding's score belongs to.
    Defaults to "impact" for findings with no clear attack-technique tie.
.PARAMETER Reasoning
    One or more short sentences explaining the score. First item is also
    exposed as risk.reason (singular) for consumers that expect a single
    reason string alongside risk.level.
#>
function Get-ForensicatorRiskAssessment {
    param(
        [Parameter(Mandatory)][int]$Score,
        [ValidateSet("execution", "persistence", "credential_access", "lateral_movement",
                     "privilege_escalation", "defense_evasion", "impact")]
        [string]$MitreBucket = "impact",
        [Parameter(Mandatory)][string[]]$Reasoning,
        [int]$Confidence = 85
    )

    if ($Score -lt 0)   { $Score = 0 }
    if ($Score -gt 100) { $Score = 100 }

    $band = Get-ForensicatorSeverityForScore -Score $Score

    $buckets = [ordered]@{}
    foreach ($b in $Script:ForensicatorRiskBuckets) { $buckets[$b] = 0 }
    $buckets[$MitreBucket] = $Score
    $buckets["total"] = $Score

    return @{
        severity     = $band.severity
        risk         = @{
            score      = $Score
            level      = $band.level
            severity   = $band.level
            confidence = $Confidence
            likelihood = $band.likelihood
            impact     = $band.impact
            reason     = $Reasoning[0]
            reasoning  = $Reasoning
        }
        risk_scoring = $buckets
    }
}

# ── Artifact knowledge base ─────────────────────────────────────────────────
#
# One entry per finding type, keyed by finding_id's stable prefix (e.g.
# "net-ip-address" for "net-ip-address-001"). Holds everything about a
# finding TYPE that doesn't vary per collection run — the explanation text,
# MITRE mapping, recommendations, and the base risk score a finding of this
# type starts from before any per-instance adjustment. Populated by
# ForensicatorArtifactKnowledgeBase.ps1, dot-sourced here to keep this file
# focused on mechanism rather than content.
. "$PSScriptRoot\ForensicatorArtifactKnowledgeBase.ps1"

# Optional, opt-in per-instance AI verdicts (config.json "ai" block). See
# ForensicatorAiClient.ps1 for provider support and the off-by-default design.
. "$PSScriptRoot\ForensicatorAiClient.ps1"

# ── Collection-quality wrapper ──────────────────────────────────────────────

<#
.SYNOPSIS
    Runs a collection scriptblock and reports whether it actually
    succeeded, instead of the codebase's existing pattern of empty
    catch{} blocks / -ErrorAction SilentlyContinue silently discarding
    the failure. Every collection command that currently runs bare goes
    through this instead.
.OUTPUTS
    @{ Result = <scriptblock output, or $null>; Quality = <evidence_quality hashtable> }
#>
function Invoke-ForensicatorCollection {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [string]$Description = ""
    )

    $quality = @{
        confidence          = 95
        collection_complete = $true
        tamper_detected     = $false
        missing_data        = @()
    }

    try {
        $result = & $Action
        return @{ Result = $result; Quality = $quality }
    }
    catch {
        $quality.collection_complete = $false
        $quality.confidence = 40
        $quality.missing_data = @($Description)
        Write-ForensicLog "[!] Collection failed: $Description — $($_.Exception.Message)" -Level WARN -Section "COLLECTION"
        return @{ Result = $null; Quality = $quality }
    }
}

# ── Finding constructor ─────────────────────────────────────────────────────

<#
.SYNOPSIS
    Assembles a fully enriched finding object: identity, MITRE mapping,
    severity/risk scoring, evidence, IOCs, relationships, timeline, and
    recommendations — populated from the ArtifactKnowledgeBase entry for
    -ArtifactKey plus the per-run inputs supplied here.
.PARAMETER ArtifactKey
    Lookup key into $Script:ArtifactKnowledgeBase (finding_id's prefix,
    e.g. "net-ip-address").
.PARAMETER FindingIdSuffix
    Appended to ArtifactKey to form finding_id, default "001" (matches
    every existing finding_id today — kept as a parameter for finding
    types that may need multiple instances per run in future).
.PARAMETER Evidence
    Array/List of evidence row objects — unchanged from today's shape.
.PARAMETER Timeline
    Array of @{timestamp; event} objects. Defaults to one entry describing
    the collection itself, matching every existing finding today.
.PARAMETER ScoreOverride / ReasoningOverride / MitreBucketOverride
    Let a specific run override the knowledge base's base_risk_score /
    default reasoning — used by the handful of finding types that need
    genuine per-instance scoring (Sigma severity from the matched rule,
    hash-match count, malicious URL hit count) rather than a fixed
    per-type score.
.PARAMETER CollectionQuality
    Optional @{confidence; collection_complete; tamper_detected;
    missing_data} from Invoke-ForensicatorCollection — merged into
    evidence_quality. Defaults to a clean "collection succeeded" quality
    object if omitted.
.PARAMETER Relationships
    Optional @{related_processes; related_users; related_ips; related_files}
    override — auto-derived from Evidence's common fields when omitted
    (see Get-ForensicatorRelationshipsFromEvidence below).
#>

<#
.SYNOPSIS
    Safely normalizes any evidence-shaped input (List[object], plain array,
    single object, $null) into a System.Object[]. Deliberately avoids the
    @() array-subexpression operator: on some PowerShell/.NET builds, @($list)
    throws "Argument types do not match" when $list is a
    System.Collections.Generic.List[object] constructed via the `New-Object`
    cmdlet rather than `[List[object]]::new()` — both forms are used
    interchangeably throughout Forensicator.ps1 and are otherwise
    indistinguishable (same type name, same iteration/indexing/.Count
    behavior), so this avoids the operator entirely rather than detecting
    which construction form was used.
#>
function ConvertTo-ForensicatorArray {
    param($InputObject)

    # The leading comma on every return below is not decorative: without it,
    # `return $someArray` auto-unwraps a ONE-ELEMENT array into the bare
    # element itself — a common case, since many finding types collect
    # exactly one evidence row — which silently turns evidence into a bare
    # object instead of a single-element array for downstream JSON consumers
    # that require evidence to always be an array.
    if ($null -eq $InputObject) { return ,([System.Object[]]@()) }
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $out = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $InputObject) { $out.Add($item) }
        return ,$out.ToArray()
    }
    return ,([System.Object[]]@($InputObject))
}

<#
.SYNOPSIS
    Scans evidence rows for a real, parseable event timestamp — not the
    collection time — using the field names findings actually use across
    the collector (time, last_write_time, logon_time, install_date, etc.).
    Returns $null when no row has a recognizable time field, which is
    correct (not a bug) for static inventory findings (installed software,
    drives, environment variables) where there is no "event time" at all.
.OUTPUTS
    @{ First = <earliest [datetime] found>; Last = <latest> }, or $null.
#>
function Get-ForensicatorEvidenceTimeRange {
    param($Evidence)

    $timeFieldNames = @(
        'time', 'timestamp', 'time_created', 'logon_time', 'creation_time',
        'creation_time_utc', 'created', 'last_write_time', 'last_write_utc',
        'last_access', 'last_access_utc', 'last_visit', 'last_use_time',
        'last_logon', 'last_run_time', 'password_last_set', 'install_date',
        'installed_on', 'create_date', 'modify_date'
    )

    $earliest = $null
    $latest = $null
    $now = Get-Date

    foreach ($rawRow in $Evidence) {
        $row = ConvertTo-ForensicatorRowHashtable -Row $rawRow
        foreach ($fieldName in $timeFieldNames) {
            if (-not $row.Contains($fieldName) -or -not $row[$fieldName]) { continue }

            $parsed = [datetime]::MinValue
            $ok = [datetime]::TryParse(
                [string]$row[$fieldName], [System.Globalization.CultureInfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::None, [ref]$parsed
            )
            # Plausibility guard: rejects sentinel "never" values some Windows
            # APIs return (e.g. LastLogon = 1601-01-01) and anything nonsensically
            # in the future — neither is a real event time worth surfacing.
            if ($ok -and $parsed.Year -ge 2000 -and $parsed -le $now.AddDays(1)) {
                if (-not $earliest -or $parsed -lt $earliest) { $earliest = $parsed }
                if (-not $latest   -or $parsed -gt $latest)   { $latest   = $parsed }
            }
        }
    }

    if (-not $earliest) { return $null }
    return @{ First = $earliest; Last = $latest }
}

function New-ForensicatorFinding {
    param(
        [Parameter(Mandatory)][string]$ArtifactKey,
        [string]$FindingIdSuffix = "001",
        [Parameter(Mandatory)]$Evidence,
        [array]$Timeline,
        [int]$ScoreOverride = -1,
        [string[]]$ReasoningOverride,
        [string]$MitreBucketOverride,
        [hashtable]$CollectionQuality,
        [hashtable]$Relationships,
        [int]$TotalEntriesOverride = -1
    )

    $kb = $Script:ArtifactKnowledgeBase[$ArtifactKey]
    if (-not $kb) {
        Write-ForensicLog "[!] No ArtifactKnowledgeBase entry for '$ArtifactKey' — finding will be under-enriched" -Level WARN -Section "COLLECTION"
        $kb = @{
            finding_type = $ArtifactKey; category = "General"; title = $ArtifactKey
            description = ""; why_this_matters = ""; expected_normal_behaviour = ""
            what_is_this = ""; why_it_exists = ""; normal_behaviour = ""
            suspicious_behaviour = ""; common_attack_usage = ""
            mitre_technique_id = ""; mitre_technique = ""; mitre_tactic = ""
            mitre_sub_technique = ""; mitre_detection_notes = ""; mitre_data_sources = @()
            base_risk_score = 10; mitre_bucket = "impact"; default_reasoning = @("Routine collection artifact.")
            recommendations = @(); investigation_questions = @(); findingtags = @()
        }
    }

    $score = if ($ScoreOverride -ge 0) { $ScoreOverride } else { $kb.base_risk_score }
    $reasoning = if ($ReasoningOverride) { $ReasoningOverride } else { $kb.default_reasoning }
    $bucket = if ($MitreBucketOverride) { $MitreBucketOverride } else { $kb.mitre_bucket }

    $riskAssessment = Get-ForensicatorRiskAssessment -Score $score -MitreBucket $bucket -Reasoning $reasoning

    $evidenceArray = ConvertTo-ForensicatorArray -InputObject $Evidence
    $totalEntries = if ($TotalEntriesOverride -ge 0) { $TotalEntriesOverride } else { $evidenceArray.Count }

    if (-not $Timeline -or $Timeline.Count -eq 0) {
        # Prefer a real event timestamp pulled from the evidence itself (when
        # the evidence has one) over the collection time — the collection
        # time is nearly identical across all ~90 findings in a run (they're
        # all gathered within the same few minutes) and is useless for
        # reconstructing when things actually happened on the endpoint.
        # event_type distinguishes a real, evidence-derived timestamp from the
        # collection-time fallback for anything downstream that cares (see
        # Get-ForensicatorCaseSummary below) — without it, both kinds of entry
        # look identical and a real cross-finding timeline can't be told apart
        # from every finding's "just collected this" noise.
        $evidenceTimeRange = Get-ForensicatorEvidenceTimeRange -Evidence $evidenceArray
        if ($evidenceTimeRange) {
            $Timeline = @(@{ timestamp = $evidenceTimeRange.First.ToString("o"); event = "Earliest evidence timestamp in $($kb.title)"; event_type = "evidence" })
            if ($evidenceTimeRange.Last -ne $evidenceTimeRange.First) {
                $Timeline += @{ timestamp = $evidenceTimeRange.Last.ToString("o"); event = "Latest evidence timestamp in $($kb.title)"; event_type = "evidence" }
            }
        } else {
            $Timeline = @(@{ timestamp = (Get-Date).ToString("o"); event = "Forensicator collected $($kb.title) from endpoint"; event_type = "collection" })
        }
    }

    if (-not $CollectionQuality) {
        $CollectionQuality = @{ confidence = 95; collection_complete = $true; tamper_detected = $false; missing_data = @() }
    }

    if (-not $Relationships) {
        $Relationships = Get-ForensicatorRelationshipsFromEvidence -Evidence $evidenceArray
    }

    $mitreBlock = @{
        tactic          = $kb.mitre_tactic
        technique       = $kb.mitre_technique
        sub_technique   = $kb.mitre_sub_technique
        detection_notes = $kb.mitre_detection_notes
        data_sources    = @($kb.mitre_data_sources)
        references      = @("https://attack.mitre.org/techniques/$($kb.mitre_technique_id -replace '\.', '/')/")
        technique_id    = $kb.mitre_technique_id
    }

    $result = [ordered]@{
        finding_id        = "$ArtifactKey-$FindingIdSuffix"
        schema_version     = "2.0"
        collector_version  = $localVersion
        finding_type       = $kb.finding_type
        category           = $kb.category
        subcategory        = $kb.subcategory
        artifact           = $kb.title
        collector          = "Forensicator"
        platform           = "Windows"
        findingtags        = @($kb.findingtags)

        host = @{ hostname = $env:COMPUTERNAME; username = $env:USERNAME }

        summary = @{
            title                      = $kb.title
            description                = $kb.description
            why_this_matters           = $kb.why_this_matters
            expected_normal_behaviour  = $kb.expected_normal_behaviour
            investigator_notes         = $kb.investigator_notes
            total_entries              = $totalEntries
        }

        explanation = @{
            what_is_this          = $kb.what_is_this
            why_it_exists         = $kb.why_it_exists
            normal_behaviour      = $kb.normal_behaviour
            suspicious_behaviour  = $kb.suspicious_behaviour
            common_attack_usage   = $kb.common_attack_usage
        }

        severity     = $riskAssessment.severity
        risk         = $riskAssessment.risk
        risk_scoring = $riskAssessment.risk_scoring

        detection = @{
            rule                  = $kb.title
            logic                 = $kb.detection_logic
            threshold             = $kb.detection_threshold
            false_positive_notes  = $kb.false_positive_notes
        }

        evidence = $evidenceArray
        evidence_quality = $CollectionQuality

        mitre = @($mitreBlock)

        ioc = Get-ForensicatorIocsFromEvidence -Evidence $evidenceArray

        relationships = $Relationships

        timeline_context = @{
            first_seen = if ($Timeline.Count -gt 0) { $Timeline[0].timestamp } else { $null }
            last_seen  = if ($Timeline.Count -gt 0) { $Timeline[-1].timestamp } else { $null }
            duration   = $null
            sequence   = 0
        }

        attack_story = @{
            phase          = $kb.mitre_tactic
            previous_phase = $null
            next_phase     = $null
        }

        threat_intelligence = @{
            known_tool      = $false
            known_malware   = @()
            known_actors    = @()
            known_campaigns = @()
            references      = @()
        }

        enrichment = @{
            signed            = $null
            signature_vendor  = $null
            signature_status  = $null
            reputation        = $null
            prevalence        = $null
            first_seen        = $null
            last_seen         = $null
            lolbin            = $false
        }

        ai = @{
            summary                    = $null
            why_flagged                = $kb.why_this_matters
            investigation_questions    = @($kb.investigation_questions)
            recommended_next_steps     = @($kb.recommendations | ForEach-Object { $_.action })
            confidence                 = $null
        }

        human_context = @{
            plain_english      = $kb.description
            technical_summary  = $kb.what_is_this
            executive_summary  = $kb.why_this_matters
        }

        recommendations = @($kb.recommendations)

        analyst = @{
            notes          = ""
            disposition    = "unreviewed"
            false_positive = $false
            verified       = $false
        }

        ai_analysis = @{ status = "pending"; summary = $null; anomalies = @(); confidence = $null }

        metadata = @{
            collector_version = $localVersion
            collected_by       = "Forensicator"
            collection_time    = (Get-Date).ToString("o")
        }

        timeline = $Timeline
    }

    # Forensicator AI (optional, opt-in via config.json's "ai" block — see
    # ForensicatorAiClient.ps1). Never allowed to fail the finding itself:
    # Add-ForensicatorAiVerdict is a no-op when AI is disabled, and swallows
    # its own errors when enabled. Each call here is a real, synchronous LLM
    # request — potentially several seconds each (longer on a cold model
    # load) — run inline, one finding at a time, as every one of the ~90
    # checks completes. Progress is printed so a long run doesn't look
    # hung with no console feedback (the actual AI call itself has no
    # other visible output otherwise).
    if ((Get-Command Add-ForensicatorAiVerdict -ErrorAction SilentlyContinue) -and $Script:ForensicatorAiConfig -and $Script:ForensicatorAiConfig.enabled) {
        if (-not $Script:ForensicatorAiBannerShown) {
            $Script:ForensicatorAiBannerShown = $true
            Write-Host ""
            Write-Host "[*] Starting AI Analysis — each check's findings are sent to $($Script:ForensicatorAiConfig.provider)/$($Script:ForensicatorAiConfig.model) as they're collected." -ForegroundColor Yellow
            Write-Host "[*] This runs inline with acquisition and can noticeably extend total run time, especially on a cold-loaded model." -ForegroundColor Yellow
        }

        $Script:ForensicatorAiFindingCounter++
        $aiTotalLabel = if ($Script:ArtifactKnowledgeBase) { "$($Script:ForensicatorAiFindingCounter)/$($Script:ArtifactKnowledgeBase.Count)" } else { "$($Script:ForensicatorAiFindingCounter)" }
        # Two separate Write-Host calls (not one line built with -NoNewline)
        # deliberately: Add-ForensicatorAiVerdict can itself log a WARN via
        # Write-ForensicLog on failure (unreachable host, unknown provider)
        # in between these two lines — with -NoNewline that warning would
        # print mid-line and garble the console/transcript output.
        Write-Host "  [AI $aiTotalLabel] Analyzing '$($kb.title)'..." -ForegroundColor DarkGray

        $aiCallStart = Get-Date
        $result = Add-ForensicatorAiVerdict -ArtifactKey $ArtifactKey -Finding $result
        $aiCallMs = [Math]::Round(((Get-Date) - $aiCallStart).TotalMilliseconds)

        if ($result.ai_analysis.status -eq "complete") {
            Write-Host "  [AI $aiTotalLabel] Verdict received (${aiCallMs}ms)" -ForegroundColor DarkGreen
        } else {
            Write-Host "  [AI $aiTotalLabel] No verdict (${aiCallMs}ms)" -ForegroundColor DarkYellow
        }
    }
    elseif (Get-Command Add-ForensicatorAiVerdict -ErrorAction SilentlyContinue) {
        # AI disabled — still call it (as a fast no-op) so ai_analysis.status
        # stays consistent, just without any of the progress output above.
        $result = Add-ForensicatorAiVerdict -ArtifactKey $ArtifactKey -Finding $result
    }

    return $result
}

# ── IOC / relationship extraction from evidence ─────────────────────────────
#
# Every finding exposes observable IOCs and cross-finding relationships,
# derived once from whatever common field names already show up in the
# evidence rows (ip/hash/domain/url/process/user style keys already used
# throughout the collector) rather than hand-built per collection block.

<#
.SYNOPSIS
    Normalizes one evidence row to a hashtable so callers can always use
    $row[$key] indexing, regardless of whether the row started out as a
    hashtable (most finding types) or a [PSCustomObject] (e.g. browser
    history rows). Must reference $Row, not $_, when converting properties:
    $_ is unset inside a plain `foreach` loop (as opposed to a pipeline), so
    using it here would silently convert every non-hashtable row into an
    empty hashtable — and callers indexing into the result would then hit a
    terminating "index evaluated to null" error that
    $ErrorActionPreference = 'silentlycontinue' does not swallow
    (property-binding errors on $null aren't ordinary cmdlet errors).
#>
function ConvertTo-ForensicatorRowHashtable {
    param($Row)

    if ($Row -is [System.Collections.IDictionary]) { return $Row }
    if ($null -eq $Row) { return @{} }

    $out = @{}
    if ($Row.PSObject) {
        foreach ($prop in $Row.PSObject.Properties) { $out[$prop.Name] = $prop.Value }
    }
    return $out
}

function Get-ForensicatorIocsFromEvidence {
    param([array]$Evidence = @())

    $ips = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[string]
    $hashes = New-Object System.Collections.Generic.List[string]
    $domains = New-Object System.Collections.Generic.List[string]
    $processes = New-Object System.Collections.Generic.List[string]
    $registry = New-Object System.Collections.Generic.List[string]

    foreach ($rawRow in $Evidence) {
        $row = ConvertTo-ForensicatorRowHashtable -Row $rawRow
        foreach ($key in @('ip', 'ip_address', 'local_address', 'remote_address', 'src_ip', 'dst_ip', 'logon_ip', 'source_network_address', 'client', 'target_rdp_host')) {
            if ($row[$key]) { [void]$ips.Add([string]$row[$key]) }
        }
        foreach ($key in @('file_path', 'path', 'filename', 'file', 'full_path', 'detected_file')) {
            if ($row[$key]) { [void]$files.Add([string]$row[$key]) }
        }
        foreach ($key in @('sha256', 'sha1', 'md5', 'hash')) {
            if ($row[$key]) { [void]$hashes.Add([string]$row[$key]) }
        }
        foreach ($key in @('domain', 'url')) {
            if ($row[$key]) { [void]$domains.Add([string]$row[$key]) }
        }
        foreach ($key in @('process_name', 'process', 'image', 'executable_path', 'command_line')) {
            if ($row[$key]) { [void]$processes.Add([string]$row[$key]) }
        }
        foreach ($key in @('registry_key', 'registry_path', 'key')) {
            if ($row[$key]) { [void]$registry.Add([string]$row[$key]) }
        }
    }

    return @{
        processes       = @($processes | Select-Object -Unique)
        files           = @($files | Select-Object -Unique)
        hashes          = @($hashes | Select-Object -Unique)
        domains         = @($domains | Select-Object -Unique)
        ips             = @($ips | Select-Object -Unique)
        registry        = @($registry | Select-Object -Unique)
        services        = @()
        scheduled_tasks = @()
        mutexes         = @()
    }
}

function Get-ForensicatorRelationshipsFromEvidence {
    param([array]$Evidence = @())

    $users = New-Object System.Collections.Generic.List[string]
    $processes = New-Object System.Collections.Generic.List[string]
    $ips = New-Object System.Collections.Generic.List[string]
    $files = New-Object System.Collections.Generic.List[string]

    # Every field name below is a real "who did this" column used by at
    # least one of the ~90 real finding types — accounts, event-log subject/
    # target fields, service/task run-as identities, and file ownership all
    # use different names for the same concept across Windows APIs and the
    # collector's own commands, so this list has to be broad to actually
    # catch cross-finding correlation (e.g. rdp-logins' logon_user and
    # credman-backup's backup_account both being "jdoe").
    foreach ($rawRow in $Evidence) {
        $row = ConvertTo-ForensicatorRowHashtable -Row $rawRow
        foreach ($key in @(
            'username', 'user', 'account', 'target_user', 'logon_user',
            'backup_account', 'restored_account', 'created_user', 'created_by',
            'actioned_by', 'added_by', 'target', 'enabled_account', 'enabled_by',
            'disabled_account', 'disabled_by', 'deleted_account', 'deleted_by',
            'locked_out_account', 'subject_user', 'performed_by', 'performed_on',
            'user_id', 'owner', 'start_name', 'local_user'
        )) {
            if ($row[$key]) { [void]$users.Add([string]$row[$key]) }
        }
        foreach ($key in @('process_name', 'process', 'command_line')) {
            if ($row[$key]) { [void]$processes.Add([string]$row[$key]) }
        }
        foreach ($key in @('ip', 'ip_address', 'remote_address', 'logon_ip', 'source_network_address', 'client', 'target_rdp_host')) {
            if ($row[$key]) { [void]$ips.Add([string]$row[$key]) }
        }
        foreach ($key in @('file_path', 'path', 'full_path', 'detected_file')) {
            if ($row[$key]) { [void]$files.Add([string]$row[$key]) }
        }
    }

    return @{
        related_findings  = @()
        related_processes = @($processes | Select-Object -Unique)
        related_users     = @($users | Select-Object -Unique)
        related_ips       = @($ips | Select-Object -Unique)
        related_files     = @($files | Select-Object -Unique)
    }
}

# ── Case summary: one cross-finding rollup for the "Investigation Summary"
#    report page ──────────────────────────────────────────────────────────
#
# Deliberately NOT an LLM output. Every number and every list item here is
# computed directly from the same risk.score / risk_scoring / mitre /
# timeline_context data already on each finding — the same single source of
# truth Get-ForensicatorRiskAssessment established for individual findings.
# The one place an LLM gets involved for this page is
# Get-ForensicatorCaseSummaryNarrative (ForensicatorAiClient.ps1), and even
# then only to turn these already-computed facts into prose — never to
# invent a score, a timestamp, or a correlation that isn't already here.

<#
.SYNOPSIS
    Extracts every {ioc,relationships}.* array value from a finding, used
    to detect when two findings share a concrete indicator (same user, IP,
    hash, domain, file, process...).
#>
function Get-ForensicatorCorrelationKeys {
    param($Finding)

    $keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($section in @($Finding.ioc, $Finding.relationships)) {
        if (-not $section) { continue }
        foreach ($prop in $section.PSObject.Properties) {
            if ($prop.Value -isnot [array]) { continue }
            foreach ($v in $prop.Value) {
                $s = "$v".Trim()
                if ($s) { [void]$keys.Add($s) }
            }
        }
    }
    return $keys
}

<#
.SYNOPSIS
    Reads every finding JSON under an investigation folder and computes a
    cross-finding case summary: overall score/tier, per-tactic risk
    breakdown, investigation status counts, a real evidence-derived
    timeline + attack chain, top priorities, evidence correlation, known
    collection gaps, and aggregated next steps. See the file-level comment
    above for why none of this is LLM-generated.
.PARAMETER InvestigationPath
    Path to the investigation/ folder containing this run's *-finding.json
    files (metadata.json is skipped).
.PARAMETER AdditionalGaps
    Known collection gaps the caller already knows about (e.g. "-RAM not
    specified", "sqlcmd.exe not found") that can't be inferred from the
    finding JSON alone.
#>
function Get-ForensicatorCaseSummary {
    param(
        [Parameter(Mandatory)][string]$InvestigationPath,
        [string[]]$AdditionalGaps = @()
    )

    $findings = [System.Collections.Generic.List[object]]::new()
    if (Test-Path $InvestigationPath) {
        $files = Get-ChildItem -Path $InvestigationPath -Recurse -Filter "*.json" -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -ne "metadata.json" }
        foreach ($file in $files) {
            try {
                # -Raw is required here for the same reason it's required
                # everywhere else this collector reads JSON with Get-Content:
                # without it, ConvertFrom-Json can silently split one JSON
                # object into a multi-element array on PowerShell 7.
                $obj = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                # A finding JSON is written for every artifact type regardless of
                # whether anything was actually collected (base_risk_score reflects
                # "how bad IS this artifact type", not "did it occur") — so an
                # empty-evidence finding (e.g. credman-backup on a host with zero
                # such events) would otherwise still carry a high risk.score and
                # get treated as a real, confirmed finding here. Require actual
                # evidence before letting a finding influence the case summary.
                if ($obj.PSObject.Properties.Name -contains 'finding_id' -and $obj.risk -and @($obj.evidence).Count -gt 0) {
                    $findings.Add($obj)
                }
            }
            catch {
                Write-ForensicLog "[!] Case summary: could not parse $($file.Name) — skipping ($($_.Exception.Message))" -Level WARN -Section "CASE_SUMMARY"
            }
        }
    }

    if ($findings.Count -eq 0) {
        return @{
            HasData          = $false
            TotalFindings    = 0
            OverallScore     = 0
            OverallLevel     = "Low"
            RiskBreakdown    = @()
            Confirmed        = 0
            HighConfidence   = 0
            Correlated       = 0
            Gaps             = @($AdditionalGaps)
            Timeline         = @()
            AttackChain      = @()
            TopPriorities    = @()
            CorrelationPairs = @()
            NextSteps        = @()
            Confidence       = 0
            TopFindingTitle  = $null
        }
    }

    # ── Overall score: driven primarily by the single worst finding (a
    # forensic case is only as clean as its worst finding), with a small,
    # capped bonus for breadth — an intrusion that touches multiple ATT&CK
    # tactics is worse than one isolated high-scoring finding of the same
    # peak severity. ────────────────────────────────────────────────────
    $bucketMax = [ordered]@{}
    foreach ($b in $Script:ForensicatorRiskBuckets) { $bucketMax[$b] = 0 }

    $maxScore = 0
    $topFindingTitle = $null
    foreach ($f in $findings) {
        $s = [int]$f.risk.score
        if ($s -gt $maxScore) { $maxScore = $s; $topFindingTitle = "$($f.summary.title)" }
        foreach ($b in $Script:ForensicatorRiskBuckets) {
            $bv = $f.risk_scoring.$b
            if ($bv -and [int]$bv -gt $bucketMax[$b]) { $bucketMax[$b] = [int]$bv }
        }
    }

    $activeBucketCount = @($bucketMax.Values | Where-Object { $_ -ge 35 }).Count
    $overallScore = [Math]::Min(100, $maxScore + [Math]::Max(0, $activeBucketCount - 1) * 3)
    $overallBand = Get-ForensicatorSeverityForScore -Score $overallScore

    $riskBreakdownRaw = foreach ($b in $Script:ForensicatorRiskBuckets) {
        if ($bucketMax[$b] -le 0) { continue }
        $band = Get-ForensicatorSeverityForScore -Score $bucketMax[$b]
        [PSCustomObject]@{
            Bucket = ($b -replace '_', ' ')
            Score  = $bucketMax[$b]
            Level  = $band.level
        }
    }
    $riskBreakdown = @($riskBreakdownRaw | Sort-Object Score -Descending)

    # ── Correlation: findings that share a concrete indicator (user, IP,
    # hash, domain, file, process) with at least one other finding. ─────
    $correlationKeys = @{}
    foreach ($f in $findings) { $correlationKeys[$f.finding_id] = Get-ForensicatorCorrelationKeys -Finding $f }

    $correlatedIds = [System.Collections.Generic.HashSet[string]]::new()
    $correlationPairs = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $findings.Count; $i++) {
        for ($j = $i + 1; $j -lt $findings.Count; $j++) {
            $a = $findings[$i]; $b = $findings[$j]
            $aKeys = $correlationKeys[$a.finding_id]
            $bKeys = $correlationKeys[$b.finding_id]
            if ($aKeys.Count -eq 0 -or $bKeys.Count -eq 0) { continue }
            $shared = @($aKeys | Where-Object { $bKeys.Contains($_) })
            if ($shared.Count -gt 0) {
                [void]$correlatedIds.Add($a.finding_id)
                [void]$correlatedIds.Add($b.finding_id)
                $correlationPairs.Add([PSCustomObject]@{
                    A      = "$($a.summary.title)"
                    B      = "$($b.summary.title)"
                    Shared = ($shared | Select-Object -First 3) -join ", "
                })
            }
        }
    }

    # ── Timeline + attack chain: ONLY from findings whose timeline was
    # built from a real evidence timestamp (see Get-ForensicatorEvidenceTimeRange
    # in New-ForensicatorFinding) — never from the "just collected" fallback,
    # which would otherwise cluster every finding at the same few minutes
    # and produce a meaningless "timeline". ─────────────────────────────
    $timelineEvents = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $findings) {
        if ([int]$f.risk.score -lt 35) { continue }
        $hasRealEvent = @($f.timeline | Where-Object { "$($_.event_type)" -eq "evidence" }).Count -gt 0
        if (-not $hasRealEvent) { continue }

        $parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse("$($f.timeline_context.first_seen)", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { continue }

        $tactic = if ($f.mitre -and $f.mitre.Count -gt 0) { "$($f.mitre[0].tactic)" } else { "" }
        $timelineEvents.Add([PSCustomObject]@{
            Time   = $parsed
            Tactic = (Get-Culture).TextInfo.ToTitleCase(($tactic -replace '_', ' '))
            Title  = "$($f.summary.title)"
            Score  = [int]$f.risk.score
        })
    }
    $timelineEvents = @($timelineEvents | Sort-Object Time)

    $attackChain = [System.Collections.Generic.List[string]]::new()
    $lastTactic = $null
    foreach ($e in $timelineEvents) {
        if ($e.Tactic -and $e.Tactic -ne $lastTactic) {
            $attackChain.Add($e.Tactic)
            $lastTactic = $e.Tactic
        }
    }

    # ── Top priorities, next steps (aggregated from the KB's own curated
    # recommendations for the highest-scoring findings — not invented). ──
    $topPriorities = @(
        $findings | Sort-Object { [int]$_.risk.score } -Descending | Select-Object -First 6 | ForEach-Object {
            [PSCustomObject]@{ Title = "$($_.summary.title)"; Score = [int]$_.risk.score; Level = "$($_.risk.level)" }
        }
    )

    $nextSteps = [System.Collections.Generic.List[string]]::new()
    $seenSteps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($f in ($findings | Sort-Object { [int]$_.risk.score } -Descending | Select-Object -First 10)) {
        if ($nextSteps.Count -ge 6) { break }
        foreach ($rec in @($f.recommendations)) {
            if ($nextSteps.Count -ge 6) { break }
            $action = if ($rec.action) { "$($rec.action)" } else { "$rec" }
            if ($action -and $seenSteps.Add($action)) { $nextSteps.Add($action) }
        }
    }

    # ── Investigation status + confidence. Confidence is a transparent,
    # reproducible heuristic — NOT an LLM-invented percentage — based on
    # how much of the evidence base is complete and corroborated. ───────
    $confirmedCount = @($findings | Where-Object { [int]$_.risk.score -ge 60 }).Count
    $highConfidenceCount = @($findings | Where-Object { [int]$_.risk.score -ge 80 }).Count

    $completeCount = @($findings | Where-Object { $_.evidence_quality.collection_complete -ne $false }).Count
    $completeFraction = if ($findings.Count -gt 0) { $completeCount / $findings.Count } else { 0 }
    $correlationBonus = [Math]::Min(15, $correlatedIds.Count * 3)
    $confidence = [Math]::Min(95, [Math]::Max(35, [int](50 + ($completeFraction * 30) + $correlationBonus)))

    $gaps = [System.Collections.Generic.List[string]]::new()
    foreach ($g in $AdditionalGaps) { $gaps.Add($g) }
    $emptyCount = @($findings | Where-Object { [int]$_.summary.total_entries -eq 0 }).Count
    if ($emptyCount -gt 0) {
        $gaps.Add("$emptyCount check(s) returned no evidence this run (may be genuinely clean, or collection was blocked — see the run log).")
    }

    return @{
        HasData          = $true
        TotalFindings    = $findings.Count
        OverallScore     = $overallScore
        OverallLevel     = $overallBand.level
        RiskBreakdown    = $riskBreakdown
        Confirmed        = $confirmedCount
        HighConfidence   = $highConfidenceCount
        Correlated       = $correlatedIds.Count
        Gaps             = @($gaps)
        Timeline         = $timelineEvents
        AttackChain      = @($attackChain)
        TopPriorities    = $topPriorities
        CorrelationPairs = @($correlationPairs | Select-Object -First 6)
        NextSteps        = @($nextSteps)
        Confidence       = $confidence
        TopFindingTitle  = $topFindingTitle
    }
}
