#Requires -Version 5.1
<#
Forensicator AI Client
=======================
Optional, local-first LLM integration for the free/open-source collector.
Off by default — enable via config.json's "ai" block:

    "ai": {
      "enabled": true,
      "provider": "ollama",
      "base_url": "http://localhost:11434",
      "api_key": "",
      "model": "mistral:7b-instruct",
      "timeout_seconds": 60,
      "max_evidence_rows": 15
    }

Supported "provider" values:
  - "ollama"                          — local Ollama, POST {base_url}/api/generate
  - "openai" / "openai_compatible"    — OpenAI or any OpenAI-compatible endpoint
                                         (Azure OpenAI, LM Studio, vLLM, etc.),
                                         POST {base_url}/v1/chat/completions
  - "anthropic"                       — POST {base_url}/v1/messages

When enabled, New-ForensicatorFinding (ForensicatorFindingBuilder.ps1) calls
Add-ForensicatorAiVerdict once per finding, after the finding object is fully
built, to get a short plain-language verdict on the ACTUAL evidence collected
this run. This is intentionally separate from — and additive to — the static,
bundled knowledge-base content the report's tooltip panel already shows for
every finding type (see ForensicatorArtifactKnowledgeBase.ps1): that content
is the same for every user regardless of what was collected; this is live,
per-instance, and produced only when the analyst has configured an LLM.

Every call is wrapped, time-bounded, and degrades to "no verdict" on any
failure (unreachable host, invalid key, malformed response, timeout) — a
misconfigured or unreachable LLM must never break or meaningfully slow down
collection for analysts who haven't set this up.
#>

$Script:ForensicatorAiConfig = $null

# ArtifactKey -> verdict text, accumulated across this run. Embedded into the
# report as ForensicatorAiVerdicts (see Forensicator.ps1's
# $ForensicatorAiVerdictsJson / __FI_AI_VERDICTS__ replacement).
$Script:ForensicatorAiVerdicts = [ordered]@{}

# Human-readable reason the MOST RECENT verdict attempt didn't produce a
# result (disabled / unknown provider / unreachable / bad response), or
# $null once a call succeeds. Single, run-wide value rather than per-finding:
# in practice a failure here is almost always systemic (disabled, or the
# same endpoint failing every call), so the report shows this instead of the
# generic "in the works" placeholder from the static external doc whenever a
# finding has no local verdict. See __FI_AI_UNAVAILABLE_REASON__ in
# Forensicator.ps1.
$Script:ForensicatorAiUnavailableReason = $null

# How many findings have had an AI verdict attempted so far this run — purely
# for the "analyzing X (n/total)" progress line New-ForensicatorFinding prints
# per finding when AI is enabled, so a long run (each finding is a real,
# potentially slow LLM call) doesn't look hung with no console feedback.
$Script:ForensicatorAiFindingCounter = 0

# Set once, the first time AI analysis is attempted this run, so the operator
# sees a single clear "starting" banner rather than the first per-finding
# progress line appearing out of nowhere.
$Script:ForensicatorAiBannerShown = $false

<#
.SYNOPSIS
    Reads config.json's "ai" block (if present) into $Script:ForensicatorAiConfig,
    with safe defaults so an absent/partial block just means "disabled" rather
    than a crash. Call once, early — before any New-ForensicatorFinding calls.
#>
function Initialize-ForensicatorAiConfig {
    param($ConfigData)

    $ai = $null
    if ($ConfigData -and $ConfigData.PSObject.Properties.Name -contains 'ai') {
        $ai = $ConfigData.ai
    }

    $Script:ForensicatorAiConfig = [ordered]@{
        enabled           = if ($ai -and $null -ne $ai.enabled) { [bool]$ai.enabled } else { $false }
        provider          = if ($ai -and $ai.provider) { "$($ai.provider)".ToLower().Trim() } else { "ollama" }
        base_url          = if ($ai -and $ai.base_url) { "$($ai.base_url)".TrimEnd('/') } else { "http://localhost:11434" }
        api_key           = if ($ai -and $ai.api_key) { "$($ai.api_key)" } else { "" }
        model             = if ($ai -and $ai.model) { "$($ai.model)" } else { "mistral:7b-instruct" }
        timeout_seconds   = if ($ai -and $ai.timeout_seconds) { [int]$ai.timeout_seconds } else { 60 }
        max_evidence_rows = if ($ai -and $ai.max_evidence_rows) { [int]$ai.max_evidence_rows } else { 15 }
    }

    if ($Script:ForensicatorAiConfig.enabled) {
        Write-ForensicLog "[*] Forensicator AI enabled — provider=$($Script:ForensicatorAiConfig.provider) model=$($Script:ForensicatorAiConfig.model) base_url=$($Script:ForensicatorAiConfig.base_url)" -Level INFO -Section "AI"
        $Script:ForensicatorAiUnavailableReason = $null
    } else {
        Write-ForensicLog "[*] Forensicator AI disabled (set ai.enabled=true in config.json to enable)" -Level INFO -Section "AI"
        $Script:ForensicatorAiUnavailableReason = "Forensicator AI is disabled for this run (set ai.enabled=true in config.json to enable)."
    }
}

<#
.SYNOPSIS
    Builds a compact, evidence-grounded prompt from an already-constructed
    finding object (the same shape New-ForensicatorFinding returns).
#>
function Get-ForensicatorAiPrompt {
    param($Finding)

    $cfg = $Script:ForensicatorAiConfig
    $lines = New-Object System.Collections.Generic.List[string]

    [void]$lines.Add("You are assisting a digital forensics and incident response (DFIR) analyst reviewing output from an automated endpoint collector.")
    [void]$lines.Add("Give a short (2-4 sentence) plain-language verdict on the finding below: what it shows, whether it looks suspicious given the ACTUAL evidence (not just the general category), and one concrete next step for the analyst. Reference specific evidence values where relevant. Respond with plain text only — no markdown, no headers, no bullet points.")
    [void]$lines.Add("")
    [void]$lines.Add("Finding type: $($Finding.finding_type)")
    [void]$lines.Add("Category: $($Finding.category)")
    [void]$lines.Add("Severity: $($Finding.severity)")
    if ($Finding.summary -and $Finding.summary.description) { [void]$lines.Add("Description: $($Finding.summary.description)") }
    if ($Finding.risk -and $Finding.risk.reason) { [void]$lines.Add("Risk reason: $($Finding.risk.reason)") }
    if ($Finding.explanation -and $Finding.explanation.suspicious_behaviour) { [void]$lines.Add("Suspicious when: $($Finding.explanation.suspicious_behaviour)") }

    $evidenceRows = @($Finding.evidence)
    if ($evidenceRows.Count -gt 0) {
        $maxRows = [Math]::Max(1, $cfg.max_evidence_rows)
        [void]$lines.Add("")
        [void]$lines.Add("Evidence ($($evidenceRows.Count) row(s) total, showing up to $maxRows):")
        $shown = $evidenceRows | Select-Object -First $maxRows
        foreach ($row in $shown) {
            try { [void]$lines.Add(($row | ConvertTo-Json -Depth 4 -Compress)) }
            catch { [void]$lines.Add("$row") }
        }
    } else {
        [void]$lines.Add("")
        [void]$lines.Add("No evidence rows were collected for this finding (empty result) — this is likely a clean/negative finding.")
    }

    return ($lines -join "`n")
}

<#
.SYNOPSIS
    Provider-dispatching LLM call. Returns the model's raw text response, or
    $null on any failure (network, auth, timeout, unexpected response shape).
#>
function Invoke-ForensicatorAiCompletion {
    param([Parameter(Mandatory)][string]$Prompt)

    $cfg = $Script:ForensicatorAiConfig
    if (-not $cfg -or -not $cfg.enabled) { return $null }

    try {
        switch ($cfg.provider) {
            "ollama" {
                $body = @{ model = $cfg.model; prompt = $Prompt; stream = $false } | ConvertTo-Json -Depth 5 -Compress
                $resp = Invoke-RestMethod -Uri "$($cfg.base_url)/api/generate" -Method Post -Body $body `
                    -ContentType "application/json" -TimeoutSec $cfg.timeout_seconds
                return $resp.response
            }
            { $_ -in @("openai", "openai_compatible", "azure_openai") } {
                $headers = @{}
                if ($cfg.api_key) { $headers["Authorization"] = "Bearer $($cfg.api_key)" }
                $body = @{
                    model    = $cfg.model
                    messages = @(@{ role = "user"; content = $Prompt })
                } | ConvertTo-Json -Depth 6 -Compress
                $resp = Invoke-RestMethod -Uri "$($cfg.base_url)/v1/chat/completions" -Method Post -Headers $headers -Body $body `
                    -ContentType "application/json" -TimeoutSec $cfg.timeout_seconds
                return $resp.choices[0].message.content
            }
            "anthropic" {
                $headers = @{
                    "x-api-key"         = $cfg.api_key
                    "anthropic-version" = "2023-06-01"
                }
                $body = @{
                    model      = $cfg.model
                    max_tokens = 400
                    messages   = @(@{ role = "user"; content = $Prompt })
                } | ConvertTo-Json -Depth 6 -Compress
                $resp = Invoke-RestMethod -Uri "$($cfg.base_url)/v1/messages" -Method Post -Headers $headers -Body $body `
                    -ContentType "application/json" -TimeoutSec $cfg.timeout_seconds
                return $resp.content[0].text
            }
            default {
                Write-ForensicLog "[!] Unknown Forensicator AI provider '$($cfg.provider)' in config.json (expected ollama, openai, openai_compatible, azure_openai, or anthropic) — skipping AI verdict" -Level WARN -Section "AI"
                $Script:ForensicatorAiUnavailableReason = "Unknown AI provider '$($cfg.provider)' configured in config.json — verdicts skipped."
                return $null
            }
        }
    }
    catch {
        Write-ForensicLog "[!] Forensicator AI call failed ($($cfg.provider)/$($cfg.model)): $($_.Exception.Message)" -Level WARN -Section "AI"
        $Script:ForensicatorAiUnavailableReason = "Forensicator AI could not reach $($cfg.provider) at $($cfg.base_url): $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Populates a finding's ai_analysis section with a real verdict when
    Forensicator AI is enabled; no-op (returns $Finding unchanged) otherwise.
    Also records the verdict into $Script:ForensicatorAiVerdicts for the
    report's per-instance AI tooltip.
#>
function Add-ForensicatorAiVerdict {
    param(
        [Parameter(Mandatory)][string]$ArtifactKey,
        [Parameter(Mandatory)]$Finding
    )

    if (-not $Script:ForensicatorAiConfig -or -not $Script:ForensicatorAiConfig.enabled) {
        return $Finding
    }

    $prompt = Get-ForensicatorAiPrompt -Finding $Finding
    $verdict = Invoke-ForensicatorAiCompletion -Prompt $prompt

    if ($verdict -and $verdict.Trim()) {
        $verdict = $verdict.Trim()
        $Finding.ai_analysis.status = "complete"
        $Finding.ai_analysis.summary = $verdict
        $Script:ForensicatorAiVerdicts[$ArtifactKey] = $verdict
        $Script:ForensicatorAiUnavailableReason = $null
    } else {
        $Finding.ai_analysis.status = "failed"
        # Invoke-ForensicatorAiCompletion already records a specific reason
        # (unreachable / unknown provider) on failure; this generic fallback
        # only applies if the call "succeeded" but returned an empty response.
        if (-not $Script:ForensicatorAiUnavailableReason) {
            $Script:ForensicatorAiUnavailableReason = "Forensicator AI returned an empty response for this finding."
        }
    }

    return $Finding
}

<#
.SYNOPSIS
    True when an AI response is unusable as prose: empty, or just an echo
    of the prompt's own section labels back — observed from smaller local
    models that ignore a "write prose" instruction entirely.
#>
function Test-ForensicatorUnusableAiText {
    param($Text)
    if (-not $Text -or -not $Text.Trim()) { return $true }
    return [bool]($Text -match 'Timeline \(chronological\)|Risk breakdown:|Investigation gaps:|Tactic sequence:')
}

<#
.SYNOPSIS
    Builds the "Why {TIER}?" and "What probably happened" narrative for the
    report's Investigation Summary page from an ALREADY-COMPUTED
    Get-ForensicatorCaseSummary result (ForensicatorFindingBuilder.ps1).
    Deliberately narrow: the LLM is only asked to turn already-computed,
    real facts (score, tactic breakdown, timeline, correlation) into prose
    — it's explicitly told not to invent detail, and every numeric or
    structural claim on the report page comes from the deterministic
    summary object, never from this text.
.OUTPUTS
    @{ WhyTier = <string>; Narrative = <string>; Source = "ai" | "template" }
    Always returns usable text for both fields — falls back to a
    deterministic, template-built explanation when AI is disabled,
    unreachable, returns nothing, or there's no data to summarize.
#>
function Get-ForensicatorCaseSummaryNarrative {
    param([Parameter(Mandatory)]$CaseSummary)

    $tierLabel = "$($CaseSummary.OverallLevel)".ToUpper()

    $topBuckets = @($CaseSummary.RiskBreakdown | Select-Object -First 2 | ForEach-Object { $_.Bucket })
    $bucketPhrase = if ($topBuckets.Count -ge 2) { "$($topBuckets[0]) and $($topBuckets[1])" }
                    elseif ($topBuckets.Count -eq 1) { "$($topBuckets[0])" }
                    else { "no single dominant category" }

    $templateWhy = if ($CaseSummary.TotalFindings -eq 0 -or -not $CaseSummary.TopFindingTitle) {
        "No findings were evaluated this run."
    } else {
        "$($CaseSummary.TotalFindings) finding(s) were evaluated this run; the highest-scoring was '$($CaseSummary.TopFindingTitle)' at $($CaseSummary.OverallScore)/100, concentrated in $bucketPhrase." +
            $(if ($CaseSummary.Correlated -gt 0) { " $($CaseSummary.Correlated) finding(s) share a common indicator (user, host, or IP), increasing confidence these are related rather than coincidental." } else { "" })
    }

    $templateNarrative = if ($CaseSummary.Timeline.Count -ge 2) {
        $first = $CaseSummary.Timeline[0]
        $last = $CaseSummary.Timeline[-1]
        $span = [Math]::Round(($last.Time - $first.Time).TotalMinutes)
        "Evidence spans roughly $span minute(s), beginning with $($first.Tactic.ToLower()) activity ('$($first.Title)') and ending with $($last.Tactic.ToLower()) activity ('$($last.Title)'). Observed tactic sequence: $($CaseSummary.AttackChain -join ' -> ')."
    } elseif ($CaseSummary.TopFindingTitle) {
        "No two findings shared a resolvable event timestamp this run, so no multi-stage sequence could be reconstructed. The most significant single finding was '$($CaseSummary.TopFindingTitle)' ($($CaseSummary.OverallScore)/100)."
    } else {
        "No findings scored high enough this run to warrant a case narrative."
    }

    if (-not $CaseSummary.HasData -or -not $Script:ForensicatorAiConfig -or -not $Script:ForensicatorAiConfig.enabled) {
        return @{ WhyTier = $templateWhy; Narrative = $templateNarrative; Source = "template" }
    }

    # ── Shared, grounded facts block — every fact below is already computed
    # by Get-ForensicatorCaseSummary. Two SEPARATE calls below (not one call
    # asked to self-segment its output with a delimiter): tested against
    # both qwen2.5:0.5b and the documented production default
    # mistral:7b-instruct, and neither reliably emitted a literal delimiter
    # line when asked to write two sections in one response — mistral
    # numbered its own sections ("1)", "2) Chronological narrative:")
    # instead, and qwen just echoed the input facts back. A single-purpose
    # prompt per call is far more reliable than parsing free-form
    # self-segmented output. ──────────────────────────────────────────────
    $factLines = New-Object System.Collections.Generic.List[string]
    [void]$factLines.Add("Overall score: $($CaseSummary.OverallScore)/100 ($tierLabel)")
    [void]$factLines.Add("Top finding: $($CaseSummary.TopFindingTitle)")
    if ($CaseSummary.RiskBreakdown.Count -gt 0) {
        [void]$factLines.Add("Risk breakdown: " + (($CaseSummary.RiskBreakdown | ForEach-Object { "$($_.Bucket)=$($_.Level)" }) -join ", "))
    }
    if ($CaseSummary.Timeline.Count -gt 0) {
        [void]$factLines.Add("Timeline (chronological):")
        foreach ($e in $CaseSummary.Timeline) {
            [void]$factLines.Add("  $($e.Time.ToString('HH:mm')) - $($e.Tactic) - $($e.Title) (score $($e.Score))")
        }
    }
    if ($CaseSummary.AttackChain.Count -gt 0) {
        [void]$factLines.Add("Tactic sequence: $($CaseSummary.AttackChain -join ' -> ')")
    }
    if ($CaseSummary.Correlated -gt 0) {
        [void]$factLines.Add("$($CaseSummary.Correlated) finding(s) share a common indicator across findings.")
    }
    [void]$factLines.Add("Investigation gaps: " + $(if ($CaseSummary.Gaps.Count -gt 0) { $CaseSummary.Gaps -join "; " } else { "none noted" }))
    $factsBlock = $factLines -join "`n"

    $whyPrompt = "You are assisting a digital forensics and incident response (DFIR) analyst.`n" +
        "Write ONLY a 1-3 sentence explanation of why this endpoint's overall risk is $tierLabel, referencing only the facts below. " +
        "Do not invent any detail not listed below. Do not use markdown, headers, or numbered lists. Output only the sentences, nothing else.`n`n$factsBlock"
    $whyResponse = Invoke-ForensicatorAiCompletion -Prompt $whyPrompt
    $whyText = if (Test-ForensicatorUnusableAiText $whyResponse) { $templateWhy } else { $whyResponse.Trim() }

    $narrativePrompt = "You are assisting a digital forensics and incident response (DFIR) analyst.`n" +
        "Write ONLY a 3-5 sentence narrative reconstructing what probably happened on this endpoint, in chronological order, using only the timeline facts below. " +
        "Do not invent any detail, timestamp, IP, account name, or event not explicitly listed below. Do not use markdown, headers, or numbered lists. Output only the narrative sentences, nothing else.`n`n$factsBlock"
    $narrativeResponse = Invoke-ForensicatorAiCompletion -Prompt $narrativePrompt
    $narrativeText = if (Test-ForensicatorUnusableAiText $narrativeResponse) { $templateNarrative } else { $narrativeResponse.Trim() }

    $source = if ($whyText -eq $templateWhy -and $narrativeText -eq $templateNarrative) { "template" } else { "ai" }
    return @{ WhyTier = $whyText; Narrative = $narrativeText; Source = $source }
}
