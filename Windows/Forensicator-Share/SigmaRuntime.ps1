if(-not $script:sigmaRulesRoot){
    $script:sigmaRulesRoot = Join-Path $PSScriptRoot "rules"
}

function Get-SigmaSeverityValue {
    param([string]$Level)

    $levelMap = @{
        "critical"      = 5
        "high"          = 4
        "medium"        = 3
        "low"           = 2
        "informational" = 1
    }

    return ($levelMap[$Level.ToLowerInvariant()] ?? 0)
}

function Get-SigmaStructuredRuleSet {
    param([string]$RulesRoot = $script:sigmaRulesRoot)

    if(-not (Test-Path $RulesRoot)){
        return $null
    }

    $sourcesPath = Join-Path $RulesRoot "sources.json"
    if(-not (Test-Path $sourcesPath)){
        Write-ForensicLog "Structured Sigma rules folder found but sources.json is missing" -Level WARN -Section "SIGMA" -Detail "Expected sources metadata at $sourcesPath"
        return $null
    }

    try{
        $sources = @(Get-Content $sourcesPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100)
    }
    catch{
        Write-ForensicLog "Failed to parse structured Sigma sources: $($_.Exception.Message)" -Level ERROR -Section "SIGMA" -Detail $sourcesPath
        return $null
    }

    $ruleFiles = @(Get-ChildItem -Path $RulesRoot -Recurse -File -Filter *.json -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -ne $sourcesPath })

    if($ruleFiles.Count -eq 0){
        Write-ForensicLog "Structured Sigma rules folder has no rule JSON files" -Level WARN -Section "SIGMA" -Detail "Expected rule files under $RulesRoot"
        return $null
    }

    $rules         = [System.Collections.Generic.List[object]]::new()
    $disabledCount  = 0

    foreach($file in $ruleFiles){
        try{
            $parsed = Get-Content $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
            if($null -eq $parsed){
                continue
            }

            if($parsed -is [System.Array]){
                foreach($rule in $parsed){
                    if($null -ne $rule){
                        # Skip only when enabled is explicitly set to false.
                        # Missing field or true both pass through — this keeps
                        # unmodified community rules working without any changes.
                        if($rule.PSObject.Properties["enabled"] -and [string]$rule.enabled -eq "false"){
                            $disabledCount++
                            continue
                        }
                        $rules.Add($rule)
                    }
                }
            }
            else{
                if($parsed.PSObject.Properties["enabled"] -and [string]$parsed.enabled -eq "false"){
                    $disabledCount++
                } else {
                    $rules.Add($parsed)
                }
            }
        }
        catch{
            Write-ForensicLog "Failed to parse structured Sigma rule file: $($_.Exception.Message)" -Level WARN -Section "SIGMA" -Detail $file.FullName
        }
    }

    if($rules.Count -eq 0){
        Write-ForensicLog "No valid structured Sigma rules loaded" -Level WARN -Section "SIGMA" -Detail "Rules root: $RulesRoot"
        return $null
    }

    return [PSCustomObject]@{
        metadata = [PSCustomObject]@{
            generated_at_utc     = (Get-Date).ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
            compiled_rule_count  = $rules.Count
            skipped_rule_count   = $disabledCount
            source               = "structured-json"
            rules_root           = $RulesRoot
        }
        sources = $sources
        rules   = @($rules)
    }
}

function New-SigmaStringSet {
    param([string[]]$Values)

    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($value in @($Values)){
        $text = [string]$value
        if(-not [string]::IsNullOrWhiteSpace($text)){
            [void]$set.Add($text.Trim())
        }
    }

    return ,$set
}

function Test-SigmaSourceSelection {
    param(
        [psobject]$Source,
        [System.Collections.Generic.HashSet[string]]$IncludeSourceIds,
        [System.Collections.Generic.HashSet[string]]$ExcludeSourceIds,
        [System.Collections.Generic.HashSet[string]]$IncludeLogNames,
        [System.Collections.Generic.HashSet[string]]$ExcludeLogNames,
        [System.Collections.Generic.HashSet[string]]$IncludeCategories,
        [System.Collections.Generic.HashSet[string]]$ExcludeCategories
    )

    $sourceId = [string]$Source.id
    $logName  = [string]$Source.log_name
    $category = [string]$Source.category

    if($IncludeSourceIds.Count -gt 0 -and -not $IncludeSourceIds.Contains($sourceId)){
        return $false
    }
    if($ExcludeSourceIds.Contains($sourceId)){
        return $false
    }
    if($IncludeLogNames.Count -gt 0 -and -not $IncludeLogNames.Contains($logName)){
        return $false
    }
    if($ExcludeLogNames.Contains($logName)){
        return $false
    }
    if($IncludeCategories.Count -gt 0 -and -not $IncludeCategories.Contains($category)){
        return $false
    }
    if($ExcludeCategories.Contains($category)){
        return $false
    }

    return $true
}

function ConvertTo-SigmaWildcardRegex {
    param(
        [string]$Value,
        [ValidateSet("exact","contains","startswith","endswith")]
        [string]$Mode
    )

    $escaped = [regex]::Escape($Value) -replace '\\\*', '.*' -replace '\\\?', '.'

    switch($Mode){
        "exact"      { return "^$escaped$" }
        "contains"   { return "^.*$escaped.*$" }
        "startswith" { return "^$escaped.*$" }
        "endswith"   { return "^.*$escaped$" }
    }
}

function Get-SigmaComparableValues {
    param(
        [string]$Value,
        [bool]$Windash
    )

    $values = [System.Collections.Generic.List[string]]::new()
    $values.Add($Value)

    if($Windash){
        if($Value.Contains('-')){
            $values.Add(($Value -replace '-', '/'))
        }
        if($Value.Contains('/')){
            $values.Add(($Value -replace '/', '-'))
        }
    }

    return $values | Where-Object { $_ } | Select-Object -Unique
}

function Test-SigmaCidrMatch {
    param(
        [string]$Address,
        [string]$Cidr
    )

    try{
        $parts = $Cidr.Split('/', 2)
        if($parts.Count -ne 2){ return $false }

        $ipAddress    = [System.Net.IPAddress]::Parse($Address)
        $network      = [System.Net.IPAddress]::Parse($parts[0])
        $prefixLength = [int]$parts[1]

        if($ipAddress.AddressFamily -ne $network.AddressFamily){
            return $false
        }

        $ipBytes      = $ipAddress.GetAddressBytes()
        $networkBytes = $network.GetAddressBytes()
        $remaining    = $prefixLength

        for($index = 0; $index -lt $ipBytes.Length; $index++){
            if($remaining -le 0){ break }

            if($remaining -ge 8){
                if($ipBytes[$index] -ne $networkBytes[$index]){
                    return $false
                }
                $remaining -= 8
                continue
            }

            $mask = [byte]((([int]0xFF) -shl (8 - $remaining)) -band 0xFF)
            if(($ipBytes[$index] -band $mask) -ne ($networkBytes[$index] -band $mask)){
                return $false
            }
            $remaining = 0
        }

        return $true
    }
    catch{
        return $false
    }
}

function Test-SigmaScalarMatch {
    param(
        [string]$Actual,
        [string]$Expected,
        [string]$Operator,
        [bool]$IgnoreCase
    )

    if($null -eq $Actual){
        return $false
    }

    if($Operator -eq "cidr"){
        return (Test-SigmaCidrMatch -Address $Actual -Cidr $Expected)
    }

    if($Operator -eq "re"){
        try{
            $options = [System.Text.RegularExpressions.RegexOptions]::None
            if($IgnoreCase){
                $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            }
            return [regex]::IsMatch($Actual, $Expected, $options)
        }
        catch{
            return $false
        }
    }

    $pattern = ConvertTo-SigmaWildcardRegex -Value $Expected -Mode $Operator
    $options = [System.Text.RegularExpressions.RegexOptions]::None
    if($IgnoreCase){
        $options = $options -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    }

    return [regex]::IsMatch($Actual, $pattern, $options)
}

function Test-SigmaFieldMatcher {
    param(
        $Matcher,
        $Context
    )

    $fieldName = [string]$Matcher.field
    $actual    = [string]($Context.Fields[$fieldName] ?? "")
    $operator  = [string]$Matcher.operator

    if($operator -eq "is_null"){
        return [string]::IsNullOrWhiteSpace($actual)
    }

    $perValueResults = foreach($rawValue in @($Matcher.values)){
        $valueMatched = $false
        foreach($candidate in Get-SigmaComparableValues -Value ([string]$rawValue) -Windash ([bool]$Matcher.windash)){
            if(Test-SigmaScalarMatch -Actual $actual -Expected $candidate -Operator $operator -IgnoreCase ([bool]$Matcher.ignore_case)){
                $valueMatched = $true
                break
            }
        }
        $valueMatched
    }

    if([string]$Matcher.match -eq "all"){
        return (-not ($perValueResults -contains $false))
    }

    return ($perValueResults -contains $true)
}

function Test-SigmaRawMatcher {
    param(
        $Matcher,
        $Context
    )

    $perValueResults = foreach($rawValue in @($Matcher.values)){
        Test-SigmaScalarMatch -Actual ([string]$Context.RawText) -Expected ([string]$rawValue) -Operator ([string]$Matcher.operator) -IgnoreCase ([bool]$Matcher.ignore_case)
    }

    if([string]$Matcher.match -eq "all"){
        return (-not ($perValueResults -contains $false))
    }

    return ($perValueResults -contains $true)
}

function Get-SigmaRuleItemNames {
    param(
        $RuleItems,
        [string]$Pattern
    )

    if($null -eq $RuleItems){
        return @()
    }

    $names = @($RuleItems.PSObject.Properties | ForEach-Object { [string]$_.Name })
    if($Pattern.ToLowerInvariant() -eq "them"){
        return $names
    }

    return @($names | Where-Object { $_ -like $Pattern })
}

function Get-SigmaItemResult {
    param(
        [string]$Name,
        $RuleItems,
        $Context,
        [hashtable]$ItemResults
    )

    if($ItemResults.ContainsKey($Name)){
        return [bool]$ItemResults[$Name]
    }

    if($null -eq $RuleItems){
        $ItemResults[$Name] = $false
        return $false
    }

    $property = $RuleItems.PSObject.Properties[$Name]
    if($null -eq $property){
        $ItemResults[$Name] = $false
        return $false
    }

    $result = Test-SigmaExpression -Expression $property.Value -Context $Context -ItemResults $ItemResults -RuleItems $RuleItems
    $ItemResults[$Name] = [bool]$result
    return [bool]$result
}

function Test-SigmaExpression {
    param(
        $Expression,
        $Context,
        [hashtable]$ItemResults,
        $RuleItems
    )

    if($null -eq $Expression){ return $false }

    switch([string]$Expression.type){
        "all" {
            foreach($child in @($Expression.children)){
                if(-not (Test-SigmaExpression -Expression $child -Context $Context -ItemResults $ItemResults -RuleItems $RuleItems)){
                    return $false
                }
            }
            return $true
        }
        "any" {
            foreach($child in @($Expression.children)){
                if(Test-SigmaExpression -Expression $child -Context $Context -ItemResults $ItemResults -RuleItems $RuleItems){
                    return $true
                }
            }
            return $false
        }
        "not" {
            return (-not (Test-SigmaExpression -Expression $Expression.child -Context $Context -ItemResults $ItemResults -RuleItems $RuleItems))
        }
        "field" {
            return (Test-SigmaFieldMatcher -Matcher $Expression -Context $Context)
        }
        "raw" {
            return (Test-SigmaRawMatcher -Matcher $Expression -Context $Context)
        }
        "item_ref" {
            return (Get-SigmaItemResult -Name ([string]$Expression.name) -RuleItems $RuleItems -Context $Context -ItemResults $ItemResults)
        }
        "wildcard_ref" {
            $pattern = [string]$Expression.pattern
            $keys = @(Get-SigmaRuleItemNames -RuleItems $RuleItems -Pattern $pattern)

            if($keys.Count -eq 0){
                return $false
            }

            if([string]$Expression.mode -eq "all"){
                foreach($key in $keys){
                    if(-not (Get-SigmaItemResult -Name ([string]$key) -RuleItems $RuleItems -Context $Context -ItemResults $ItemResults)){
                        return $false
                    }
                }
                return $true
            }

            foreach($key in $keys){
                if(Get-SigmaItemResult -Name ([string]$key) -RuleItems $RuleItems -Context $Context -ItemResults $ItemResults){
                    return $true
                }
            }
            return $false
        }
        default {
            return $false
        }
    }
}

function ConvertTo-SigmaEventContext {
    param(
        $Record,
        $Source
    )

    $xml = [xml]$Record.ToXml()
    $eventData = @{}

    if($xml.Event.EventData -and $xml.Event.EventData.Data){
        foreach($node in @($xml.Event.EventData.Data)){
            if($node.Name){
                $eventData[[string]$node.Name] = [string]$node.'#text'
            }
        }
    }

    $systemValues = @{
        EventID      = [string]$Record.Id
        Channel      = [string]$Record.LogName
        ProviderName = [string]$xml.Event.System.Provider.Name
    }

    $fields = @{}
    foreach($property in $Source.field_map.PSObject.Properties){
        $fieldName = [string]$property.Name
        $mapping   = $property.Value
        $value     = $null

        switch([string]$mapping.kind){
            "eventdata" { $value = $eventData[[string]$mapping.name] }
            "system"    { $value = $systemValues[[string]$mapping.name] }
        }

        if($null -ne $value){
            $fields[$fieldName] = [string]$value
        }
    }

    $rawText = ""
    try{
        $rawText = [string]$Record.Message
    }
    catch{
        $rawText = ""
    }

    if([string]::IsNullOrWhiteSpace($rawText)){
        $rawText = $xml.OuterXml
    }
    else{
        $rawText = $rawText + "`n" + $xml.OuterXml
    }

    return @{
        Event     = $Record
        Fields    = $fields
        EventData = $eventData
        RawText   = $rawText
    }
}

function Test-SigmaRuleMatch {
    param(
        $Rule,
        $Context
    )

    $itemResults = @{}
    return (Test-SigmaExpression -Expression $Rule.condition -Context $Context -ItemResults $itemResults -RuleItems $Rule.items)
}

function ConvertTo-SigmaFilterXml {
    param(
        $Source,
        [int]$DaysBack
    )

    $logName = [string]$Source.log_name
    $safeLogName = [System.Security.SecurityElement]::Escape($logName)
    $startTimeUtc = (Get-Date).AddDays(-$DaysBack).ToUniversalTime().ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)

    $systemClauses = [System.Collections.Generic.List[string]]::new()
    $eventIdClauses = @($Source.event_ids | ForEach-Object { "EventID=$([int]$_)" })
    if($eventIdClauses.Count -gt 0){
        $systemClauses.Add("(" + ($eventIdClauses -join " or ") + ")")
    }
    $systemClauses.Add("TimeCreated[@SystemTime&gt;='$startTimeUtc']")

    $systemFilter = $systemClauses -join " and "

    return [xml]@"
<QueryList>
  <Query Id="0" Path="$safeLogName">
    <Select Path="$safeLogName">*[System[$systemFilter]]</Select>
  </Query>
</QueryList>
"@
}

function Invoke-SigmaScan {
    param(
        [string]  $RulesRoot         = $script:sigmaRulesRoot,
        [int]     $DaysBack          = 30,
        [ValidateSet("critical","high","medium","low","informational")]
        [string]  $MinLevel          = "medium",
        [string[]]$IncludeSourceIds,
        [string[]]$ExcludeSourceIds,
        [string[]]$IncludeLogNames,
        [string[]]$ExcludeLogNames,
        [string[]]$IncludeCategories,
        [string[]]$ExcludeCategories,
        [int]$MaxEventsPerSource = 0
    )

    $results             = [System.Collections.Generic.List[PSCustomObject]]::new()
    $bundle              = Get-SigmaStructuredRuleSet -RulesRoot $RulesRoot
    $seenMatches         = [System.Collections.Generic.HashSet[string]]::new()
    $failedRules         = [System.Collections.Generic.HashSet[string]]::new()
    $includeSourceIdSet  = New-SigmaStringSet -Values $IncludeSourceIds
    $excludeSourceIdSet  = New-SigmaStringSet -Values $ExcludeSourceIds
    $includeLogNameSet   = New-SigmaStringSet -Values $IncludeLogNames
    $excludeLogNameSet   = New-SigmaStringSet -Values $ExcludeLogNames
    $includeCategorySet  = New-SigmaStringSet -Values $IncludeCategories
    $excludeCategorySet  = New-SigmaStringSet -Values $ExcludeCategories

    if($null -eq $bundle){
        Write-ForensicLog "No structured Sigma rules available — skipping detection" -Level WARN -Section "SIGMA" -Detail "Rules root: $RulesRoot"
        return ,$results
    }

    $bundleSource = [string]($bundle.metadata.source ?? "structured-json")
    $disabledLabel = if($bundle.metadata.skipped_rule_count -gt 0){ " | Disabled (enabled:false): $($bundle.metadata.skipped_rule_count)" } else { "" }
    Write-ForensicLog "Loaded Sigma rule set" -Level INFO -Section "SIGMA" -Detail "Source: $bundleSource | Generated: $($bundle.metadata.generated_at_utc) | Rules: $($bundle.metadata.compiled_rule_count)$disabledLabel"

    $activeSources = @(
        @($bundle.sources) | Where-Object {
            Test-SigmaSourceSelection `
                -Source $_ `
                -IncludeSourceIds $includeSourceIdSet `
                -ExcludeSourceIds $excludeSourceIdSet `
                -IncludeLogNames $includeLogNameSet `
                -ExcludeLogNames $excludeLogNameSet `
                -IncludeCategories $includeCategorySet `
                -ExcludeCategories $excludeCategorySet
        }
    )

    if($activeSources.Count -eq 0){
        Write-ForensicLog "No Sigma event sources selected after config filters" -Level WARN -Section "SIGMA" -Detail "Rules root: $RulesRoot"
        return ,$results
    }

    $allowedSourceIds = New-SigmaStringSet -Values @($activeSources | ForEach-Object { [string]$_.id })
    $activeLogNames   = @($activeSources | ForEach-Object { [string]$_.log_name } | Sort-Object -Unique)
    $maxEventsLabel = if($MaxEventsPerSource -gt 0){ [string]$MaxEventsPerSource } else { "unbounded" }
    Write-ForensicLog "Sigma source selection resolved" -Level INFO -Section "SIGMA" -Detail "Sources: $($activeSources.Count)/$(@($bundle.sources).Count) | Logs: $($activeLogNames -join ', ') | MaxEventsPerSource: $maxEventsLabel"

    $minLevelNum = Get-SigmaSeverityValue -Level $MinLevel
    $rules = @(
        $bundle.rules | Where-Object {
            ((Get-SigmaSeverityValue -Level ([string]$_.level)) -ge $minLevelNum) -and
            (@($_.sources | Where-Object { $allowedSourceIds.Contains([string]$_) }).Count -gt 0)
        }
    )

    if($rules.Count -eq 0){
        Write-ForensicLog "No Sigma rules met the selected severity threshold" -Level WARN -Section "SIGMA" -Detail "Minimum level: $MinLevel"
        return ,$results
    }

    $sourceMap = @{}
    foreach($source in $activeSources){
        $sourceMap[[string]$source.id] = $source
    }

    $rulesBySource = @{}
    foreach($rule in $rules){
        foreach($sourceId in @($rule.sources)){
            if(-not $allowedSourceIds.Contains([string]$sourceId)){
                continue
            }
            if(-not $rulesBySource.ContainsKey([string]$sourceId)){
                $rulesBySource[[string]$sourceId] = [System.Collections.Generic.List[object]]::new()
            }
            $rulesBySource[[string]$sourceId].Add($rule)
        }
    }

    $sourceIds = @($rulesBySource.Keys | Sort-Object)
    $sourceIndex = 0

    foreach($sourceId in $sourceIds){
        $sourceIndex++
        $source = $sourceMap[$sourceId]
        if($null -eq $source){ continue }

        Write-Progress -Activity "Running Sigma Rules" `
                       -Status "[$sourceIndex/$($sourceIds.Count)] $([string]$source.log_name)" `
                       -PercentComplete ([Math]::Round(($sourceIndex / $sourceIds.Count) * 100))

        try{
            Get-WinEvent -ListLog ([string]$source.log_name) -ErrorAction Stop | Out-Null
        }
        catch{
            Write-ForensicLog "Skipping Sigma source — log not available" -Level WARN -Section "SIGMA" -Detail "$([string]$source.log_name)"
            continue
        }

        $filterXml = ConvertTo-SigmaFilterXml -Source $source -DaysBack $DaysBack

        try{
            $eventQueryParams = @{
                FilterXml   = $filterXml
                ErrorAction = "Stop"
            }
            if($MaxEventsPerSource -gt 0){
                $eventQueryParams.MaxEvents = $MaxEventsPerSource
            }

            $candidateCount = 0
            foreach($logRecord in Get-WinEvent @eventQueryParams){
                $candidateCount++
                $context = ConvertTo-SigmaEventContext -Record $logRecord -Source $source

                foreach($rule in $rulesBySource[$sourceId]){
                    try{
                        $isMatch = Test-SigmaRuleMatch -Rule $rule -Context $context
                    }
                    catch{
                        $ruleKey = "{0}|{1}" -f ([string]$sourceId), ([string]$rule.rule_file)
                        if($failedRules.Add($ruleKey)){
                            Write-ForensicLog "Sigma rule evaluation failed — skipping rule" `
                                              -Level WARN `
                                              -Section "SIGMA" `
                                              -Detail "Source: $([string]$source.log_name) | Rule: $([string]$rule.title) | File: $([string]$rule.rule_file) | Error: $($_.Exception.Message)"
                        }
                        continue
                    }

                    if(-not $isMatch){
                        continue
                    }

                    $recordId = [string]($logRecord.RecordId ?? $logRecord.Id)
                    $matchKey = "$sourceId|$([string]$rule.rule_file)|$recordId"
                    if(-not $seenMatches.Add($matchKey)){
                        continue
                    }

                    $results.Add([PSCustomObject]@{
                        RuleTitle   = [string]$rule.title
                        RuleLevel   = [string]$rule.level
                        RuleTags    = (@($rule.tags) -join ", ")
                        EventId     = $logRecord.Id
                        LogName     = [string]$logRecord.LogName
                        TimeCreated = $logRecord.TimeCreated.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
                        User        = [string]($context.Fields["User"] ?? $context.EventData["SubjectUserName"] ?? $context.EventData["TargetUserName"] ?? "N/A")
                        CommandLine = [string]($context.Fields["CommandLine"] ?? $context.Fields["ScriptBlockText"] ?? $context.Fields["Payload"] ?? "N/A")
                        Process     = [string]($context.Fields["Image"] ?? $context.Fields["ImageLoaded"] ?? "N/A")
                        RuleFile    = [string]$rule.rule_file
                    })

                    Write-ForensicLog "SIGMA HIT: $([string]$rule.title)" `
                                      -Level FINDING `
                                      -Section "SIGMA" `
                                      -Detail "Level: $([string]$rule.level) | EventId: $($logRecord.Id) | Time: $($logRecord.TimeCreated)"
                }
            }

            if($MaxEventsPerSource -gt 0 -and $candidateCount -ge $MaxEventsPerSource){
                Write-ForensicLog "Sigma source reached event cap" -Level WARN -Section "SIGMA" -Detail "Source: $([string]$source.log_name) | SourceId: $sourceId | Scanned newest $candidateCount candidate events | Increase sigma.max_events_per_source for deeper coverage"
            }
            else{
                Write-ForensicLog "Sigma source scanned" -Level INFO -Section "SIGMA" -Detail "Source: $([string]$source.log_name) | SourceId: $sourceId | Candidate events: $candidateCount"
            }
        }
        catch{
            if($_.Exception.Message -like "*No events were found that match the specified selection criteria*"){
                Write-ForensicLog "No Sigma candidate events in $([string]$source.log_name) for the selected time range" -Level INFO -Section "SIGMA"
            }
            else{
                Write-ForensicLog "Failed Sigma query for $([string]$source.log_name): $($_.Exception.Message)" -Level WARN -Section "SIGMA"
            }
        }
    }

    Write-Progress -Activity "Running Sigma Rules" -Completed
    return ,$results
}
