# Copyright 2016-2023 Cloudbase Solutions Srl
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
$ErrorActionPreference= 'silentlycontinue'
enum SerializationOptions {
    None = 0
    Roundtrip = 1
    DisableAliases = 2
    EmitDefaults = 4
    JsonCompatible = 8
    DefaultToStaticType = 16
    WithIndentedSequences = 32
}
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$assemblies = Join-Path $here "Load-Assemblies.ps1"
$infinityRegex = [regex]::new('^[-+]?(\.inf|\.Inf|\.INF)$', "Compiled, CultureInvariant");

if (Test-Path $assemblies) {
    . $here\Load-Assemblies.ps1
}

function Get-YamlDocuments {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [string]$Yaml,
        [switch]$UseMergingParser=$false
    )
    PROCESS {
        $stringReader = new-object System.IO.StringReader($Yaml)
        $parser = New-Object "YamlDotNet.Core.Parser" $stringReader
        if($UseMergingParser) {
            $parser = New-Object "YamlDotNet.Core.MergingParser" $parser
        }

        $yamlStream = New-Object "YamlDotNet.RepresentationModel.YamlStream"
        $yamlStream.Load([YamlDotNet.Core.IParser] $parser)

        $stringReader.Close()

        return $yamlStream
    }
}

function Convert-ValueToProperType {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Object]$Node
    )
    PROCESS {
        if (!($Node.Value -is [string])) {
            return $Node
        }
        
        if ([string]::IsNullOrEmpty($Node.Tag) -eq $false) {
            switch($Node.Tag) {
                "tag:yaml.org,2002:str" {
                    return $Node.Value
                }
                "tag:yaml.org,2002:null" {
                    return $null
                }
                "tag:yaml.org,2002:bool" {
                    $parsedValue = $false
                    if (![boolean]::TryParse($Node.Value, [ref]$parsedValue)) {
                        Throw ("failed to parse scalar {0} as boolean" -f $Node)
                    }
                    return $parsedValue
                }
                "tag:yaml.org,2002:int" {
                    $parsedValue = 0
                    if ($node.Value.Length -gt 2) {
                        switch ($node.Value.Substring(0, 2)) {
                            "0o" {
                                $parsedValue = [Convert]::ToInt64($Node.Value.Substring(2), 8)
                            }
                            "0x" {
                                $parsedValue = [Convert]::ToInt64($Node.Value.Substring(2), 16)
                            }
                            default {
                                if (![long]::TryParse($Node.Value, [Globalization.NumberStyles]::Any, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)) {
                                    Throw ("failed to parse scalar {0} as long" -f $Node)
                                }
                            }
                        }
                    } else {
                        if (![long]::TryParse($Node.Value, [Globalization.NumberStyles]::Any, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)) {
                            Throw ("failed to parse scalar {0} as long" -f $Node)
                        }
                    }
                    return $parsedValue
                }
                "tag:yaml.org,2002:float" {
                    $parsedValue = 0.0
                    if ($infinityRegex.Matches($Node.Value)) {
                        $prefix = $Node.Value.Substring(0, 1)
                        switch ($prefix) {
                            "-" {
                                return [double]::NegativeInfinity
                            }
                            default {
                                # Prefix is either missing or is a +
                                return [double]::PositiveInfinity
                            }
                        }
                    }
                    if (![double]::TryParse($Node.Value, [Globalization.NumberStyles]::Any, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)) {
                        Throw ("failed to parse scalar {0} as double" -f $Node)
                    }
                    return $parsedValue
                }
                "tag:yaml.org,2002:timestamp" {
                    # From the YAML spec: http://yaml.org/type/timestamp.html
                    [DateTime]$parsedValue = [DateTime]::MinValue
                    $ts = [DateTime]::SpecifyKind($Node.Value, [System.DateTimeKind]::Utc)
                    $tss = $ts.ToString("o")
                    if(![datetime]::TryParse($tss, $null, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref] $parsedValue)) {
                        Throw ("failed to parse scalar {0} as DateTime" -f $Node)
                    }
                    return $parsedValue
                }
            }
        }

        if ($Node.Style -eq 'Plain')
        {
            $types = @([int], [long], [double], [boolean], [decimal])
            foreach($i in $types){
                $parsedValue = New-Object -TypeName $i.FullName
                if ($i.IsAssignableFrom([boolean])){
                    $result = $i::TryParse($Node,[ref]$parsedValue) 
                } else {
                    $result = $i::TryParse($Node, [Globalization.NumberStyles]::Any, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsedValue)
                }
                if( $result ) {
                    return $parsedValue
                }
            }
        }

        if ($Node.Style -eq 'Plain' -and $Node.Value -in '','~','null','Null','NULL') {
            return $null
        }

        return $Node.Value
    }
}

function Convert-YamlMappingToHashtable {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [YamlDotNet.RepresentationModel.YamlMappingNode]$Node,
        [switch] $Ordered
    )
    PROCESS {
        if ($Ordered) { $ret = [ordered]@{} } else { $ret = @{} }
        foreach($i in $Node.Children.Keys) {
            $ret[$i.Value] = Convert-YamlDocumentToPSObject $Node.Children[$i] -Ordered:$Ordered
        }
        return $ret
    }
}

function Convert-YamlSequenceToArray {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [YamlDotNet.RepresentationModel.YamlSequenceNode]$Node,
        [switch]$Ordered
    )
    PROCESS {
        $ret = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
        foreach($i in $Node.Children){
            $ret.Add((Convert-YamlDocumentToPSObject $i -Ordered:$Ordered))
        }
        return ,$ret
    }
}

function Convert-YamlDocumentToPSObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [System.Object]$Node, 
        [switch]$Ordered
    )
    PROCESS {
        switch($Node.GetType().FullName){
            "YamlDotNet.RepresentationModel.YamlMappingNode"{
                return Convert-YamlMappingToHashtable $Node -Ordered:$Ordered
            }
            "YamlDotNet.RepresentationModel.YamlSequenceNode" {
                return Convert-YamlSequenceToArray $Node -Ordered:$Ordered
            }
            "YamlDotNet.RepresentationModel.YamlScalarNode" {
                return (Convert-ValueToProperType $Node)
            }
        }
    }
}

function Convert-HashtableToDictionary {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [hashtable]$Data
    )
    foreach($i in $($data.Keys)) {
        $Data[$i] = Convert-PSObjectToGenericObject $Data[$i]
    }
    return $Data
}

function Convert-OrderedHashtableToDictionary {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [System.Collections.Specialized.OrderedDictionary] $Data
    )
    foreach ($i in $($data.Keys)) {
        $Data[$i] = Convert-PSObjectToGenericObject $Data[$i]
    }
    return $Data
}

function Convert-ListToGenericList {
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [array]$Data=@()
    )
    $ret = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    for($i=0; $i -lt $Data.Count; $i++) {
        $ret.Add((Convert-PSObjectToGenericObject $Data[$i]))
    }
    return ,$ret
}

function Convert-PSCustomObjectToDictionary {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [PSCustomObject]$Data
    )
    $ret = [System.Collections.Generic.Dictionary[string,object]](New-Object 'System.Collections.Generic.Dictionary[string,object]')
    foreach ($i in $Data.psobject.properties) {
        $ret[$i.Name] = Convert-PSObjectToGenericObject $i.Value
    }
    return $ret
}

function Convert-PSObjectToGenericObject {
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [System.Object]$Data
    )

    if ($null -eq $data) {
        return $data
    }

    $dataType = $data.GetType()
    if ($data -isnot [System.Object]) {
        return $data -as $dataType
    }

    if ($dataType.FullName -eq "System.Management.Automation.PSCustomObject") {
        return Convert-PSCustomObjectToDictionary $data
    } elseif (([System.Collections.Specialized.OrderedDictionary].IsAssignableFrom($dataType))){
        return Convert-OrderedHashtableToDictionary $data
    } elseif (([System.Collections.IDictionary].IsAssignableFrom($dataType))){
        return Convert-HashtableToDictionary $data
    } elseif (([System.Collections.IList].IsAssignableFrom($dataType))) {
        return Convert-ListToGenericList $data
    }
    return $data -as $dataType
}

function ConvertFrom-Yaml {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, ValueFromPipeline=$true, Position=0)]
        [string]$Yaml,
        [switch]$AllDocuments=$false,
        [switch]$Ordered,
        [switch]$UseMergingParser=$false
    )

    BEGIN {
        $d = ""
    }
    PROCESS {
        if($Yaml -is [string]) {
            $d += $Yaml + "`n"
        }
    }

    END {
        if($d -eq ""){
            return
        }
        $documents = Get-YamlDocuments -Yaml $d -UseMergingParser:$UseMergingParser
        if (!$documents.Count) {
            return
        }
        if($documents.Count -eq 1){
            return Convert-YamlDocumentToPSObject $documents[0].RootNode -Ordered:$Ordered
        }
        if(!$AllDocuments) {
            return Convert-YamlDocumentToPSObject $documents[0].RootNode -Ordered:$Ordered
        }
        $ret = @()
        foreach($i in $documents) {
            $ret += Convert-YamlDocumentToPSObject $i.RootNode -Ordered:$Ordered
        }
        return $ret
    }
}

$stringQuotingEmitterSource = @"
using System;
using System.Text.RegularExpressions;
using YamlDotNet;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.EventEmitters;
public class StringQuotingEmitter: ChainedEventEmitter {
    // Patterns from https://yaml.org/spec/1.2/spec.html#id2804356
    private static Regex quotedRegex = new Regex(@`"^(\~|null|true|false|on|off|yes|no|y|n|[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?|[-+]?(\.inf))?$`", RegexOptions.Compiled | RegexOptions.IgnoreCase);
    public StringQuotingEmitter(IEventEmitter next): base(next) {}

    public override void Emit(ScalarEventInfo eventInfo, IEmitter emitter) {
        var typeCode = eventInfo.Source.Value != null
        ? Type.GetTypeCode(eventInfo.Source.Type)
        : TypeCode.Empty;

        switch (typeCode) {
            case TypeCode.Char:
                if (Char.IsDigit((char)eventInfo.Source.Value)) {
                    eventInfo.Style = ScalarStyle.DoubleQuoted;
                }
                break;
            case TypeCode.String:
                var val = eventInfo.Source.Value.ToString();
                if (quotedRegex.IsMatch(val))
                {
                    eventInfo.Style = ScalarStyle.DoubleQuoted;
                } else if (val.IndexOf('\n') > -1) {
                    eventInfo.Style = ScalarStyle.Literal;
                }
                break;
        }

        base.Emit(eventInfo, emitter);
    }

    public static SerializerBuilder Add(SerializerBuilder builder) {
        return builder.WithEventEmitter(next => new StringQuotingEmitter(next));
    }
}
"@

if (!([System.Management.Automation.PSTypeName]'StringQuotingEmitter').Type) {
    $referenceList = @([YamlDotNet.Serialization.Serializer].Assembly.Location,[Text.RegularExpressions.Regex].Assembly.Location)
    if ($PSVersionTable.PSEdition -eq "Core") {
        $referenceList += [IO.Directory]::GetFiles([IO.Path]::Combine($PSHOME, 'ref'), 'netstandard.dll', [IO.SearchOption]::TopDirectoryOnly)
        Add-Type -TypeDefinition $stringQuotingEmitterSource -ReferencedAssemblies $referenceList -Language CSharp -CompilerOptions "-nowarn:1701"
    } else {
        Add-Type -TypeDefinition $stringQuotingEmitterSource -ReferencedAssemblies $referenceList -Language CSharp
    }
}

function Get-Serializer {
    Param(
        [Parameter(Mandatory=$true)][SerializationOptions]$Options
    )
    
    $builder = New-Object "YamlDotNet.Serialization.SerializerBuilder"
    
    if ($Options.HasFlag([SerializationOptions]::Roundtrip)) {
        $builder = $builder.EnsureRoundtrip()
    }
    if ($Options.HasFlag([SerializationOptions]::DisableAliases)) {
        $builder = $builder.DisableAliases()
    }
    if ($Options.HasFlag([SerializationOptions]::EmitDefaults)) {
        $builder = $builder.EmitDefaults()
    }
    if ($Options.HasFlag([SerializationOptions]::JsonCompatible)) {
        $builder = $builder.JsonCompatible()
    }
    if ($Options.HasFlag([SerializationOptions]::DefaultToStaticType)) {
        $builder = $builder.WithTypeResolver((New-Object "YamlDotNet.Serialization.TypeResolvers.StaticTypeResolver"))
    }
    if ($Options.HasFlag([SerializationOptions]::WithIndentedSequences)) {
        $builder = $builder.WithIndentedSequences()
    }
    $builder = [StringQuotingEmitter]::Add($builder)
    return $builder.Build()
}

function ConvertTo-Yaml {
    [CmdletBinding(DefaultParameterSetName = 'NoOptions')]
    Param(
        [Parameter(ValueFromPipeline = $true, Position=0)]
        [System.Object]$Data,

        [string]$OutFile,

        [Parameter(ParameterSetName = 'Options')]
        [SerializationOptions]$Options = [SerializationOptions]::Roundtrip,

        [Parameter(ParameterSetName = 'NoOptions')]
        [switch]$JsonCompatible,
        
        [switch]$KeepArray,

        [switch]$Force
    )
    BEGIN {
        $d = [System.Collections.Generic.List[object]](New-Object "System.Collections.Generic.List[object]")
    }
    PROCESS {
        if($data -is [System.Object]) {
            $d.Add($data)
        }
    }
    END {
        if ($d -eq $null -or $d.Count -eq 0) {
            return
        }
        if ($d.Count -eq 1 -and !($KeepArray)) {
            $d = $d[0]
        }
        $norm = Convert-PSObjectToGenericObject $d
        if ($OutFile) {
            $parent = Split-Path $OutFile
            if (!(Test-Path $parent)) {
                Throw "Parent folder for specified path does not exist"
            }
            if ((Test-Path $OutFile) -and !$Force) {
                Throw "Target file already exists. Use -Force to overwrite."
            }
            $wrt = New-Object "System.IO.StreamWriter" $OutFile
        } else {
            $wrt = New-Object "System.IO.StringWriter"
        }
    
        if ($PSCmdlet.ParameterSetName -eq 'NoOptions') {
            $Options = 0
            if ($JsonCompatible) {
                # No indent options :~(
                $Options = [SerializationOptions]::JsonCompatible
            }
        }

        try {
            $serializer = Get-Serializer $Options
            $serializer.Serialize($wrt, $norm)
        }
        catch{
            $_
        }
        finally {
            $wrt.Close()
        }
        if ($OutFile) {
            return
        } else {
            return $wrt.ToString()
        }
    }
}

New-Alias -Name cfy -Value ConvertFrom-Yaml
New-Alias -Name cty -Value ConvertTo-Yaml

Export-ModuleMember -Function ConvertFrom-Yaml,ConvertTo-Yaml -Alias cfy,cty
