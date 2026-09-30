<#
================================================================================
 Sys@dmin - Diagnostic Engine  (v4)
 --------------------------------------------------------------------------
 Pure data-collection / analysis layer. NO UI code lives here.
     . "$PSScriptRoot\DiagEngine.ps1"

 v4 FIXES THE ROOT CAUSE of the empty Firewall / GPO / Intune / DNS tabs:

   Invoke-DxSection previously declared
       [System.Collections.Generic.List[string]]$ErrorLog
   a STRONGLY TYPED parameter. Collectors normalise their error list to a plain
   array (ConvertTo-DxArray) and then call Invoke-DxSection again - passing an
   object[] into a [List[string]] parameter throws

       ArgumentException: Argument types do not match

   at the CALL SITE, which is why stack traces pointed at whatever innocent
   statement happened to sit next to the call. One landmine emptied four tabs.

   $ErrorLog is now untyped and appended defensively, so no collection type can
   ever break it again.

 Target : Windows 10 / 11 / Server 2016+  |  Windows PowerShell 5.1
================================================================================
#>

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

$script:DxKbFile = Join-Path $PSScriptRoot 'KnowledgeBase.json'
$script:DxKb     = $null
$script:DxWork   = Join-Path $env:ProgramData 'EndpointDiagX'
if (-not (Test-Path $script:DxWork)) { New-Item -Path $script:DxWork -ItemType Directory -Force | Out-Null }

# =============================================================================
# region  Core helpers
# =============================================================================

function Invoke-DxSafe {
    param([Parameter(Mandatory)][scriptblock]$Script, $Default = $null)
    try   { & $Script }
    catch { $Default }
}

function ConvertTo-DxArray {
    <# Normalises any collection to a plain object[]. Cannot throw. #>
    param($Collection)
    if ($null -eq $Collection) { return @() }
    try {
        if ($Collection -is [object[]]) { return $Collection }
        if ($Collection -is [System.Array]) { return [object[]]$Collection }
        if ($Collection -is [System.Collections.IEnumerable] -and $Collection -isnot [string]) {
            $o = New-Object System.Collections.ArrayList
            foreach ($x in $Collection) { $null = $o.Add($x) }
            return $o.ToArray()
        }
        return @($Collection)
    }
    catch {
        try {
            $o = New-Object System.Collections.ArrayList
            foreach ($x in $Collection) { $null = $o.Add($x) }
            return $o.ToArray()
        } catch { return @() }
    }
}

function Get-DxCount {
    <# Bulletproof count. Never throws, never returns null. #>
    param($Collection)
    if ($null -eq $Collection) { return 0 }
    try { return (ConvertTo-DxArray $Collection).Length } catch { return 0 }
}

function Add-DxError {
    <#
      Appends to an error log of ANY collection type. This is the counterpart to
      the untyped $ErrorLog parameter - List, ArrayList and object[] all work.
      Returns the (possibly new) collection so callers can reassign if needed.
    #>
    param($Log, [string]$Message)
    if ($null -eq $Log) { return ,@($Message) }
    try { $null = $Log.Add($Message); return $Log } catch { }
    try { return ,(@(ConvertTo-DxArray $Log) + @($Message)) } catch { }
    return $Log
}

function Invoke-DxSection {
    <#
      Runs ONE phase of a collector in isolation. A failure is recorded and the
      caller carries on with $Default, so a single bad statement can never empty
      an entire tab.

      $ErrorLog is deliberately UNTYPED - see the header note. Typing it as
      [List[string]] caused ArgumentException at every call site once the
      caller had normalised its list to an array.
    #>
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        $Default = $null,
        $ErrorLog
    )
    try { return & $Script }
    catch {
        try {
            $st = ''
            if ($_.ScriptStackTrace) { $st = ($_.ScriptStackTrace -split "`n")[0].Trim() }
            $msg = "[$Name] $($_.Exception.GetType().Name): $($_.Exception.Message)"
            if ($st) { $msg = "$msg  @ $st" }
            if ($null -ne $ErrorLog) { $null = Add-DxError -Log $ErrorLog -Message $msg }
            $script:DxLastSectionError = $msg
        } catch { }
        return $Default
    }
}

function Test-DxAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DxRegValue {
    param([string]$Path, [string]$Name)
    Invoke-DxSafe { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
}

function Get-DxCn {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return '' }
    if ($Dn -match 'CN=([^,]+)') { return $matches[1].Trim() }
    return $Dn
}

function Resolve-DxSidName {
    <#
      Three shapes turn up as a scope key and only one of them is a real SID:

        S-1-5-18                              SYSTEM
        S-0-0-00-0000000000-...-000           the device-context PLACEHOLDER
                                              EnterpriseDesktopAppManagement
                                              writes. It starts with "S-" so it
                                              survived the old all-zeros test
                                              and rendered raw.
        e3dc27d5-4452-44ed-b4f5-...           an Entra user OBJECT ID, which
                                              newer IME builds use instead of a
                                              SID. Translate() cannot resolve it
                                              and never will.
    #>
    param([string]$Sid)
    if (-not $Sid) { return '' }
    if ($Sid -match '^S-1-5-18$') { return 'Device (SYSTEM)' }
    if ($Sid -match '^0+(-0+)*$') { return 'Device (SYSTEM)' }
    if ($Sid -match '^S-0(-0+)+$') { return 'Device (SYSTEM)' }
    if ($Sid -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        $upn = ''
        try { $upn = "$($script:DxEnrolledUpn)" } catch { }
        if ($upn) { return "User $upn" }
        return "User (Entra object ID $($Sid.Substring(0,8)))"
    }
    $n = $Sid
    try { $n = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).Translate([System.Security.Principal.NTAccount]).Value } catch { }
    return $n
}

function Get-DxRegValueMap {
    <#
      Every value on a key, as an ordered name -> value map.

      Reading a named value only tells you "absent"; it cannot tell you what IS
      there. That distinction is the whole reason the Win32 columns came back
      blank with no error to chase.
    #>
    param([string]$Path)
    $map = [ordered]@{}
    try {
        $p = Get-ItemProperty -Path $Path -ErrorAction Stop
        foreach ($prop in $p.PSObject.Properties) {
            if ($prop.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $map[$prop.Name] = $prop.Value
        }
    } catch { }
    return $map
}

function Get-DxRegValueAny {
    # First candidate name that exists on the key, case-insensitively.
    param($Map, [string[]]$Names)
    if (-not $Map) { return $null }
    foreach ($n in $Names) {
        foreach ($k in $Map.Keys) {
            if ("$k" -ieq $n) { return $Map[$k] }
        }
    }
    return $null
}

function Invoke-DxProcess {
    param([Parameter(Mandatory)][string]$FilePath, [string]$Arguments = '', [int]$TimeoutSec = 120)
    try {
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $FilePath; $psi.Arguments = $Arguments
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $out = $p.StandardOutput.ReadToEnd()
        $err = $p.StandardError.ReadToEnd()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            Invoke-DxSafe { $p.Kill() }
            return "TIMEOUT after $TimeoutSec seconds."
        }
        return ($out + "`r`n" + $err).Trim()
    }
    catch { return "Failed to run $FilePath : $($_.Exception.Message)" }
}

function Initialize-DxModules {
    <#
      CDXML/CIM-backed modules do not always auto-load inside a background
      runspace. Import explicitly and record the outcome for the UI.
    #>
    $loaded = @(); $failed = @()
    foreach ($m in @('DnsClient','NetTCPIP','NetSecurity','NetAdapter','NetConnection')) {
        if (Get-Module -Name $m -ErrorAction SilentlyContinue) { $loaded += $m; continue }
        try { Import-Module $m -DisableNameChecking -ErrorAction Stop; $loaded += $m }
        catch { $failed += "$m : $($_.Exception.Message)" }
    }
    [pscustomobject]@{ Loaded = $loaded; Failed = $failed }
}
$script:DxModuleReport = Initialize-DxModules

# =============================================================================
# region  Knowledge base
# =============================================================================

function Get-DxKnowledgeBase {
    param([switch]$Force)
    if ($script:DxKb -and -not $Force) { return $script:DxKb }
    if (Test-Path $script:DxKbFile) {
        $script:DxKb = Invoke-DxSafe { Get-Content $script:DxKbFile -Raw -Encoding UTF8 | ConvertFrom-Json }
    }
    if (-not $script:DxKb) { $script:DxKb = [pscustomobject]@{ version='0'; rules=@(); textRules=@() } }
    return $script:DxKb
}

function Resolve-DxEventGuidance {
    param([string]$ProviderName, [int]$EventId, [string]$Level = 'Error', [string]$Message = '')
    $kb = Get-DxKnowledgeBase
    foreach ($rule in $kb.rules) {
        $idOk = $true; $provOk = $true
        if ($rule.eventIds -and $rule.eventIds.Count -gt 0) { $idOk = ($rule.eventIds -contains $EventId) }
        if ($rule.providers -and $rule.providers.Count -gt 0) {
            $provOk = $false
            foreach ($p in $rule.providers) { if ($ProviderName -and ($ProviderName -like "*$p*")) { $provOk = $true; break } }
        }
        if ($idOk -and $provOk) {
            return [pscustomobject]@{
                Matched=$true; RuleId=$rule.id; Title=$rule.title; Severity=$rule.severity
                Cause=$rule.cause; Impact=$rule.impact; Steps=@($rule.steps)
                Commands=@($rule.commands); Docs=$rule.docs
            }
        }
    }
    $q = [Uri]::EscapeDataString("$ProviderName event id $EventId")
    [pscustomobject]@{
        Matched=$false; RuleId='GENERIC'
        Title="Unclassified $Level - $ProviderName (Event ID $EventId)"
        Severity=$Level
        Cause='No knowledge-base rule matched this event yet. Use the triage workflow below, then add a rule to KnowledgeBase.json so the next occurrence is auto-classified.'
        Impact='Unknown - correlate with user-reported symptoms and the events logged immediately before and after this one.'
        Steps=@(
            'Open the raw event XML (the Full detail window shows it) and read the EventData fields - they usually name the failing file, service, driver or HRESULT.',
            'Look for a 0x8... / 0xC0... HRESULT in the message and decode it.',
            'Check whether the event is a one-off or repeating on a schedule - repeating usually means a policy, task or service loop.',
            'Correlate the timestamp with Setup, WindowsUpdateClient and GroupPolicy events to see if a change triggered it.',
            'If it started after a specific date, compare against installed updates and driver install dates.'
        )
        Commands=@(
            "Get-WinEvent -FilterHashtable @{LogName='System';Id=$EventId} -MaxEvents 5 | Format-List *",
            '[ComponentModel.Win32Exception]::new(0x80070002).Message',
            'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10'
        )
        Docs="https://learn.microsoft.com/en-us/search/?terms=$q"
    }
}

# =============================================================================
# region  System snapshot
# =============================================================================

function Get-DxSystemSnapshot {
    $os = Invoke-DxSafe { Get-CimInstance Win32_OperatingSystem }
    $cs = Invoke-DxSafe { Get-CimInstance Win32_ComputerSystem }
    $bios = Invoke-DxSafe { Get-CimInstance Win32_BIOS }
    $cpu = Invoke-DxSafe { Get-CimInstance Win32_Processor | Select-Object -First 1 }
    $boot = $null; $uptime = $null
    if ($os) { $boot = $os.LastBootUpTime; $uptime = (Get-Date) - $boot }
    $cv = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $display = Get-DxRegValue -Path $cv -Name 'DisplayVersion'
    $ubr = Get-DxRegValue -Path $cv -Name 'UBR'

    $disks = Invoke-DxSafe {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
            $pct = 0
            if ($_.Size -gt 0) { $pct = [math]::Round(($_.FreeSpace / $_.Size) * 100, 1) }
            [pscustomobject]@{
                Drive=$_.DeviceID; Label=$_.VolumeName
                SizeGB=[math]::Round($_.Size/1GB,1); FreeGB=[math]::Round($_.FreeSpace/1GB,1)
                FreePct=$pct; UsedPct=[math]::Round(100-$pct,1)
            }
        }
    } @()

    $memTotal=0; $memFree=0; $memPct=0
    if ($os) {
        $memTotal = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
        $memFree  = [math]::Round($os.FreePhysicalMemory/1MB,1)
        if ($memTotal -gt 0) { $memPct = [math]::Round((($memTotal-$memFree)/$memTotal)*100,1) }
    }

    $tpm = Invoke-DxSafe { Get-Tpm }
    $sb  = Invoke-DxSafe { Confirm-SecureBootUEFI } 'N/A'
    $bl  = Invoke-DxSafe { Get-BitLockerVolume -MountPoint $env:SystemDrive }
    $def = Invoke-DxSafe { Get-MpComputerStatus }

    [pscustomobject]@{
        Collected=Get-Date; ComputerName=$env:COMPUTERNAME; UserName="$env:USERDOMAIN\$env:USERNAME"
        IsAdmin=Test-DxAdmin; OSName=$os.Caption; OSVersion=$os.Version; DisplayVersion=$display
        Build="$($os.BuildNumber).$ubr"; Architecture=$os.OSArchitecture; InstallDate=$os.InstallDate
        LastBoot=$boot
        UptimeDays=if($uptime){[math]::Round($uptime.TotalDays,2)}else{$null}
        UptimeText=if($uptime){'{0}d {1}h {2}m' -f $uptime.Days,$uptime.Hours,$uptime.Minutes}else{'Unknown'}
        Manufacturer=$cs.Manufacturer; Model=$cs.Model; SerialNumber=$bios.SerialNumber
        BiosVersion=$bios.SMBIOSBIOSVersion; BiosDate=$bios.ReleaseDate
        Domain=$cs.Domain; PartOfDomain=$cs.PartOfDomain
        CPU=$cpu.Name; Cores=$cpu.NumberOfCores; LogicalCPUs=$cs.NumberOfLogicalProcessors
        MemoryTotalGB=$memTotal; MemoryFreeGB=$memFree; MemoryUsedPct=$memPct; Disks=$disks
        TpmPresent=$tpm.TpmPresent; TpmReady=$tpm.TpmReady
        TpmVersion=Invoke-DxSafe { (Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm).SpecVersion }
        SecureBoot=$sb; BitLockerStatus=$bl.ProtectionStatus; BitLockerPct=$bl.EncryptionPercentage
        DefenderRTP=$def.RealTimeProtectionEnabled; DefenderSigAge=$def.AntivirusSignatureAge
        PSVersion=$PSVersionTable.PSVersion.ToString()
    }
}

# =============================================================================
# region  Events
# =============================================================================

function Get-DxAvailableLogs {
    Invoke-DxSafe {
        Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordCount -gt 0 } |
            Sort-Object -Property @{Expression='RecordCount';Descending=$true} |
            Select-Object -ExpandProperty LogName
    } @('System','Application')
}

function Get-DxEvents {
    param(
        [string[]]$LogNames = @('System','Application'),
        [int[]]$Levels = @(1,2,3),
        [int]$Hours = 24,
        [int]$MaxPerLog = 1500,
        [string]$TextFilter = ''
    )
    $start = (Get-Date).AddHours(-1 * [math]::Abs($Hours))
    $results = New-Object System.Collections.Generic.List[object]

    foreach ($log in $LogNames) {
        if ([string]::IsNullOrWhiteSpace($log)) { continue }
        $lv = @($Levels)
        if ($lv -contains 4) { $lv = @($lv + 0) | Select-Object -Unique }
        $raw = $null
        try { $raw = Get-WinEvent -FilterHashtable @{ LogName=$log; StartTime=$start; Level=$lv } -MaxEvents $MaxPerLog -ErrorAction Stop }
        catch {
            if ($_.Exception.Message -notmatch 'No events were found') {
                $results.Add([pscustomobject]@{
                    TimeCreated=Get-Date; LogName=$log; Level='Warning'; LevelValue=3; Id=0
                    Provider='Sys@dmin'; Machine=$env:COMPUTERNAME; Task=''; Opcode=''
                    Keywords=''; RecordId=0; ProcessId=0; ThreadId=0; UserSid=''
                    Message="Could not read '$log': $($_.Exception.Message). Run elevated (the Security log always requires elevation)."
                }) | Out-Null
            }
            continue
        }
        foreach ($e in $raw) {
            $msg = $e.Message
            if (-not $msg) { $msg = '(no rendered message - provider metadata missing)' }
            $msg = ($msg -replace '\s+',' ').Trim()
            if ($TextFilter -and ($msg -notmatch [regex]::Escape($TextFilter)) -and
                ($e.ProviderName -notmatch [regex]::Escape($TextFilter))) { continue }
            $lvlName = $e.LevelDisplayName
            if (-not $lvlName) {
                $lvlName = switch ([int]$e.Level) { 1{'Critical'} 2{'Error'} 3{'Warning'} 4{'Information'} default{'Verbose'} }
            }
            $results.Add([pscustomobject]@{
                TimeCreated=$e.TimeCreated; LogName=$e.LogName; Level=$lvlName; LevelValue=[int]$e.Level
                Id=$e.Id; Provider=$e.ProviderName; Machine=$e.MachineName; Task=$e.TaskDisplayName
                Opcode=$e.OpcodeDisplayName; Keywords=((@($e.KeywordsDisplayNames)) -join ', ')
                RecordId=$e.RecordId; ProcessId=$e.ProcessId; ThreadId=$e.ThreadId
                UserSid=(Invoke-DxSafe { $e.UserId.Value } '')
                Message=$msg
            }) | Out-Null
        }
    }
    return ($results | Sort-Object TimeCreated -Descending)
}

function Get-DxEventFullDetail {
    param([Parameter(Mandatory)][string]$LogName, [Parameter(Mandatory)]$RecordId)
    $r = [pscustomobject]@{ Found=$false; Xml=''; XmlPretty=''; Properties=@(); Message=''; Error='' }
    if (-not $RecordId -or $RecordId -le 0) { $r.Error = 'No record id available for this row.'; return $r }
    try {
        $ev = Get-WinEvent -LogName $LogName -FilterXPath "*[System[(EventRecordID=$RecordId)]]" -MaxEvents 1 -ErrorAction Stop
        if (-not $ev) { $r.Error = 'Event no longer present in the log (it may have rolled over).'; return $r }
        $r.Found = $true; $r.Message = $ev.Message
        $raw = $ev.ToXml(); $r.Xml = $raw
        $r.XmlPretty = Invoke-DxSafe {
            $doc = New-Object System.Xml.XmlDocument; $doc.LoadXml($raw)
            $sw = New-Object System.IO.StringWriter
            $xw = New-Object System.Xml.XmlTextWriter($sw)
            $xw.Formatting = [System.Xml.Formatting]::Indented; $xw.Indentation = 2
            $doc.WriteContentTo($xw); $xw.Flush(); $sw.Flush(); $sw.ToString()
        } $raw
        $props = New-Object System.Collections.Generic.List[object]
        Invoke-DxSafe {
            $doc = [xml]$raw; $i = 0
            foreach ($d in @($doc.Event.EventData.Data)) {
                $nm=''; $vl=''
                if ($d -is [string]) { $vl = $d } else { $nm = $d.Name; $vl = $d.'#text' }
                if (-not $nm) { $nm = "Data[$i]" }
                $props.Add([pscustomobject]@{ Name=$nm; Value=$vl }) | Out-Null
                $i++
            }
        }
        $r.Properties = $props
    }
    catch { $r.Error = $_.Exception.Message }
    return $r
}

function Get-DxEventSummary {
    param([Parameter(Mandatory)][object[]]$Events, [int]$Top = 40)
    if (-not $Events -or $Events.Count -eq 0) { return @() }
    $groups = $Events | Where-Object { $_.Id -ne 0 } | Group-Object -Property Provider, Id |
              Sort-Object Count -Descending | Select-Object -First $Top
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($g in $groups) {
        $first = $g.Group | Sort-Object TimeCreated | Select-Object -First 1
        $last  = $g.Group | Sort-Object TimeCreated | Select-Object -Last 1
        $worst = $g.Group | Sort-Object LevelValue | Select-Object -First 1
        $kb = Resolve-DxEventGuidance -ProviderName $worst.Provider -EventId $worst.Id -Level $worst.Level -Message $worst.Message
        $out.Add([pscustomobject]@{
            Provider=$worst.Provider; Id=$worst.Id; Level=$worst.Level; LevelValue=$worst.LevelValue
            LogName=$worst.LogName; RecordId=$worst.RecordId; Count=$g.Count
            FirstSeen=$first.TimeCreated; LastSeen=$last.TimeCreated
            Title=$kb.Title; Known=$kb.Matched; Severity=$kb.Severity; Cause=$kb.Cause
            Impact=$kb.Impact; Steps=$kb.Steps; Commands=$kb.Commands; Docs=$kb.Docs
            SampleText=$worst.Message
        }) | Out-Null
    }
    return $out
}

function Get-DxEventStats {
    param([object[]]$Events)
    $c=0;$e=0;$w=0;$i=0
    foreach ($ev in $Events) { switch ($ev.LevelValue) { 1{$c++} 2{$e++} 3{$w++} default{$i++} } }
    [pscustomobject]@{ Total=@($Events).Count; Critical=$c; Error=$e; Warning=$w; Information=$i }
}

function Get-DxSeverityChartData {
    param($Stats)
    if (-not $Stats) { return @() }
    @(
        [pscustomobject]@{ Label='Critical';    Value=[int]$Stats.Critical;    Color='#DC2626' },
        [pscustomobject]@{ Label='Error';       Value=[int]$Stats.Error;       Color='#F97316' },
        [pscustomobject]@{ Label='Warning';     Value=[int]$Stats.Warning;     Color='#F59E0B' },
        [pscustomobject]@{ Label='Information'; Value=[int]$Stats.Information; Color='#3B82F6' }
    )
}

function Get-DxTopProviders {
    param([object[]]$Events, [int]$Top = 8)
    if (-not $Events -or @($Events).Count -eq 0) { return @() }
    $palette = @('#4F46E5','#7C3AED','#0EA5E9','#059669','#D97706','#DC2626','#DB2777','#0891B2')
    $i = 0
    $Events | Group-Object Provider | Sort-Object Count -Descending | Select-Object -First $Top | ForEach-Object {
        $nm = $_.Name
        if ($nm.Length -gt 34) { $nm = $nm.Substring(0,32) + '..' }
        $c = $palette[$i % $palette.Count]; $i++
        [pscustomobject]@{ Label=$nm; Value=$_.Count; Color=$c }
    }
}

function Get-DxEventTimeline {
    param([object[]]$Events, [int]$Buckets = 12)
    if (-not $Events -or @($Events).Count -eq 0) { return @() }
    $times = @($Events | Where-Object { $_.TimeCreated } | Select-Object -ExpandProperty TimeCreated)
    if ($times.Count -eq 0) { return @() }
    $min = ($times | Measure-Object -Minimum).Minimum
    $max = ($times | Measure-Object -Maximum).Maximum
    $span = ($max - $min).TotalMinutes
    if ($span -le 0) { $span = 1 }
    $step = $span / $Buckets
    $fmt = 'HH:mm'
    if ($span -gt (60*48)) { $fmt = 'dd MMM' } elseif ($span -gt 60*12) { $fmt = 'dd HH:mm' }
    $out = New-Object System.Collections.Generic.List[object]
    for ($b = 0; $b -lt $Buckets; $b++) {
        $bs = $min.AddMinutes($step * $b); $be = $min.AddMinutes($step * ($b + 1))
        if ($b -eq $Buckets - 1) { $n = @($Events | Where-Object { $_.TimeCreated -ge $bs -and $_.TimeCreated -le $be }).Count }
        else { $n = @($Events | Where-Object { $_.TimeCreated -ge $bs -and $_.TimeCreated -lt $be }).Count }
        $out.Add([pscustomobject]@{ Label=$bs.ToString($fmt); Value=$n; Color='#4F46E5' }) | Out-Null
    }
    return $out
}

function Get-DxDiskChartData {
    param($Snapshot)
    if (-not $Snapshot) { return @() }
    foreach ($d in @($Snapshot.Disks)) {
        $c = '#059669'
        if ($d.FreePct -lt 10) { $c = '#DC2626' } elseif ($d.FreePct -lt 20) { $c = '#F59E0B' }
        [pscustomobject]@{ Label="$($d.Drive) $($d.FreeGB)/$($d.SizeGB) GB"; Value=$d.UsedPct; Color=$c }
    }
}

# =============================================================================
# region  NETWORK - firewall
# =============================================================================

function Get-DxFirewallState {
    $sectionErrors = New-Object System.Collections.ArrayList

    $profiles = @(Invoke-DxSection -Name 'Firewall/Profiles' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Profile=[string]$_.Name; Enabled=[bool]$_.Enabled
                DefaultInboundAction="$($_.DefaultInboundAction)"
                DefaultOutboundAction="$($_.DefaultOutboundAction)"
                LogBlocked="$($_.LogBlocked)"; LogAllowed="$($_.LogAllowed)"
                LogFileName=[Environment]::ExpandEnvironmentVariables("$($_.LogFileName)")
                Status=if([bool]$_.Enabled){'Enabled'}else{'DISABLED'}
            }
        })
    })

    $connProfiles = @(Invoke-DxSection -Name 'Firewall/ConnProfiles' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Interface=[string]$_.InterfaceAlias; NetworkName=[string]$_.Name
                Category="$($_.NetworkCategory)"; IPv4Connectivity="$($_.IPv4Connectivity)"
            }
        })
    })

    $svc = Invoke-DxSection -Name 'Firewall/Service' -ErrorLog $sectionErrors -Script {
        Get-Service -Name MpsSvc -ErrorAction Stop
    }

    # --- rules: PRIMARY data, kept separate from enrichment ---------------
    # These used to share one try/catch. Get-NetFirewallPortFilter returns
    # thousands of objects and is the fragile part - when it threw, the rules
    # were discarded too, producing an empty grid from a working query.
    $ruleStats = [pscustomobject]@{ Total=0; Enabled=0; Inbound=0; Outbound=0; Allow=0; Block=0; InboundAllow=0; InboundBlock=0 }
    $script:DxFwEnabled = @()
    $null = Invoke-DxSection -Name 'Firewall/Rules' -ErrorLog $sectionErrors -Script {
        $all = @(Get-NetFirewallRule -ErrorAction Stop)
        $ruleStats.Total = $all.Count
        $en = @($all | Where-Object { "$($_.Enabled)" -eq 'True' })
        $ruleStats.Enabled      = $en.Count
        $ruleStats.Inbound      = @($en | Where-Object { "$($_.Direction)" -eq 'Inbound' }).Count
        $ruleStats.Outbound     = @($en | Where-Object { "$($_.Direction)" -eq 'Outbound' }).Count
        $ruleStats.Allow        = @($en | Where-Object { "$($_.Action)" -eq 'Allow' }).Count
        $ruleStats.Block        = @($en | Where-Object { "$($_.Action)" -eq 'Block' }).Count
        $ruleStats.InboundAllow = @($en | Where-Object { "$($_.Direction)" -eq 'Inbound' -and "$($_.Action)" -eq 'Allow' }).Count
        $ruleStats.InboundBlock = @($en | Where-Object { "$($_.Direction)" -eq 'Inbound' -and "$($_.Action)" -eq 'Block' }).Count
        $script:DxFwEnabled = @($en | Select-Object -First 1500)
    }
    $enabledRules = @($script:DxFwEnabled); $script:DxFwEnabled = @()

    $portMap = @{}
    $null = Invoke-DxSection -Name 'Firewall/PortFilters' -ErrorLog $sectionErrors -Script {
        foreach ($p in @(Get-NetFirewallPortFilter -ErrorAction Stop)) {
            $k = "$($p.InstanceID)"
            if ($k -and -not $portMap.ContainsKey($k)) {
                $portMap[$k] = [pscustomobject]@{
                    Protocol="$($p.Protocol)"; LocalPort=((@($p.LocalPort)) -join ','); RemotePort=((@($p.RemotePort)) -join ',')
                }
            }
        }
    }

    $appMap = @{}
    $null = Invoke-DxSection -Name 'Firewall/AppFilters' -ErrorLog $sectionErrors -Script {
        foreach ($a in @(Get-NetFirewallApplicationFilter -ErrorAction Stop)) {
            $k = "$($a.InstanceID)"
            if ($k -and -not $appMap.ContainsKey($k)) { $appMap[$k] = "$($a.Program)" }
        }
    }

    $rules = New-Object System.Collections.ArrayList
    $null = Invoke-DxSection -Name 'Firewall/Project' -ErrorLog $sectionErrors -Script {
        foreach ($r in $enabledRules) {
            $id = "$($r.InstanceID)"; if (-not $id) { $id = "$($r.Name)" }
            $pf = $null; $ap = ''
            if ($id -and $portMap.ContainsKey($id)) { $pf = $portMap[$id] }
            if ($id -and $appMap.ContainsKey($id))  { $ap = $appMap[$id] }
            $null = $rules.Add([pscustomobject]@{
                DisplayName="$($r.DisplayName)"; Direction="$($r.Direction)"; Action="$($r.Action)"
                Profile="$($r.Profile)"; Enabled='True'; Group="$($r.DisplayGroup)"
                Protocol=if($pf){$pf.Protocol}else{''}
                LocalPort=if($pf){$pf.LocalPort}else{''}
                RemotePort=if($pf){$pf.RemotePort}else{''}
                Program=$ap; Owner="$($r.Owner)"; PolicyStore="$($r.PolicyStoreSourceType)"
            })
        }
    }

    $logPath = ''
    $lp = @($profiles | Where-Object { $_.LogFileName } | Select-Object -First 1)
    if ($lp.Count -gt 0) { $logPath = $lp[0].LogFileName }
    if (-not $logPath) { $logPath = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log" }

    $logRows = @(Invoke-DxSection -Name 'Firewall/Log' -Default @() -ErrorLog $sectionErrors -Script {
        if (-not (Test-Path $logPath)) { return @() }
        $o = New-Object System.Collections.ArrayList
        foreach ($l in @(Get-Content -Path $logPath -Tail 400 -ErrorAction Stop)) {
            if ($l -match '^#' -or [string]::IsNullOrWhiteSpace($l)) { continue }
            $p = $l -split '\s+'
            if ($p.Count -lt 8) { continue }
            $null = $o.Add([pscustomobject]@{
                Time="$($p[0]) $($p[1])"; Action=$p[2]; Protocol=$p[3]
                SrcIp=$p[4]; DstIp=$p[5]; SrcPort=$p[6]; DstPort=$p[7]
            })
        }
        $arr = $o.ToArray(); [array]::Reverse($arr); ,@($arr | Select-Object -First 250)
    })

    $blocked = @(Invoke-DxSection -Name 'Firewall/BlockedEvents' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=@(5152,5157); StartTime=(Get-Date).AddDays(-3) } -MaxEvents 150 -ErrorAction Stop |
            ForEach-Object {
                $m = ($_.Message -replace '\s+',' ').Trim()
                $app=''; $dst=''; $dport=''
                if ($m -match 'Application Name:\s*(\S+)')    { $app = $matches[1] }
                if ($m -match 'Destination Address:\s*(\S+)') { $dst = $matches[1] }
                if ($m -match 'Destination Port:\s*(\S+)')    { $dport = $matches[1] }
                [pscustomobject]@{
                    Time=$_.TimeCreated; Id=$_.Id
                    Kind=if($_.Id -eq 5157){'Connection blocked'}else{'Packet dropped'}
                    Application=$app; Destination=$dst; Port=$dport
                }
            })
    })

    # --- findings ---------------------------------------------------------
    $issues = New-Object System.Collections.ArrayList
    foreach ($p in $profiles) {
        if (-not $p.Enabled) { $null = $issues.Add("Firewall is DISABLED for the $($p.Profile) profile - the endpoint is unprotected on any network classified as $($p.Profile).") }
        if ($p.DefaultInboundAction -eq 'Allow') { $null = $issues.Add("$($p.Profile) profile default inbound action is ALLOW. The secure baseline is Block; this exposes every listening port with no explicit block rule.") }
        if ($p.DefaultOutboundAction -eq 'Block') { $null = $issues.Add("$($p.Profile) profile default outbound action is BLOCK - expect application breakage unless every required flow has an explicit allow rule.") }
        if ($p.LogBlocked -ne 'True') { $null = $issues.Add("Dropped-packet logging is off for the $($p.Profile) profile, so there is no local evidence trail when the firewall blocks traffic.") }
    }
    if ($svc -and $svc.Status -ne 'Running') { $null = $issues.Add("The Windows Defender Firewall service (MpsSvc) is '$($svc.Status)'. Firewall policy is not being enforced.") }
    foreach ($cp in $connProfiles) {
        if ($cp.Category -eq 'Public') { $null = $issues.Add("Interface '$($cp.Interface)' ($($cp.NetworkName)) is classified PUBLIC. Domain-scoped firewall rules will not apply on it - a very common cause of 'remote management stopped working'.") }
    }
    if ($ruleStats.InboundAllow -gt 250) { $null = $issues.Add("$($ruleStats.InboundAllow) enabled inbound ALLOW rules. Large inbound surfaces are worth an audit - filter the rules grid by Direction=Inbound.") }
    if (@($blocked).Count -gt 0) { $null = $issues.Add("$(@($blocked).Count) blocked-connection audit event(s) in the last 3 days - see the blocked traffic grid.") }

    if ($ruleStats.Total -eq 0) {
        $null = Add-DxError -Log $sectionErrors -Message '[Firewall/Rules] Get-NetFirewallRule returned nothing. This requires elevation and the NetSecurity module.'
    } elseif ($rules.Count -eq 0) {
        $null = Add-DxError -Log $sectionErrors -Message "[Firewall/Project] $($ruleStats.Total) rules were read but none projected into the grid."
    }
    if ($issues.Count -eq 0 -and $rules.Count -gt 0) { $null = $issues.Add('No firewall problems detected. All profiles enabled with a Block inbound default.') }

    $profileChart = foreach ($p in $profiles) {
        [pscustomobject]@{ Label=$p.Profile; Value=1; Color=if($p.Enabled){'#059669'}else{'#DC2626'} }
    }
    $ruleChart = @(
        [pscustomobject]@{ Label='Inbound allow';  Value=$ruleStats.InboundAllow; Color='#0EA5E9' },
        [pscustomobject]@{ Label='Inbound block';  Value=$ruleStats.InboundBlock; Color='#DC2626' },
        [pscustomobject]@{ Label='Outbound allow'; Value=[math]::Max(0,$ruleStats.Allow-$ruleStats.InboundAllow); Color='#059669' },
        [pscustomobject]@{ Label='Outbound block'; Value=[math]::Max(0,$ruleStats.Block-$ruleStats.InboundBlock); Color='#F59E0B' }
    )

    [pscustomobject]@{
        Profiles=@($profiles); ConnectionProfiles=@($connProfiles); Service=$svc
        Rules=@($rules.ToArray()); RuleStats=$ruleStats; LogPath=$logPath; LogRows=@($logRows)
        BlockedEvents=@($blocked); Issues=@($issues.ToArray())
        SectionErrors=@($sectionErrors.ToArray())
        ProfileChart=@($profileChart); RuleChart=$ruleChart
    }
}

# =============================================================================
# region  NETWORK - DNS
# =============================================================================

$script:DxDnsTypeMap = @{
    1='A'; 2='NS'; 5='CNAME'; 6='SOA'; 12='PTR'; 15='MX'; 16='TXT'; 17='RP'; 24='SIG'; 25='KEY'
    28='AAAA'; 29='LOC'; 33='SRV'; 35='NAPTR'; 39='DNAME'; 41='OPT'; 43='DS'; 46='RRSIG'
    47='NSEC'; 48='DNSKEY'; 50='NSEC3'; 52='TLSA'; 64='SVCB'; 65='HTTPS'; 99='SPF'; 255='ANY'; 257='CAA'
}
$script:DxDnsStatusMap = @{
    0='Success'; 9003='Name does not exist'; 9501='No records'; 9502='Bad packet'
    9503='Server failure'; 9505='Unsecure packet'; 9701='No memory'; 9714='Timeout'
}

function ConvertTo-DxDnsRecordType {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = "$Value"
    if ($s -match '^\d+$') {
        $n = 0
        if ([int]::TryParse($s, [ref]$n) -and $script:DxDnsTypeMap.ContainsKey($n)) { return $script:DxDnsTypeMap[$n] }
    }
    return $s
}

function ConvertTo-DxDnsStatus {
    param($Value)
    if ($null -eq $Value) { return '' }
    $s = "$Value"
    if ($s -match '^\d+$') {
        $n = 0
        if ([int]::TryParse($s, [ref]$n) -and $script:DxDnsStatusMap.ContainsKey($n)) { return $script:DxDnsStatusMap[$n] }
    }
    return $s
}

function Get-DxDnsServersNative {
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up') { continue }
            if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
            $props = $null
            try { $props = $nic.GetIPProperties() } catch { continue }
            if (-not $props) { continue }
            $dns = @()
            foreach ($a in @($props.DnsAddresses)) {
                if ($a -and "$($a.AddressFamily)" -eq 'InterNetwork') { $dns += $a.IPAddressToString }
            }
            if ($dns.Count -eq 0) { continue }
            $null = $out.Add([pscustomobject]@{
                Interface=$nic.Name; Index=0; Servers=($dns -join ', '); Count=$dns.Count; Source='.NET'
            })
        }
    } catch { }
    return @($out.ToArray())
}

function Get-DxDnsSuffixNative {
    $out = New-Object System.Collections.ArrayList
    try {
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            if ($nic.OperationalStatus -ne 'Up') { continue }
            if ($nic.NetworkInterfaceType -eq 'Loopback') { continue }
            $props = $null
            try { $props = $nic.GetIPProperties() } catch { continue }
            if (-not $props) { continue }
            $null = $out.Add([pscustomobject]@{
                Interface=$nic.Name; Suffix="$($props.DnsSuffix)"; SearchList=''
                RegisterAddress="$($props.IsDnsEnabled)"; UseSuffixInReg=''; Source='.NET'
            })
        }
    } catch { }
    return @($out.ToArray())
}

function Get-DxDnsCacheNative {
    $out = New-Object System.Collections.ArrayList
    try {
        $txt = Invoke-DxProcess -FilePath "$env:SystemRoot\System32\ipconfig.exe" -Arguments '/displaydns' -TimeoutSec 45
        if (-not $txt) { return @() }
        $cur = $null
        foreach ($line in ($txt -split "`r?`n")) {
            $l = $line.Trim()
            if (-not $l -or $l -match '^-{3,}$') { continue }
            if ($l -match '^[^:]*?[.\s]{3,}:\s*(.*)$') {
                $val = $matches[1].Trim()
                $label = (($l -split ':')[0] -replace '[.\s]+$','').Trim()
                if ($label -match '(?i)record name') {
                    if ($cur -and $cur.Entry) { $null = $out.Add($cur) }
                    $cur = [pscustomobject]@{ Entry=$val; Name=$val; Type=''; TTL=''; Status='Success'; Data=''; Section=''; Source='ipconfig' }
                }
                elseif ($cur -and $label -match '(?i)record type') {
                    $d = ($val -replace '\D','')
                    if ($d) { $n=0; if ([int]::TryParse($d,[ref]$n)) { $cur.Type = ConvertTo-DxDnsRecordType $n } }
                }
                elseif ($cur -and $label -match '(?i)time to live') { $cur.TTL = $val }
                elseif ($cur -and $label -match '(?i)section') { $cur.Section = $val }
                elseif ($cur -and $val -match '^\d+\.\d+\.\d+\.\d+$') { $cur.Data = $val }
            }
        }
        if ($cur -and $cur.Entry) { $null = $out.Add($cur) }
    } catch { }
    return @($out.ToArray())
}

function Get-DxDnsStateCore {
    <# SECTION ISOLATED. Every phase runs inside Invoke-DxSection. #>
    $sectionErrors = New-Object System.Collections.ArrayList
    $diag          = New-Object System.Collections.ArrayList
    $srcServers = 'none'; $srcCache = 'none'; $srcProbe = 'none'

    # 1. configured servers
    $servers = @(Invoke-DxSection -Name 'DNS/Servers' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { @($_.ServerAddresses).Count -gt 0 } | ForEach-Object {
                [pscustomobject]@{
                    Interface=[string]$_.InterfaceAlias; Index=[int]$_.InterfaceIndex
                    Servers=((@($_.ServerAddresses)) -join ', '); Count=@($_.ServerAddresses).Count
                    Source='DnsClient'
                }
            })
    })
    if (@($servers).Count -gt 0) { $srcServers = 'DnsClient module' }
    else {
        $servers = @(Invoke-DxSection -Name 'DNS/Servers.NET' -Default @() -ErrorLog $sectionErrors -Script { Get-DxDnsServersNative })
        if (@($servers).Count -gt 0) { $srcServers = '.NET fallback'; $null = $diag.Add("Recovered $(@($servers).Count) adapter(s) via the .NET fallback.") }
    }

    # 2. suffixes
    $clients = @(Invoke-DxSection -Name 'DNS/Suffixes' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-DnsClient -ErrorAction Stop | Where-Object { $_.InterfaceAlias } | ForEach-Object {
            [pscustomobject]@{
                Interface=[string]$_.InterfaceAlias; Suffix=[string]$_.ConnectionSpecificSuffix
                SearchList=((@($_.ConnectionSpecificSuffixSearchList)) -join ', ')
                RegisterAddress=[string]$_.RegisterThisConnectionsAddress
                UseSuffixInReg=[string]$_.UseSuffixWhenRegistering; Source='DnsClient'
            }
        })
    })
    if (@($clients).Count -eq 0) {
        $clients = @(Invoke-DxSection -Name 'DNS/Suffixes.NET' -Default @() -ErrorLog $sectionErrors -Script { Get-DxDnsSuffixNative })
    }

    # 3. global settings  (NOT named $global - collides with the scope keyword)
    $globalCfg = Invoke-DxSection -Name 'DNS/Global' -ErrorLog $sectionErrors -Script {
        $g = Get-DnsClientGlobalSetting -ErrorAction Stop
        [pscustomobject]@{
            SuffixSearchList=((@($g.SuffixSearchList)) -join ', ')
            UseDevolution=[string]$g.UseDevolution; DevolutionLevel=[string]$g.DevolutionLevel
        }
    }
    if (-not $globalCfg) {
        $sl = Get-DxRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'SearchList'
        $globalCfg = [pscustomobject]@{ SuffixSearchList="$sl"; UseDevolution=''; DevolutionLevel='' }
    }

    # 4. NRPT
    $nrpt = @(Invoke-DxSection -Name 'DNS/NRPT' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-DnsClientNrptPolicy -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Namespace=((@($_.Namespace)) -join ', '); NameServers=((@($_.NameServers)) -join ', ')
                DnsSecEnabled=[string]$_.DnsSecValidationRequired; DirectAccess=[string]$_.DirectAccessEnabled
            }
        })
    })

    # 5. resolver cache
    $cache = @(Invoke-DxSection -Name 'DNS/Cache' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-DnsClientCache -ErrorAction Stop | Select-Object -First 400 | ForEach-Object {
            $rn = [string]$_.RecordName; if (-not $rn) { $rn = [string]$_.Name }
            [pscustomobject]@{
                Entry=[string]$_.Entry; Name=$rn
                Type=(ConvertTo-DxDnsRecordType $_.Type); Status=(ConvertTo-DxDnsStatus $_.Status)
                TTL=[string]$_.TimeToLive; Data=[string]$_.Data; Section=[string]$_.Section; Source='DnsClient'
            }
        })
    })
    if (@($cache).Count -gt 0) { $srcCache = 'DnsClient module' }
    else {
        $cache = @(Invoke-DxSection -Name 'DNS/Cache.ipconfig' -Default @() -ErrorLog $sectionErrors -Script { @(Get-DxDnsCacheNative | Select-Object -First 400) })
        if (@($cache).Count -gt 0) { $srcCache = 'ipconfig /displaydns' }
    }

    # 6. reachability  (populated in place - see note in section 7)
    $reach = New-Object System.Collections.ArrayList
    $null = Invoke-DxSection -Name 'DNS/Reachability' -ErrorLog $sectionErrors -Script {
        $seen = @{}
        foreach ($s in @($servers)) {
            foreach ($ip in ("$($s.Servers)" -split ',')) {
                $ipT = "$ip".Trim()
                if ([string]::IsNullOrWhiteSpace($ipT) -or $seen.ContainsKey($ipT)) { continue }
                $seen[$ipT] = $true
                $tcpOk = $false
                try { $tcpOk = [bool](Test-DxPortQuick -Target $ipT -Port 53 -TimeoutMs 1500).Open } catch { }
                $icmpOk = $false
                try { $icmpOk = [bool](Invoke-DxPingOnce -Target $ipT -TimeoutMs 1200).Success } catch { }
                $null = $reach.Add([pscustomobject]@{
                    Server=$ipT; Interface=[string]$s.Interface
                    TcpPort53=$tcpOk; IcmpReply=$icmpOk; Reachable=($tcpOk -or $icmpOk)
                })
            }
        }
    }

    # 7. probes
    #    Lists are created HERE and populated in place. Returning a List from
    #    inside Invoke-DxSection went through return-value unrolling and arrived
    #    empty; mutating a parent-scope object has no such ambiguity.
    $probes = New-Object System.Collections.ArrayList
    $script:DxProbeSrc = $null
    $null = Invoke-DxSection -Name 'DNS/Probes' -ErrorLog $sectionErrors -Script {
        $targets = @('login.microsoftonline.com','manage.microsoft.com','graph.microsoft.com')
        if ($env:USERDNSDOMAIN) { $targets += [string]$env:USERDNSDOMAIN }
        foreach ($t in $targets) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $addr = New-Object System.Collections.ArrayList
            $usedNet = $false
            try {
                foreach ($x in @(Resolve-DnsName -Name $t -Type A -DnsOnly -ErrorAction Stop)) {
                    if ($x.IPAddress) { $null = $addr.Add([string]$x.IPAddress) }
                }
            } catch { }
            if ($addr.Count -eq 0) {
                try {
                    foreach ($a in @([System.Net.Dns]::GetHostAddresses($t))) {
                        if ("$($a.AddressFamily)" -eq 'InterNetwork') { $null = $addr.Add([string]$a.IPAddressToString); $usedNet = $true }
                    }
                } catch { }
            }
            $sw.Stop()
            if ($addr.Count -gt 0) {
                if ($usedNet) { $script:DxProbeSrc = '.NET fallback' }
                elseif (-not $script:DxProbeSrc) { $script:DxProbeSrc = 'DnsClient module' }
            }
            $null = $probes.Add([pscustomobject]@{
                Name=[string]$t; Resolved=($addr.Count -gt 0)
                Addresses=((@($addr.ToArray())) -join ', '); Ms=[int]$sw.ElapsedMilliseconds
            })
        }
    }
    if ($script:DxProbeSrc) { $srcProbe = $script:DxProbeSrc; $script:DxProbeSrc = $null }

    # publish partial data BEFORE assembly, so a late fault cannot discard it
    $script:DxDnsPartial = [pscustomobject]@{
        Servers=@($servers); Clients=@($clients); Global=$globalCfg
        Nrpt=@($nrpt); Cache=@($cache); Reachability=@($reach.ToArray()); Probes=@($probes.ToArray())
        SourceServers=$srcServers; SourceCache=$srcCache; SourceProbe=$srcProbe
    }

    # 8. findings
    $issues = New-Object System.Collections.ArrayList
    $null = Invoke-DxSection -Name 'DNS/Findings' -ErrorLog $sectionErrors -Script {
        foreach ($d in @($diag.ToArray())) { $null = $issues.Add("DIAGNOSTIC: $d") }
        if (@($servers).Count -eq 0) {
            $null = $issues.Add('No DNS servers found on any connected adapter. If this device clearly has DNS, see the section errors below - collection failed rather than the device being misconfigured.')
        }
        foreach ($r in @($reach.ToArray())) {
            if (-not $r.Reachable) { $null = $issues.Add("DNS server $($r.Server) on '$($r.Interface)' did not answer on TCP 53 or ICMP.") }
        }
        $publicList = @('8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9','208.67.222.222')
        $pub = @($reach.ToArray() | Where-Object { $publicList -contains "$($_.Server)" })
        $isDomain = $false
        try { $isDomain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch { }
        if ($isDomain -and $pub.Count -gt 0) {
            $null = $issues.Add("Public DNS ($((($pub | ForEach-Object { $_.Server })) -join ', ')) is configured on a domain-joined device. Internal names and _msdcs SRV records will not resolve, breaking Group Policy and domain logon.")
        }
        foreach ($s in @($servers)) {
            if ("$($s.Servers)" -match '^127\.' -and [int]$s.Count -eq 1) {
                $null = $issues.Add("Adapter '$($s.Interface)' points only at a loopback DNS address. Expected on a DNS server; on a client it usually means a VPN or filtering agent is intercepting DNS.")
            }
        }
        foreach ($p in @($probes.ToArray())) {
            if (-not $p.Resolved) { $null = $issues.Add("Could not resolve '$($p.Name)' - check the DNS servers and any NRPT or split-DNS rules.") }
            elseif ([int]$p.Ms -gt 800) { $null = $issues.Add("Resolving '$($p.Name)' took $($p.Ms) ms - slow DNS causes sign-in and check-in delays.") }
        }
        if (@($nrpt).Count -gt 0) { $null = $issues.Add("$(@($nrpt).Count) NRPT rule(s) are active - specific namespaces are routed to designated DNS servers.") }
    }

    # assembly: plain arrays only
    $issuesOut = @()
    foreach ($e in @($sectionErrors.ToArray())) { $issuesOut = $issuesOut + @("SECTION ERROR $e") }
    foreach ($i in @($issues.ToArray()))        { $issuesOut = $issuesOut + @("$i") }

    $incomplete = @()
    if ((Get-DxCount $reach)  -eq 0) { $incomplete = $incomplete + @('server reachability') }
    if ((Get-DxCount $probes) -eq 0) { $incomplete = $incomplete + @('resolution probes') }
    if ((Get-DxCount $cache)  -eq 0) { $incomplete = $incomplete + @('resolver cache') }

    if ((Get-DxCount $incomplete) -gt 0) {
        $issuesOut = @("INCOMPLETE: no data was collected for $($incomplete -join ', '). Treat those panels as unverified rather than healthy.") + $issuesOut
    }
    elseif ((Get-DxCount $issuesOut) -eq 0) {
        $issuesOut = @('No DNS problems detected. All configured servers answered and test names resolved promptly.')
    }

    $probeChart = @()
    foreach ($p in @($probes.ToArray())) {
        $c = '#059669'
        if (-not $p.Resolved) { $c = '#DC2626' }
        elseif ([int]$p.Ms -gt 800) { $c = '#F59E0B' }
        elseif ([int]$p.Ms -gt 300) { $c = '#0EA5E9' }
        $nm = "$($p.Name)"; if ($nm.Length -gt 30) { $nm = $nm.Substring(0,28) + '..' }
        $probeChart = $probeChart + @([pscustomobject]@{ Label=$nm; Value=[int]$p.Ms; Color=$c })
    }

    [pscustomobject]@{
        Servers=@($servers); Clients=@($clients); Global=$globalCfg
        Nrpt=@($nrpt); Cache=@($cache); Reachability=@($reach.ToArray()); Probes=@($probes.ToArray())
        Issues=$issuesOut; ProbeChart=$probeChart
        Diagnostics=@($diag.ToArray()); SectionErrors=@($sectionErrors.ToArray())
        SourceServers=$srcServers; SourceCache=$srcCache; SourceProbe=$srcProbe
        ModuleReport=$script:DxModuleReport
    }
}

function Get-DxDnsState {
    <# NEVER-THROW WRAPPER. Recovers partial data if assembly fails. #>
    $script:DxDnsPartial = $null
    try {
        $r = Get-DxDnsStateCore
        if ($r) { return $r }
        $err = 'The DNS collector returned nothing (no exception was raised).'; $where = ''
    }
    catch {
        $err = "$($_.Exception.GetType().Name): $($_.Exception.Message)"; $where = ''
        if ($_.ScriptStackTrace -match 'line (\d+)') {
            $ln = [int]$matches[1]
            $where = " at line $ln"
            $srcLine = Invoke-DxSafe {
                $f = Join-Path $PSScriptRoot 'DiagEngine.ps1'
                if (Test-Path $f) { (Get-Content -Path $f -ErrorAction Stop)[$ln - 1].Trim() }
            } ''
            if ($srcLine) { $where += ": $srcLine" }
        }
    }

    $p = $script:DxDnsPartial
    $recovered = $false
    if ($p) {
        if (((Get-DxCount $p.Servers) + (Get-DxCount $p.Cache) + (Get-DxCount $p.Clients)) -gt 0) { $recovered = $true }
    }
    $msg = @()
    if ($recovered) {
        $msg += 'PARTIAL RESULT: the collector failed during final assembly, but the data below was gathered successfully and is valid.'
        $msg += "COLLECTOR FAULT: $err$where"
    } else {
        $msg += "COLLECTOR FAILED: $err$where"
        $msg += 'Every panel on this tab is empty because collection failed. This is a tool fault, not evidence about the device.'
    }
    [pscustomobject]@{
        Servers=if($recovered){ConvertTo-DxArray $p.Servers}else{@()}
        Clients=if($recovered){ConvertTo-DxArray $p.Clients}else{@()}
        Global=if($recovered){$p.Global}else{$null}
        Nrpt=if($recovered){ConvertTo-DxArray $p.Nrpt}else{@()}
        Cache=if($recovered){ConvertTo-DxArray $p.Cache}else{@()}
        Reachability=if($recovered){ConvertTo-DxArray $p.Reachability}else{@()}
        Probes=if($recovered){ConvertTo-DxArray $p.Probes}else{@()}
        ProbeChart=@(); Issues=$msg
        Diagnostics=@("Get-DxDnsState wrapper caught: $err$where")
        SectionErrors=@("[WRAPPER] $err$where")
        SourceServers=if($recovered){"$($p.SourceServers) (partial)"}else{'failed'}
        SourceCache=if($recovered){"$($p.SourceCache) (partial)"}else{'failed'}
        SourceProbe=if($recovered){"$($p.SourceProbe) (partial)"}else{'failed'}
        ModuleReport=$script:DxModuleReport
    }
}

function Get-DxNetAdapters {
    Invoke-DxSafe {
        Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' -or $_.Status -eq 'Disconnected' } | ForEach-Object {
            $cfg = Invoke-DxSafe { Get-NetIPConfiguration -InterfaceIndex $_.ifIndex -ErrorAction Stop }
            [pscustomobject]@{
                Name=$_.Name; Description=$_.InterfaceDescription; Status="$($_.Status)"
                LinkSpeed="$($_.LinkSpeed)"; MacAddress=$_.MacAddress; DriverVersion=$_.DriverVersion
                IPv4=if($cfg){((@($cfg.IPv4Address.IPAddress)) -join ', ')}else{''}
                Gateway=if($cfg){((@($cfg.IPv4DefaultGateway.NextHop)) -join ', ')}else{''}
                DNS=if($cfg){((@($cfg.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | Select-Object -ExpandProperty ServerAddresses)) -join ', ')}else{''}
            }
        }
    } @()
}

# =============================================================================
# region  NETWORK - ping / lookup / trace / port
# =============================================================================

function Invoke-DxPingOnce {
    param([Parameter(Mandatory)][string]$Target, [int]$TimeoutMs = 1500, [int]$BufferSize = 32)
    $out = [pscustomobject]@{
        Target=$Target; Success=$false; Address=''; RoundtripMs=-1
        Status='Unknown'; Ttl=0; Time=Get-Date; Error=''
    }
    $p = $null
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $buf = New-Object byte[] $BufferSize
        for ($i=0; $i -lt $BufferSize; $i++) { $buf[$i] = 97 }
        $opt = New-Object System.Net.NetworkInformation.PingOptions(128, $false)
        $r = $p.Send($Target, $TimeoutMs, $buf, $opt)
        $out.Status = "$($r.Status)"
        if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $out.Success = $true; $out.RoundtripMs = [int]$r.RoundtripTime; $out.Address = "$($r.Address)"
            if ($r.Options) { $out.Ttl = [int]$r.Options.Ttl }
        }
    }
    catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
        $out.Error = $m; $out.Status = 'Error'
    }
    finally { if ($p) { Invoke-DxSafe { $p.Dispose() } } }
    return $out
}

function Invoke-DxTraceHop {
    <# One hop, one probe. The UI calls this per TTL so the route builds live. #>
    param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][int]$Ttl,
          [int]$TimeoutMs = 2000, [switch]$ResolveNames)
    $out = [pscustomobject]@{
        Hop=$Ttl; Address=''; HostName=''; RoundtripMs=-1
        Status='Unknown'; IsDestination=$false; Success=$false; Error=''
    }
    $p = $null
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $buf = New-Object byte[] 32
        for ($i=0; $i -lt 32; $i++) { $buf[$i] = 97 }
        $opt = New-Object System.Net.NetworkInformation.PingOptions($Ttl, $false)
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = $p.Send($Target, $TimeoutMs, $buf, $opt)
        $sw.Stop()
        $out.Status = "$($r.Status)"
        if ($r.Address) { $out.Address = "$($r.Address)" }
        if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
            $out.Success = $true; $out.IsDestination = $true; $out.RoundtripMs = [int]$r.RoundtripTime
        }
        elseif ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::TtlExpired -or
                $r.Status -eq [System.Net.NetworkInformation.IPStatus]::TimeExceeded) {
            $out.Success = $true
            # routers that expire a TTL usually report RoundtripTime 0
            $rt = [int]$r.RoundtripTime
            if ($rt -le 0) { $rt = [int]$sw.ElapsedMilliseconds }
            $out.RoundtripMs = $rt
        }
        if ($ResolveNames -and $out.Address) {
            $out.HostName = Invoke-DxSafe {
                $e = [System.Net.Dns]::GetHostEntry($out.Address)
                if ($e -and $e.HostName -and $e.HostName -ne $out.Address) { $e.HostName } else { '' }
            } ''
        }
    }
    catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
        $out.Error = $m; $out.Status = 'Error'
    }
    finally { if ($p) { Invoke-DxSafe { $p.Dispose() } } }
    return $out
}

function Invoke-DxLookup {
    param([Parameter(Mandatory)][string]$Name, [string]$Type = 'A', [string]$Server = '', [switch]$NoHostsFile)
    $result = [pscustomobject]@{ Name=$Name; Type=$Type; Server=$Server; Success=$false; Records=@(); Ms=0; Error=''; Raw='' }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $splat = @{ Name = $Name; ErrorAction = 'Stop' }
        if ($Type -and $Type -ne 'ALL') { $splat['Type'] = $Type }
        if ($Server) { $splat['Server'] = $Server }
        if ($NoHostsFile) { $splat['DnsOnly'] = $true; $splat['NoHostsFile'] = $true }
        $recs = Resolve-DnsName @splat
        $sw.Stop(); $result.Ms = [int]$sw.ElapsedMilliseconds
        $rows = New-Object System.Collections.ArrayList
        foreach ($r in @($recs)) {
            $data = ''
            foreach ($prop in @('IPAddress','NameHost','NameExchange','Text','PrimaryServer','Strings','IP6Address')) {
                if ($null -ne $r.PSObject.Properties[$prop] -and $r.$prop) { $data = ((@($r.$prop)) -join ' '); break }
            }
            if (-not $data) { $data = "$($r.Type)" }
            $null = $rows.Add([pscustomobject]@{ Name=$r.Name; Type="$($r.Type)"; TTL=$r.TTL; Data=$data; Section="$($r.Section)" })
        }
        $result.Records = @($rows.ToArray())
        $result.Success = ($rows.Count -gt 0)
        if (-not $result.Success) { $result.Error = 'Query returned no records.' }
    }
    catch {
        $sw.Stop(); $result.Ms = [int]$sw.ElapsedMilliseconds
        $result.Error = $_.Exception.Message
        # .NET fallback (adapter DNS only, address types only)
        if (-not $Server -and $Type -in @('A','AAAA','ALL')) {
            $net = Invoke-DxSafe { [System.Net.Dns]::GetHostAddresses($Name) }
            if ($net) {
                $rows = New-Object System.Collections.ArrayList
                foreach ($a in @($net)) {
                    $fam = "$($a.AddressFamily)"
                    if ($Type -eq 'A' -and $fam -ne 'InterNetwork') { continue }
                    if ($Type -eq 'AAAA' -and $fam -ne 'InterNetworkV6') { continue }
                    $null = $rows.Add([pscustomobject]@{
                        Name=$Name; Type=if($fam -eq 'InterNetworkV6'){'AAAA'}else{'A'}
                        TTL=''; Data=$a.IPAddressToString; Section='Answer (.NET)'
                    })
                }
                if ($rows.Count -gt 0) {
                    $result.Records = @($rows.ToArray()); $result.Success = $true
                    $result.Error = ''; $result.Server = 'adapter DNS (.NET fallback)'
                    return $result
                }
            }
        }
        $a = "-type=$Type $Name"
        if ($Server) { $a = "$a $Server" }
        $result.Raw = Invoke-DxProcess -FilePath 'nslookup.exe' -Arguments $a -TimeoutSec 20
    }
    return $result
}

$script:DxPortNames = @{
    20='FTP data'; 21='FTP'; 22='SSH / SFTP'; 23='Telnet'; 25='SMTP'; 53='DNS'; 67='DHCP server'
    68='DHCP client'; 69='TFTP'; 80='HTTP'; 88='Kerberos'; 110='POP3'; 111='RPC portmap'; 123='NTP'
    135='RPC endpoint mapper'; 137='NetBIOS name'; 138='NetBIOS datagram'; 139='NetBIOS session'
    143='IMAP'; 161='SNMP'; 389='LDAP'; 443='HTTPS'; 445='SMB'; 464='Kerberos kpasswd'; 465='SMTPS'
    500='IKE / IPsec'; 514='Syslog'; 515='LPD print'; 587='SMTP submission'; 593='RPC over HTTP'
    636='LDAPS'; 993='IMAPS'; 995='POP3S'; 1433='SQL Server'; 1434='SQL Browser'; 1521='Oracle'
    1701='L2TP'; 1723='PPTP'; 1812='RADIUS auth'; 1813='RADIUS acct'; 2049='NFS'; 3128='Squid proxy'
    3268='Global Catalog'; 3269='Global Catalog SSL'; 3306='MySQL'; 3389='RDP'; 5060='SIP'; 5061='SIP TLS'
    5432='PostgreSQL'; 5671='AMQP TLS'; 5672='AMQP'; 5985='WinRM HTTP'; 5986='WinRM HTTPS'; 6379='Redis'
    8000='HTTP alt'; 8080='HTTP proxy'; 8443='HTTPS alt'; 8530='WSUS HTTP'; 8531='WSUS HTTPS'
    9100='Printer raw'; 9389='AD Web Services'; 10123='Teams media'; 27017='MongoDB'; 47001='WinRM listener'
}

function Get-DxPortName {
    param([int]$Port)
    if ($script:DxPortNames.ContainsKey($Port)) { return $script:DxPortNames[$Port] }
    if ($Port -ge 49152) { return 'Dynamic / ephemeral' }
    return ''
}

function Expand-DxPortList {
    <# "443, 80, 5985-5986" -> de-duplicated ordered int list. Never throws. #>
    param([string]$Text, [int]$Max = 256)
    $out = New-Object System.Collections.Generic.List[int]
    if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
    foreach ($part in ($Text -split '[,;\s]+')) {
        if ([string]::IsNullOrWhiteSpace($part)) { continue }
        $p = $part.Trim()
        if ($p -match '^(\d{1,5})\s*-\s*(\d{1,5})$') {
            $a = [int]$matches[1]; $b = [int]$matches[2]
            if ($a -gt $b) { $t = $a; $a = $b; $b = $t }
            for ($i = $a; $i -le $b; $i++) {
                if ($i -ge 1 -and $i -le 65535 -and -not $out.Contains($i)) {
                    $out.Add($i) | Out-Null
                    if ($out.Count -ge $Max) { return $out }
                }
            }
        }
        elseif ($p -match '^\d{1,5}$') {
            $i = [int]$p
            if ($i -ge 1 -and $i -le 65535 -and -not $out.Contains($i)) {
                $out.Add($i) | Out-Null
                if ($out.Count -ge $Max) { return $out }
            }
        }
    }
    return $out
}

function Test-DxPortQuick {
    param([Parameter(Mandatory)][string]$Target, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 2000)
    $ok = $false; $err = ''; $resolved = ''
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $c = $null
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $iar = $c.BeginConnect($Target, $Port, $null, $null)
        if ($iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            try { $c.EndConnect($iar); $ok = $true; $resolved = Invoke-DxSafe { "$($c.Client.RemoteEndPoint.Address)" } '' }
            catch { $err = $_.Exception.Message }
        } else { $err = 'Timed out' }
    }
    catch {
        $m = $_.Exception.Message
        if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
        $err = $m
    }
    finally {
        if ($c) { Invoke-DxSafe { $c.Close() }; Invoke-DxSafe { $c.Dispose() } }
        $sw.Stop()
    }
    if ($err -match 'actively refused') { $err = 'Connection refused (host reachable, nothing listening)' }
    elseif ($err -match 'did not properly respond|timed out') { $err = 'Timed out (filtered or host down)' }
    elseif ($err -match 'No such host is known') { $err = 'Name did not resolve' }
    [pscustomobject]@{
        Target=$Target; Port=$Port; Service=(Get-DxPortName -Port $Port)
        Open=$ok; State=if($ok){'Open'}else{'Closed'}
        Ms=[int]$sw.ElapsedMilliseconds; Address=$resolved; Error=$err
    }
}

# =============================================================================
# region  Certificates
# =============================================================================

function Get-DxCertPurpose {
    param([string]$Issuer, [string]$Subject, [string[]]$Eku, [bool]$SelfSigned, [string]$Store)
    if ($Issuer -match 'Microsoft Intune MDM Device CA') { return 'Intune MDM device' }
    if ($Issuer -match 'MS-Organization-Access')         { return 'Entra ID device join' }
    if ($Issuer -match 'MS-Organization-P2P-Access')     { return 'Entra ID P2P / WHfB' }
    if ($Issuer -match 'Microsoft Intune Imported PFX')  { return 'Intune imported PFX' }
    if ($Issuer -match 'Windows Azure CRP Certificate')  { return 'Azure VM agent' }
    if ($Store -match 'Root|Authority' -and $SelfSigned) { return 'Trusted root CA' }
    if ($Store -match 'Intermediate')                    { return 'Intermediate CA' }
    $e = ($Eku -join '; ')
    if ($e -match 'Smart Card Logon')       { return 'Smart card / WHfB logon' }
    if ($e -match 'Client Authentication')  { return 'Client auth (802.1X / VPN / SCEP)' }
    if ($e -match 'Server Authentication')  { return 'Server auth (TLS)' }
    if ($e -match 'Code Signing')           { return 'Code signing' }
    if ($e -match 'Secure Email')           { return 'S/MIME e-mail' }
    if ($e -match 'Encrypting File System') { return 'EFS' }
    if ($e -match 'Time Stamping')          { return 'Time stamping' }
    if ($SelfSigned)                        { return 'Self-signed' }
    return 'Other'
}

function Get-DxCertificates {
    param([switch]$IncludeCaStores)
    $stores = New-Object System.Collections.ArrayList
    $null = $stores.Add([pscustomobject]@{ Scope='Device'; Path='Cert:\LocalMachine\My'; Store='Personal' })
    $null = $stores.Add([pscustomobject]@{ Scope='User';   Path='Cert:\CurrentUser\My';  Store='Personal' })
    if ($IncludeCaStores) {
        $null = $stores.Add([pscustomobject]@{ Scope='Device'; Path='Cert:\LocalMachine\Root'; Store='Trusted Root' })
        $null = $stores.Add([pscustomobject]@{ Scope='Device'; Path='Cert:\LocalMachine\CA';   Store='Intermediate CA' })
        $null = $stores.Add([pscustomobject]@{ Scope='User';   Path='Cert:\CurrentUser\Root';  Store='Trusted Root' })
        $null = $stores.Add([pscustomobject]@{ Scope='User';   Path='Cert:\CurrentUser\CA';    Store='Intermediate CA' })
    }
    $now = Get-Date
    $out = New-Object System.Collections.ArrayList
    foreach ($s in $stores) {
        $certs = Invoke-DxSafe { Get-ChildItem -Path $s.Path -ErrorAction Stop } @()
        foreach ($c in $certs) {
            if (-not $c.Thumbprint) { continue }
            $eku = @()
            Invoke-DxSafe {
                foreach ($x in $c.Extensions) {
                    if ($x -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
                        foreach ($o in $x.EnhancedKeyUsages) {
                            $n = $o.FriendlyName; if (-not $n) { $n = $o.Value }
                            $eku += $n
                        }
                    }
                }
            }
            $template = Invoke-DxSafe {
                foreach ($x in $c.Extensions) {
                    if ($x.Oid.Value -eq '1.3.6.1.4.1.311.21.7' -or $x.Oid.Value -eq '1.3.6.1.4.1.311.20.2') {
                        return ($x.Format($false) -replace '\s+',' ').Trim()
                    }
                }
                return ''
            } ''
            $days = [int][math]::Floor(($c.NotAfter - $now).TotalDays)
            $status = 'Valid'
            if ($days -lt 0) { $status = 'Expired' } elseif ($days -lt 15) { $status = 'Critical' } elseif ($days -lt 45) { $status = 'Warning' }
            $selfSigned = ($c.Subject -eq $c.Issuer)
            $keySize = Invoke-DxSafe { $c.PublicKey.Key.KeySize } 0
            if (-not $keySize) { $keySize = Invoke-DxSafe { $c.GetRSAPublicKey().KeySize } 0 }
            $null = $out.Add([pscustomobject]@{
                Scope=$s.Scope; Store=$s.Store
                SubjectCN=(Get-DxCn $c.Subject); IssuerCN=(Get-DxCn $c.Issuer)
                FriendlyName=$c.FriendlyName
                Purpose=(Get-DxCertPurpose -Issuer $c.Issuer -Subject $c.Subject -Eku $eku -SelfSigned $selfSigned -Store $s.Store)
                NotBefore=$c.NotBefore; NotAfter=$c.NotAfter; DaysLeft=$days; Status=$status
                HasKey=$c.HasPrivateKey; KeySize=$keySize
                SigAlg=(Invoke-DxSafe { $c.SignatureAlgorithm.FriendlyName } '')
                Template=$template; Eku=($eku -join ', '); SelfSigned=$selfSigned
                Thumbprint=$c.Thumbprint; Serial=$c.SerialNumber; Subject=$c.Subject; Issuer=$c.Issuer
            })
        }
    }
    return @($out.ToArray() | Sort-Object DaysLeft)
}

function Get-DxCertFindings {
    param([object[]]$Certs)
    $issues = New-Object System.Collections.ArrayList
    if (-not $Certs -or @($Certs).Count -eq 0) {
        $null = $issues.Add('No certificates were read. Run elevated to enumerate the LocalMachine store.')
        return @($issues.ToArray())
    }
    $personal = @($Certs | Where-Object { $_.Store -eq 'Personal' })
    foreach ($c in @($personal | Where-Object { $_.Status -eq 'Expired' })) {
        $null = $issues.Add("EXPIRED ($($c.Scope)): '$($c.SubjectCN)' [$($c.Purpose)] expired $([math]::Abs($c.DaysLeft)) day(s) ago on $($c.NotAfter.ToString('dd MMM yyyy')).")
    }
    foreach ($c in @($personal | Where-Object { $_.Status -eq 'Critical' })) {
        $null = $issues.Add("EXPIRES IN $($c.DaysLeft) DAY(S) ($($c.Scope)): '$($c.SubjectCN)' [$($c.Purpose)] - renew now.")
    }
    foreach ($c in @($personal | Where-Object { $_.Status -eq 'Warning' })) {
        $null = $issues.Add("Expires in $($c.DaysLeft) days ($($c.Scope)): '$($c.SubjectCN)' [$($c.Purpose)].")
    }
    if (@($personal | Where-Object { $_.Purpose -eq 'Intune MDM device' }).Count -eq 0) {
        $null = $issues.Add('No Intune MDM device certificate in LocalMachine\My - the device cannot authenticate to the MDM channel (expected if not Intune enrolled).')
    }
    if (@($personal | Where-Object { $_.Purpose -eq 'Entra ID device join' }).Count -eq 0) {
        $null = $issues.Add('No Entra ID device-join certificate (MS-Organization-Access) - the device is not Entra joined or registered.')
    }
    $noKey = @($personal | Where-Object { -not $_.HasKey -and $_.Status -ne 'Expired' })
    if ($noKey.Count -gt 0) { $null = $issues.Add("$($noKey.Count) personal certificate(s) have no private key - they cannot be used for authentication or signing.") }
    $weak = @($personal | Where-Object { $_.KeySize -gt 0 -and $_.KeySize -lt 2048 -and $_.SigAlg -notmatch 'ecdsa' })
    if ($weak.Count -gt 0) { $null = $issues.Add("$($weak.Count) certificate(s) use an RSA key smaller than 2048 bits - below current policy baselines.") }
    $sha1 = @($personal | Where-Object { $_.SigAlg -match 'sha1' })
    if ($sha1.Count -gt 0) { $null = $issues.Add("$($sha1.Count) certificate(s) are signed with SHA-1 - deprecated and rejected by modern services.") }
    if ($issues.Count -eq 0) { $null = $issues.Add('No certificate problems detected. All personal certificates are valid for more than 45 days.') }
    return @($issues.ToArray())
}

function Get-DxCertSummary {
    param([object[]]$Certs)
    $c = @($Certs)
    $expired  = @($c | Where-Object { $_.Status -eq 'Expired' }).Count
    $critical = @($c | Where-Object { $_.Status -eq 'Critical' }).Count
    $warning  = @($c | Where-Object { $_.Status -eq 'Warning' }).Count
    $valid    = @($c | Where-Object { $_.Status -eq 'Valid' }).Count
    $statusChart = @(
        [pscustomobject]@{ Label='Expired';       Value=$expired;  Color='#DC2626' },
        [pscustomobject]@{ Label='Under 15 days'; Value=$critical; Color='#F97316' },
        [pscustomobject]@{ Label='Under 45 days'; Value=$warning;  Color='#F59E0B' },
        [pscustomobject]@{ Label='Valid';         Value=$valid;    Color='#059669' }
    )
    $palette = @('#4F46E5','#0EA5E9','#7C3AED','#059669','#D97706','#DB2777','#0891B2','#65A30D')
    $i = 0
    $purposeChart = $c | Group-Object Purpose | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object {
        $col = $palette[$i % $palette.Count]; $i++
        $nm = $_.Name; if ($nm.Length -gt 30) { $nm = $nm.Substring(0,28) + '..' }
        [pscustomobject]@{ Label=$nm; Value=$_.Count; Color=$col }
    }
    [pscustomobject]@{
        Total=$c.Count
        Device=@($c | Where-Object { $_.Scope -eq 'Device' }).Count
        User=@($c | Where-Object { $_.Scope -eq 'User' }).Count
        Expired=$expired; Critical=$critical; Warning=$warning; Valid=$valid
        StatusChart=$statusChart; PurposeChart=@($purposeChart)
    }
}

# =============================================================================
# region  Intune / MDM
# =============================================================================

function Get-DxDsRegStatus {
    $txt = Invoke-DxProcess -FilePath "$env:SystemRoot\System32\dsregcmd.exe" -Arguments '/status' -TimeoutSec 60
    $map = @{}
    foreach ($line in ($txt -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z0-9_ \-\.]+?)\s*:\s*(.+?)\s*$') {
            $k = $matches[1].Trim()
            if (-not $map.ContainsKey($k)) { $map[$k] = $matches[2].Trim() }
        }
    }
    [pscustomobject]@{
        Raw=$txt; AzureAdJoined=$map['AzureAdJoined']; EnterpriseJoined=$map['EnterpriseJoined']
        DomainJoined=$map['DomainJoined']; DeviceId=$map['DeviceId']; TenantName=$map['TenantName']
        TenantId=$map['TenantId']; MdmUrl=$map['MdmUrl']; MdmComplianceUrl=$map['MdmComplianceUrl']
        AzureAdPrt=$map['AzureAdPrt']; IdpDomain=$map['IdpDomain']; Map=$map
    }
}

function Get-DxIntuneScriptState {
    <#
      Platform PowerShell scripts:
        HKLM\...\IntuneManagementExtension\Policies\<UserSID>\<PolicyGUID>
      Remediations (proactive remediations / health scripts):
        HKLM\...\IntuneManagementExtension\SideCarPolicies\Scripts\Execution\<UserSID>\<ScriptGUID>
    #>
    $sectionErrors = New-Object System.Collections.ArrayList
    $scripts       = New-Object System.Collections.ArrayList
    $remediations  = New-Object System.Collections.ArrayList

    $null = Invoke-DxSection -Name 'Intune/PSScripts' -ErrorLog $sectionErrors -Script {
        $base = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Policies'
        if (-not (Test-Path $base)) { return }
        foreach ($sidKey in @(Get-ChildItem $base -ErrorAction Stop)) {
            $acct = Resolve-DxSidName $sidKey.PSChildName
            foreach ($pol in @(Get-ChildItem $sidKey.PSPath -ErrorAction SilentlyContinue)) {
                $res  = Get-DxRegValue -Path $pol.PSPath -Name 'Result'
                $code = Get-DxRegValue -Path $pol.PSPath -Name 'ErrorCode'
                $det  = Get-DxRegValue -Path $pol.PSPath -Name 'ResultDetails'
                $dl   = Get-DxRegValue -Path $pol.PSPath -Name 'DownloadCount'
                $state = 'Unknown'
                if ("$res" -match '(?i)success') { $state = 'Success' } elseif ($res) { $state = 'Failed' }
                if ($null -ne $code -and "$code" -ne '0' -and "$code" -ne '') { $state = 'Failed' }
                $msg = "$det"; if (-not $msg) { $msg = "$res" }
                $null = $scripts.Add([pscustomobject]@{
                    Scope=$acct; ScriptId=$pol.PSChildName; State=$state
                    ErrorCode=if($null -eq $code){''}else{"$code"}
                    Downloads="$dl"; Detail=("$msg" -replace '\s+',' ').Trim()
                })
            }
        }
    }

    $null = Invoke-DxSection -Name 'Intune/Remediations' -ErrorLog $sectionErrors -Script {
        $base = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution'
        if (-not (Test-Path $base)) { return }
        foreach ($sidKey in @(Get-ChildItem $base -ErrorAction Stop)) {
            $acct = Resolve-DxSidName $sidKey.PSChildName
            foreach ($sc in @(Get-ChildItem $sidKey.PSPath -ErrorAction SilentlyContinue)) {
                $res  = Get-DxRegValue -Path $sc.PSPath -Name 'Result'
                $code = Get-DxRegValue -Path $sc.PSPath -Name 'ErrorCode'
                $last = Get-DxRegValue -Path $sc.PSPath -Name 'LastExecution'
                $pre  = Get-DxRegValue -Path $sc.PSPath -Name 'PreRemediationDetectScriptOutput'
                $post = Get-DxRegValue -Path $sc.PSPath -Name 'PostRemediationDetectScriptOutput'
                $rerr = Get-DxRegValue -Path $sc.PSPath -Name 'RemediationScriptErrorDetails'
                $cnt  = Get-DxRegValue -Path $sc.PSPath -Name 'ExecutionCount'
                $state = 'Unknown'
                if ($res) {
                    $j = Invoke-DxSafe { $res | ConvertFrom-Json }
                    if ($j -and $j.PSObject.Properties['Result']) { $state = "$($j.Result)" }
                    elseif ("$res" -match '(?i)success') { $state = 'Success' }
                    else { $state = "$res" }
                }
                if ($null -ne $code -and "$code" -ne '0' -and "$code" -ne '') { $state = 'Failed' }
                if ("$state".Length -gt 40) { $state = "$state".Substring(0,40) }
                $detect = "$pre"
                if ($post) { $detect = "pre: $pre | post: $post" }
                if ($rerr) { $detect = "$detect | error: $rerr" }
                $null = $remediations.Add([pscustomobject]@{
                    Scope=$acct; ScriptId=$sc.PSChildName; State=$state
                    ErrorCode=if($null -eq $code){''}else{"$code"}
                    LastRun="$last"; Executions="$cnt"
                    Detail=("$detect" -replace '\s+',' ').Trim()
                })
            }
        }
    }

    $issues = New-Object System.Collections.ArrayList
    $failS = @($scripts.ToArray()      | Where-Object { $_.State -eq 'Failed' })
    $failR = @($remediations.ToArray() | Where-Object { $_.State -match '(?i)fail' -or ($_.ErrorCode -and $_.ErrorCode -ne '0') })
    if ($failS.Count -gt 0) { $null = $issues.Add("$($failS.Count) platform PowerShell script(s) reported a failure - see the Detail column for the error text.") }
    if ($failR.Count -gt 0) { $null = $issues.Add("$($failR.Count) remediation(s) reported a failure. Check the detection output before blaming the remediation script.") }
    if ($scripts.Count -eq 0 -and $remediations.Count -eq 0) {
        $null = $issues.Add('No platform scripts or remediations are assigned to this device (the IME registry keys are absent). This is a correct result, not a collection failure.')
    }

    [pscustomobject]@{
        Scripts=@($scripts.ToArray()); Remediations=@($remediations.ToArray())
        Issues=@($issues.ToArray()); SectionErrors=@($sectionErrors.ToArray())
    }
}

function Get-DxIntuneState {
    $sectionErrors = New-Object System.Collections.ArrayList

    $enrollments = @(Invoke-DxSection -Name 'Intune/Enrollments' -Default @() -ErrorLog $sectionErrors -Script {
        $o = New-Object System.Collections.ArrayList
        foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop)) {
            $state = Get-DxRegValue -Path $k.PSPath -Name 'EnrollmentState'
            $prov  = Get-DxRegValue -Path $k.PSPath -Name 'ProviderID'
            if ($state -or $prov) {
                $null = $o.Add([pscustomobject]@{
                    EnrollmentId=$k.PSChildName; ProviderID=$prov; EnrollmentState=$state
                    EnrollmentType=Get-DxRegValue -Path $k.PSPath -Name 'EnrollmentType'
                    UPN=Get-DxRegValue -Path $k.PSPath -Name 'UPN'
                    DiscoveryUrl=Get-DxRegValue -Path $k.PSPath -Name 'DiscoveryServiceFullURL'
                })
            }
        }
        ,@($o.ToArray())
    })
    $active = @($enrollments | Where-Object { $_.ProviderID -eq 'MS DM Server' -and $_.EnrollmentState -eq 1 }) | Select-Object -First 1

    $cert = Invoke-DxSection -Name 'Intune/Cert' -ErrorLog $sectionErrors -Script {
        Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
            Where-Object { $_.Issuer -match 'Microsoft Intune MDM Device CA' } |
            Sort-Object NotAfter -Descending | Select-Object -First 1
    }
    $ime = Invoke-DxSection -Name 'Intune/Service' -ErrorLog $sectionErrors -Script { Get-Service -Name 'IntuneManagementExtension' -ErrorAction Stop }
    $imeVer = Invoke-DxSafe { (Get-Item 'C:\Program Files (x86)\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe' -ErrorAction Stop).VersionInfo.ProductVersion }

    $tasks = @(Invoke-DxSection -Name 'Intune/Tasks' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction Stop | ForEach-Object {
            $info = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            [pscustomobject]@{
                TaskName=$_.TaskName; State="$($_.State)"; LastRunTime=$info.LastRunTime
                LastResult=$info.LastTaskResult; NextRunTime=$info.NextRunTime
            }
        })
    })

    # --- Win32 apps: isolated, with decoded enforcement state ---------------
    $apps = New-Object System.Collections.ArrayList
    $w32Base = 'HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Win32Apps'
    $null = Invoke-DxSection -Name 'Intune/Win32Apps' -ErrorLog $sectionErrors -Script {
        if (-not (Test-Path $w32Base)) { return }
        foreach ($sidKey in @(Get-ChildItem $w32Base -ErrorAction Stop)) {
            $scope = Resolve-DxSidName $sidKey.PSChildName
            foreach ($appKey in @(Get-ChildItem $sidKey.PSPath -ErrorAction SilentlyContinue)) {
                if ($appKey.PSChildName -match '^(GRS|Reporting|_ActiveUsers)$') { continue }
                # Enumerate instead of asking for one name. The v4.5 build
                # read 'EnforcementStateMessage' directly and every column came
                # back blank with no error - a named read cannot distinguish
                # "wrong name" from "no value". ValueNames carries whatever is
                # actually on the key so a future layout change is visible in
                # the grid rather than silent.
                $map = Get-DxRegValueMap -Path $appKey.PSPath
                if (@($map.Keys).Count -eq 0) {
                    foreach ($sub in @(Get-ChildItem $appKey.PSPath -ErrorAction SilentlyContinue)) {
                        $m2 = Get-DxRegValueMap -Path $sub.PSPath
                        if (@($m2.Keys).Count -gt 0) { $map = $m2; break }
                    }
                }
                $esm = Get-DxRegValueAny -Map $map -Names @(
                    'EnforcementStateMessage','EnforcementState','ComplianceStateMessage','ResultDetails')
                $code = $null; $state = $null; $target = ''
                if ($esm) {
                    $j = Invoke-DxSafe { $esm | ConvertFrom-Json }
                    if ($j) {
                        $state  = $j.EnforcementState
                        if ($null -eq $state) { $state = $j.ComplianceState }
                        $code   = $j.ErrorCode
                        $target = "$($j.TargetingMethod)"
                    } elseif ("$esm" -match '^\d+$') {
                        # some builds store the bare numeric state, not JSON
                        $state = "$esm"
                    }
                }
                if ($null -eq $state) { $state = Get-DxRegValueAny -Map $map -Names @('EnforcementState','Status') }
                if ($null -eq $code)  { $code  = Get-DxRegValueAny -Map $map -Names @('ErrorCode','LastError') }
                $stateText = switch ("$state") {
                    '1000' { 'Success' }                    '1001' { 'Success (reboot pending)' }
                    '1002' { 'Success (reboot required)' }  '1003' { 'Success (soft reboot)' }
                    '2000' { 'In progress' }                '2001' { 'Downloading' }
                    '2002' { 'Installing' }                 '2003' { 'Pending reboot' }
                    '3000' { 'Requirements not met' }       '4000' { 'FAILED' }
                    '5000' { 'FAILED (install)' }           '5001' { 'FAILED (download)' }
                    '5002' { 'FAILED (detection)' }         '5003' { 'FAILED (content)' }
                    '5999' { 'FAILED (generic)' }
                    default { if ("$state") { "State $state" } else { '' } }
                }
                $complete = Get-DxRegValueAny -Map $map -Names @('Complete','IsComplete')
                $null = $apps.Add([pscustomobject]@{
                    Scope=$scope; AppId=$appKey.PSChildName; State=$stateText; RawState="$state"
                    ErrorCode=$(if($null -eq $code){''}else{"$code"})
                    Targeting=$target; Complete="$complete"
                    ValueNames=((@($map.Keys) | Select-Object -First 8) -join ', ')
                })
            }
        }
    }
    if ($apps.Count -eq 0) {
        if (Test-Path $w32Base) {
            $null = Add-DxError -Log $sectionErrors -Message '[Intune/Win32Apps] The Win32Apps registry key exists but contains no application entries - no Win32 apps are assigned to this device or user.'
        } else {
            $null = Add-DxError -Log $sectionErrors -Message '[Intune/Win32Apps] The IME Win32Apps registry key does not exist. No Win32 apps have ever been assigned, or the Intune Management Extension is not installed.'
        }
    }

    $policyAreas = @(Invoke-DxSection -Name 'Intune/PolicyAreas' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction Stop | Select-Object -ExpandProperty PSChildName)
    })

    $mdmLog = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $mdmEvents = @(Invoke-DxSection -Name 'Intune/MdmEvents' -Default @() -ErrorLog $sectionErrors -Script {
        Get-DxEvents -LogNames @($mdmLog) -Levels @(1,2,3) -Hours 336 -MaxPerLog 500
    })
    $enrollEvents = @(Invoke-DxSection -Name 'Intune/EnrollEvents' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-WinEvent -FilterHashtable @{ LogName=$mdmLog; Id=@(75,76) } -MaxEvents 20 -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Time=$_.TimeCreated; Id=$_.Id
                Result=if($_.Id -eq 75){'Auto MDM enroll SUCCEEDED'}else{'Auto MDM enroll FAILED'}
                Message=($_.Message -replace '\s+',' ').Trim()
            }
        })
    })

    $dsreg = Get-DxDsRegStatus

    $scriptState = Invoke-DxSection -Name 'Intune/ScriptState' -ErrorLog $sectionErrors -Script { Get-DxIntuneScriptState }
    if (-not $scriptState) { $scriptState = [pscustomobject]@{ Scripts=@(); Remediations=@(); Issues=@(); SectionErrors=@() } }
    foreach ($e in @($scriptState.SectionErrors)) { $null = Add-DxError -Log $sectionErrors -Message $e }

    $issues = New-Object System.Collections.ArrayList
    if ($dsreg.AzureAdJoined -ne 'YES' -and $dsreg.EnterpriseJoined -ne 'YES') { $null = $issues.Add('Device is not Microsoft Entra joined or registered - MDM enrollment cannot complete.') }
    if ($dsreg.AzureAdPrt -eq 'NO') { $null = $issues.Add('No Microsoft Entra PRT - SSO, Conditional Access and silent enrollment will fail. Have the user sign out and back in.') }
    if (-not $active) { $null = $issues.Add('No active "MS DM Server" enrollment (EnrollmentState=1). Device is not MDM enrolled.') }
    if (-not $dsreg.MdmUrl) { $null = $issues.Add('MdmUrl is empty in dsregcmd /status - auto-enrollment policy or MDM scope is not reaching the device.') }
    if ($cert -and $cert.NotAfter -lt (Get-Date).AddDays(30)) { $null = $issues.Add("Intune MDM device certificate expires $($cert.NotAfter) - renewal happens on sync.") }
    if (-not $cert) { $null = $issues.Add('No "Microsoft Intune MDM Device CA" certificate in LocalMachine\My.') }
    if ($ime -and $ime.Status -ne 'Running') { $null = $issues.Add("Intune Management Extension service is '$($ime.Status)' - Win32 apps, scripts and remediations will not run.") }
    foreach ($t in $tasks) {
        if ($null -ne $t.LastResult -and $t.LastResult -ne 0) { $null = $issues.Add(("MDM scheduled task '{0}' last result = 0x{1:X8}" -f $t.TaskName, $t.LastResult)) }
    }
    $failedApps = @($apps.ToArray() | Where-Object { $_.ErrorCode -and $_.ErrorCode -ne '0' -and $_.ErrorCode -ne '' })
    if ($failedApps.Count -gt 0) { $null = $issues.Add("$($failedApps.Count) Win32 app(s) report a non-zero enforcement error code.") }
    $lastFail = @($enrollEvents | Where-Object { $_.Id -eq 76 }) | Select-Object -First 1
    if ($lastFail) { $null = $issues.Add("Event ID 76 (Auto MDM Enroll: Failed) logged $($lastFail.Time).") }
    foreach ($i in @($scriptState.Issues)) { $null = $issues.Add($i) }
    foreach ($e in @($sectionErrors.ToArray())) { $null = $issues.Add("SECTION ERROR $e") }

    [pscustomobject]@{
        DsReg=$dsreg; Enrollments=@($enrollments); ActiveEnrollment=$active; Certificate=$cert
        ImeService=$ime; ImeVersion=$imeVer; Tasks=@($tasks); Win32Apps=@($apps.ToArray())
        Scripts=@($scriptState.Scripts); Remediations=@($scriptState.Remediations)
        PolicyAreas=@($policyAreas); MdmEvents=@($mdmEvents); EnrollEvents=@($enrollEvents)
        Issues=@($issues.ToArray()); SectionErrors=@($sectionErrors.ToArray())
        LogFolder="$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    }
}

function Get-DxIntuneLogFindings {
    param([int]$MaxLines = 4000, [int]$Top = 200)
    $folder = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs"
    $out = New-Object System.Collections.ArrayList
    if (-not (Test-Path $folder)) { return @() }
    $files = Get-ChildItem $folder -Filter '*.log' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 8
    foreach ($f in $files) {
        $lines = Invoke-DxSafe { Get-Content $f.FullName -Tail $MaxLines -ErrorAction Stop } @()
        foreach ($line in $lines) {
            if ($line -notmatch 'type="(2|3)"') {
                if ($line -notmatch '(?i)\b(error|failed|exception|denied|0x8[0-9A-F]{7})\b') { continue }
            }
            $text = $line
            if ($line -match '\<\!\[LOG\[(?<m>.*?)\]LOG\]') { $text = $matches['m'] }
            $time = $null
            if ($line -match 'time="(?<t>[^"]+)".*?date="(?<d>[^"]+)"') {
                $time = Invoke-DxSafe { [datetime]::Parse("$($matches['d']) $(($matches['t'] -split '\.')[0])") }
            }
            $sev = 'Warning'
            if ($line -match 'type="3"' -or $text -match '(?i)error|failed|exception') { $sev = 'Error' }
            $null = $out.Add([pscustomobject]@{ Time=$time; Severity=$sev; LogFile=$f.Name; Message=($text -replace '\s+',' ').Trim() })
        }
    }
    return @($out.ToArray() | Sort-Object Time -Descending | Select-Object -First $Top)
}

function Invoke-DxIntuneSync {
    $t = Invoke-DxSafe {
        Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\*' -ErrorAction Stop |
            Where-Object { $_.TaskName -like 'PushLaunch*' -or $_.TaskName -like 'Schedule #3*' -or $_.TaskName -like 'Schedule to run OMADMClient*' }
    }
    if (-not $t) { return 'No EnterpriseMgmt sync task found - the device is probably not MDM enrolled.' }
    foreach ($task in $t) { Invoke-DxSafe { Start-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName } }
    return "Triggered $(@($t).Count) MDM sync task(s). Allow 5-10 minutes, then re-run the Intune tab."
}

function Invoke-DxMdmDiagReport {
    param([string]$OutputFolder = $script:DxWork)
    $zip = Join-Path $OutputFolder ("MDMDiagReport-{0}.zip" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $a = '-area "DeviceEnrollment;DeviceProvisioning;Autopilot" -zip "{0}"' -f $zip
    $res = Invoke-DxProcess -FilePath "$env:SystemRoot\System32\mdmdiagnosticstool.exe" -Arguments $a -TimeoutSec 300
    [pscustomobject]@{ ZipPath=$zip; Output=$res }
}

# =============================================================================
# region  Group Policy
# =============================================================================

function Get-DxGpoState {
    $sectionErrors = New-Object System.Collections.ArrayList
    $xmlPath = Join-Path $script:DxWork ("gpresult-{0}.xml" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $out = [ordered]@{}

    $rText = Invoke-DxProcess -FilePath 'gpresult.exe' -Arguments '/r /scope:computer' -TimeoutSec 180
    $xText = Invoke-DxProcess -FilePath 'gpresult.exe' -Arguments ('/x "{0}" /f' -f $xmlPath) -TimeoutSec 240

    # gpresult writes errors to stdout and still exits 0, so inspect the text
    if ("$rText" -match '(?i)does not have RSOP data|access is denied|ERROR:') {
        $bad = (("$rText" -split "`r?`n") | Where-Object { $_ -match '(?i)error|denied|N/A' } | Select-Object -First 2) -join ' | '
        $null = Add-DxError -Log $sectionErrors -Message "[GPO/gpresult] $bad"
    }
    if (-not (Test-Path $xmlPath)) {
        $bad = (("$xText" -split "`r?`n") | Where-Object { $_ } | Select-Object -First 2) -join ' | '
        $null = Add-DxError -Log $sectionErrors -Message "[GPO/xml] gpresult produced no XML at $xmlPath. Output: $bad"
    }

    $out['RsopXmlPath'] = $xmlPath
    $out['SummaryText'] = $rText
    $out['IsDomainJoined'] = (Invoke-DxSafe { (Get-CimInstance Win32_ComputerSystem).PartOfDomain } $false)

    $applied=New-Object System.Collections.ArrayList
    $denied=New-Object System.Collections.ArrayList
    $cse=New-Object System.Collections.ArrayList
    $settings=New-Object System.Collections.ArrayList
    $conflicts=New-Object System.Collections.ArrayList

    $null = Invoke-DxSection -Name 'GPO/Parse' -ErrorLog $sectionErrors -Script {
        if (-not (Test-Path $xmlPath)) { return }
        $xml = $null
        try { $xml = [xml](Get-Content $xmlPath -Raw -Encoding UTF8 -ErrorAction Stop) }
        catch { $null = Add-DxError -Log $sectionErrors -Message "[GPO/parse] $($_.Exception.GetType().Name): $($_.Exception.Message)"; return }
        if (-not $xml) { $null = Add-DxError -Log $sectionErrors -Message '[GPO/parse] The RSoP XML could not be loaded.'; return }

        foreach ($scopeName in @('ComputerResults','UserResults')) {
            $scopeNode = $xml.Rsop.$scopeName
            if (-not $scopeNode) { continue }
            $scopeLabel = if ($scopeName -eq 'ComputerResults') { 'Computer' } else { 'User' }

            foreach ($g in @($scopeNode.GPO)) {
                if (-not $g) { continue }
                $linkPath=''; $enforced='false'; $order=0
                if ($g.Link) {
                    $l = @($g.Link)[0]
                    $linkPath = $l.SOMPath; $enforced = $l.Enforced; $order = [int]($l.AppliedOrder)
                }
                $rec = [pscustomobject]@{
                    Scope=$scopeLabel; Name="$($g.Name)"
                    Id=(Invoke-DxSafe { if ($g.Path.Identifier -is [string]) { $g.Path.Identifier } else { $g.Path.Identifier.'#text' } } '')
                    Enabled="$($g.Enabled)"; AccessDenied="$($g.AccessDenied)"; FilterAllowed="$($g.FilterAllowed)"
                    IsValid="$($g.IsValid)"; SecurityFilter=((@($g.SecurityFilter)) -join ', ')
                    Link=$linkPath; Enforced=$enforced; Order=$order
                    VersionDir=$g.VersionDirectory; VersionSys=$g.VersionSysvol
                }
                if ($g.FilterAllowed -eq 'false' -or $g.AccessDenied -eq 'true' -or $g.Enabled -eq 'false') { $null = $denied.Add($rec) }
                else { $null = $applied.Add($rec) }

                foreach ($x in @($g.ExtensionStatus)) {
                    if (-not $x) { continue }
                    $null = $cse.Add([pscustomobject]@{
                        Scope=$scopeLabel; GPO="$($g.Name)"; Extension="$($x.Name)"; Status="$($x.Status)"
                        BeginTime=$x.BeginTime; EndTime=$x.EndTime; Error=$x.Error
                    })
                }
                if ($null -ne $g.VersionDirectory -and $null -ne $g.VersionSysvol -and $g.VersionDirectory -ne $g.VersionSysvol) {
                    $null = $conflicts.Add([pscustomobject]@{
                        Type='Version mismatch'; Severity='Error'; Scope=$scopeLabel; Subject="$($g.Name)"
                        Detail="AD version ($($g.VersionDirectory)) does not match SYSVOL version ($($g.VersionSysvol)) - SYSVOL/DFSR replication problem."
                        Winner=''
                    })
                }
            }

            foreach ($p in $scopeNode.SelectNodes('.//*[local-name()="Policy"]')) {
                $gpoName=''; $name=''; $state=''; $cat=''
                $t = $p.SelectSingleNode('./*[local-name()="GPO"]/*[local-name()="Name"]'); if ($t) { $gpoName = $t.InnerText }
                $t = $p.SelectSingleNode('./*[local-name()="Name"]');     if ($t) { $name  = $t.InnerText }
                $t = $p.SelectSingleNode('./*[local-name()="State"]');    if ($t) { $state = $t.InnerText }
                $t = $p.SelectSingleNode('./*[local-name()="Category"]'); if ($t) { $cat   = $t.InnerText }
                $regNodes = $p.SelectNodes('.//*[local-name()="RegistrySetting"]')
                if ($regNodes.Count -eq 0) {
                    $null = $settings.Add([pscustomobject]@{
                        Scope=$scopeLabel; Category=$cat; Setting=$name; State=$state
                        KeyName=''; ValueName=''; Value=''; GPO=$gpoName
                    })
                }
                foreach ($r in $regNodes) {
                    $kn=''; $vn=''; $vv=''
                    $t = $r.SelectSingleNode('./*[local-name()="KeyName"]');   if ($t) { $kn = $t.InnerText }
                    $t = $r.SelectSingleNode('./*[local-name()="ValueName"]'); if ($t) { $vn = $t.InnerText }
                    $t = $r.SelectSingleNode('.//*[local-name()="Number" or local-name()="String"]'); if ($t) { $vv = $t.InnerText }
                    $null = $settings.Add([pscustomobject]@{
                        Scope=$scopeLabel; Category=$cat; Setting=$name; State=$state
                        KeyName=$kn; ValueName=$vn; Value=$vv; GPO=$gpoName
                    })
                }
            }
        }
    }

    $null = Invoke-DxSection -Name 'GPO/Conflicts' -ErrorLog $sectionErrors -Script {
        $sArr = @($settings.ToArray())
        foreach ($grp in ($sArr | Where-Object { $_.KeyName } | Group-Object -Property { "$($_.Scope)|$($_.KeyName)|$($_.ValueName)" })) {
            $gpos = @($grp.Group | Select-Object -ExpandProperty GPO -Unique | Where-Object { $_ })
            $vals = @($grp.Group | Select-Object -ExpandProperty Value -Unique)
            if ($gpos.Count -gt 1) {
                $first = $grp.Group[0]
                $winner = @($applied.ToArray() | Where-Object { $_.Name -in $gpos } | Sort-Object Order -Descending) | Select-Object -First 1
                $null = $conflicts.Add([pscustomobject]@{
                    Type='Duplicate setting'; Severity=if($vals.Count -gt 1){'Error'}else{'Warning'}
                    Scope=$first.Scope; Subject="$($first.Setting) [$($first.KeyName)\$($first.ValueName)]"
                    Detail="Delivered by $($gpos.Count) GPOs: $($gpos -join ' | '). Values seen: $($vals -join ' , ')."
                    Winner=$winner.Name
                })
            }
        }
        foreach ($grp in ($sArr | Where-Object { $_.Setting } | Group-Object -Property { "$($_.Scope)|$($_.Category)|$($_.Setting)" })) {
            $gpos = @($grp.Group | Select-Object -ExpandProperty GPO -Unique | Where-Object { $_ })
            $states = @($grp.Group | Select-Object -ExpandProperty State -Unique)
            if ($gpos.Count -gt 1 -and $states.Count -gt 1) {
                $first = $grp.Group[0]
                $null = $conflicts.Add([pscustomobject]@{
                    Type='State conflict'; Severity='Error'; Scope=$first.Scope; Subject=$first.Setting
                    Detail="Configured as $($states -join ' AND ') by: $($gpos -join ' | '). Highest link order or an enforced link wins."
                    Winner=''
                })
            }
        }
        foreach ($g in @($applied.ToArray() | Where-Object { $_.Enforced -eq 'true' })) {
            $null = $conflicts.Add([pscustomobject]@{
                Type='Enforced link'; Severity='Info'; Scope=$g.Scope; Subject=$g.Name
                Detail="Linked as ENFORCED at '$($g.Link)'. Overrides conflicting settings from GPOs closer to the object and ignores Block Inheritance."
                Winner=$g.Name
            })
        }
    }

    $mdmWins = Get-DxRegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -Name 'ControlPolicyConflict'
    $mdmAreas = @(Invoke-DxSafe { Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction Stop | Select-Object -ExpandProperty PSChildName } @())
    if ($mdmAreas.Count -gt 0 -and $applied.Count -gt 0) {
        $verdict = 'Group Policy wins where both configure the same setting (Windows default).'
        if ($mdmWins -eq 1) { $verdict = 'MDMWinsOverGP is ENABLED - Intune (MDM) policy overrides Group Policy for Policy CSP settings.' }
        $null = $conflicts.Add([pscustomobject]@{
            Type='MDM / GPO overlap'; Severity='Warning'; Scope='Computer'
            Subject="$($mdmAreas.Count) Policy CSP areas + $($applied.Count) applied GPOs"
            Detail="$verdict Overlapping areas to review: $((@($mdmAreas) | Select-Object -First 12) -join ', ')."
            Winner=if($mdmWins -eq 1){'Intune (MDM)'}else{'Group Policy'}
        })
    }

    $gpEvents = @(Invoke-DxSection -Name 'GPO/Events' -Default @() -ErrorLog $sectionErrors -Script {
        Get-DxEvents -LogNames @('Microsoft-Windows-GroupPolicy/Operational') -Levels @(1,2,3) -Hours 168 -MaxPerLog 400
    })
    $sysGp = @(Invoke-DxSection -Name 'GPO/SysEvents' -Default @() -ErrorLog $sectionErrors -Script {
        @(Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-GroupPolicy'; Level=@(1,2,3); StartTime=(Get-Date).AddDays(-7) } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                TimeCreated=$_.TimeCreated; LogName='System'; Level=$_.LevelDisplayName
                LevelValue=[int]$_.Level; Id=$_.Id; Provider=$_.ProviderName; RecordId=$_.RecordId
                Message=($_.Message -replace '\s+',' ').Trim()
            }
        })
    })

    if ($applied.Count -eq 0 -and $denied.Count -eq 0) {
        $null = Add-DxError -Log $sectionErrors -Message '[GPO] No GPOs were extracted from the RSoP XML. On a cloud-only device with no domain GPOs this is expected and correct.'
    }

    $out['AppliedGpos']=@($applied.ToArray()); $out['DeniedGpos']=@($denied.ToArray())
    $out['Extensions']=@($cse.ToArray()); $out['Settings']=@($settings.ToArray())
    $out['Conflicts']=@($conflicts.ToArray())
    $out['Events']=@(@($gpEvents) + @($sysGp) | Sort-Object TimeCreated -Descending)
    $out['MdmWinsOverGP']=$mdmWins
    $out['SectionErrors']=@($sectionErrors.ToArray())
    $out['RawSummary']=$rText
    return [pscustomobject]$out
}

# =============================================================================
# region  System diagnostics
# =============================================================================

function Get-DxPendingReboot {
    $reasons = New-Object System.Collections.ArrayList
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $null = $reasons.Add('Component Based Servicing (CBS) reboot pending') }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $null = $reasons.Add('Windows Update reboot required') }
    if (Get-DxRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations') { $null = $reasons.Add('Pending file rename operations') }
    $cn1 = Get-DxRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName'
    $cn2 = Get-DxRegValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName'
    if ($cn1 -and $cn2 -and ($cn1 -ne $cn2)) { $null = $reasons.Add('Computer rename pending') }
    [pscustomobject]@{ Pending=($reasons.Count -gt 0); Reasons=@($reasons.ToArray()) }
}

function Get-DxSystemDiagnostics {
    $res = [ordered]@{}
    $res['PhysicalDisks'] = Invoke-DxSafe {
        Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Number=$_.DeviceId; Model=$_.FriendlyName; MediaType=$_.MediaType
                SizeGB=[math]::Round($_.Size/1GB,1); HealthStatus=$_.HealthStatus
                OperationalStatus=($_.OperationalStatus -join ',')
            }
        }
    } @()
    $res['Volumes'] = Invoke-DxSafe {
        Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter } | ForEach-Object {
            $pct = 0
            if ($_.Size -gt 0) { $pct = [math]::Round(($_.SizeRemaining/$_.Size)*100,1) }
            [pscustomobject]@{
                Drive=$_.DriveLetter; Label=$_.FileSystemLabel; FS=$_.FileSystem
                SizeGB=[math]::Round($_.Size/1GB,1); FreeGB=[math]::Round($_.SizeRemaining/1GB,1)
                FreePct=$pct; Health=$_.HealthStatus
            }
        }
    } @()
    $res['ProblemDevices'] = Invoke-DxSafe {
        Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.ConfigManagerErrorCode -ne 0 } | ForEach-Object {
            # capture first: inside a switch, $_ rebinds to the switch input
            $code = $_.ConfigManagerErrorCode
            $meaning = switch ($code) {
                1{'Not configured correctly'} 10{'Cannot start'} 12{'Not enough free resources'}
                14{'Requires a restart to work properly'} 18{'Reinstall the drivers'} 19{'Registry corrupt'}
                22{'Disabled'} 24{'Not present, not working, or missing a driver'} 28{'Drivers not installed'}
                31{'Not working properly - driver load failed'} 37{'Driver returned a failure on initialisation'}
                39{'Driver corrupted or missing'} 43{'Stopped because it reported problems'}
                45{'Not currently connected'} default{"Device Manager error code $code"}
            }
            [pscustomobject]@{ Device=$_.Name; Class=$_.PNPClass; ErrorCode=$code; Meaning=$meaning; DeviceId=$_.DeviceID }
        }
    } @()
    $res['StoppedAutoServices'] = Invoke-DxSafe {
        Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' -and $_.Name -notmatch '^(gupdate|edgeupdate|MapsBroker|dbupdate|CDPUserSvc|OneSyncSvc|WbioSrvc|tiledatamodelsvc|RemoteRegistry)' } |
            ForEach-Object {
                [pscustomobject]@{ Name=$_.Name; DisplayName=$_.DisplayName; State=$_.State; StartMode=$_.StartMode; ExitCode=$_.ExitCode }
            }
    } @()
    $res['BugChecks'] = Invoke-DxSafe {
        Get-WinEvent -FilterHashtable @{ LogName='System'; Id=@(41,1001,6008); StartTime=(Get-Date).AddDays(-30) } -MaxEvents 50 -ErrorAction Stop |
            Where-Object { $_.ProviderName -match 'Kernel-Power|BugCheck|EventLog' } | ForEach-Object {
                [pscustomobject]@{ Time=$_.TimeCreated; Id=$_.Id; Provider=$_.ProviderName; Message=($_.Message -replace '\s+',' ').Trim() }
            }
    } @()
    $res['AppCrashes'] = Invoke-DxSafe {
        Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=@(1000,1002); StartTime=(Get-Date).AddDays(-14) } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
            $app = ''
            if ($_.Properties.Count -gt 0) { $app = $_.Properties[0].Value }
            [pscustomobject]@{
                Time=$_.TimeCreated; Type=if($_.Id -eq 1000){'Crash'}else{'Hang'}; App=$app
                Module=if($_.Properties.Count -gt 3){$_.Properties[3].Value}else{''}
                Message=($_.Message -replace '\s+',' ').Trim()
            }
        }
    } @()
    $res['RecentUpdates'] = Invoke-DxSafe {
        Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 15 |
            ForEach-Object { [pscustomobject]@{ HotFixID=$_.HotFixID; Description=$_.Description; InstalledOn=$_.InstalledOn } }
    } @()
    $res['UpdateErrors'] = Invoke-DxSafe {
        Get-WinEvent -FilterHashtable @{ LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Level=@(1,2,3); StartTime=(Get-Date).AddDays(-30) } -MaxEvents 100 -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{ Time=$_.TimeCreated; Id=$_.Id; Level=$_.LevelDisplayName; Message=($_.Message -replace '\s+',' ').Trim() } }
    } @()
    $res['Connectivity'] = Invoke-DxSafe {
        $targets = @(
            @{ Name='Entra ID';          Host='login.microsoftonline.com' },
            @{ Name='Intune enrollment'; Host='enrollment.manage.microsoft.com' },
            @{ Name='Intune service';    Host='manage.microsoft.com' },
            @{ Name='Windows Update';    Host='windowsupdate.microsoft.com' },
            @{ Name='MS Graph';          Host='graph.microsoft.com' }
        )
        foreach ($t in $targets) {
            $r = Test-DxPortQuick -Target $t.Host -Port 443 -TimeoutMs 3000
            [pscustomobject]@{ Target=$t.Name; Endpoint=$t.Host; Port=443; Reachable=$r.Open }
        }
    } @()
    $res['PendingReboot'] = Get-DxPendingReboot
    $res['TimeSync'] = Invoke-DxProcess -FilePath 'w32tm.exe' -Arguments '/query /status' -TimeoutSec 30
    return [pscustomobject]$res
}

function Get-DxHealthScore {
    param($Snapshot, $EventStats, $Intune, $Gpo, $SysDiag, $Certs, $Firewall, $Dns)
    $score = 100
    $items = New-Object System.Collections.ArrayList
    function Add-Ded { param($L,[string]$A,[int]$P,[string]$R) $null = $L.Add([pscustomobject]@{ Area=$A; Points=$P; Reason=$R }) }

    if ($EventStats) {
        if ($EventStats.Critical -gt 0) { $d=[math]::Min(20,$EventStats.Critical*4); $score-=$d; Add-Ded $items 'Event log' $d "$($EventStats.Critical) critical event(s)" }
        if ($EventStats.Error -gt 20)   { $d=[math]::Min(15,[int]($EventStats.Error/10)); $score-=$d; Add-Ded $items 'Event log' $d "$($EventStats.Error) errors" }
        if ($EventStats.Warning -gt 100){ $score-=5; Add-Ded $items 'Event log' 5 "$($EventStats.Warning) warnings - noisy log" }
    }
    if ($Snapshot) {
        foreach ($d in @($Snapshot.Disks)) {
            if ($d.FreePct -lt 10) { $score-=10; Add-Ded $items 'Storage' 10 "Drive $($d.Drive) has only $($d.FreePct)% free" }
            elseif ($d.FreePct -lt 15) { $score-=5; Add-Ded $items 'Storage' 5 "Drive $($d.Drive) has $($d.FreePct)% free" }
        }
        if ($Snapshot.MemoryUsedPct -gt 90) { $score-=5; Add-Ded $items 'Memory' 5 "Memory utilisation $($Snapshot.MemoryUsedPct)%" }
        if ($Snapshot.UptimeDays -gt 14) { $score-=3; Add-Ded $items 'Uptime' 3 "Up $($Snapshot.UptimeDays) days without a restart" }
        if ($Snapshot.DefenderRTP -eq $false) { $score-=10; Add-Ded $items 'Security' 10 'Defender real-time protection is OFF' }
        if ($Snapshot.BitLockerStatus -eq 'Off') { $score-=5; Add-Ded $items 'Security' 5 'System drive is not BitLocker protected' }
        if ($Snapshot.TpmReady -eq $false) { $score-=5; Add-Ded $items 'Security' 5 'TPM not ready' }
    }
    if ($SysDiag) {
        $pd = @($SysDiag.ProblemDevices).Count
        if ($pd -gt 0) { $d=[math]::Min(10,$pd*2); $score-=$d; Add-Ded $items 'Drivers' $d "$pd device(s) reporting a Device Manager error" }
        if (@($SysDiag.BugChecks).Count -gt 0) { $score-=8; Add-Ded $items 'Stability' 8 "$(@($SysDiag.BugChecks).Count) unexpected shutdown or bugcheck event(s)" }
        if ($SysDiag.PendingReboot -and $SysDiag.PendingReboot.Pending) { $score-=3; Add-Ded $items 'Servicing' 3 'Reboot pending' }
        $unreach = @($SysDiag.Connectivity | Where-Object { -not $_.Reachable })
        if ($unreach.Count -gt 0) { $d=[math]::Min(10,$unreach.Count*3); $score-=$d; Add-Ded $items 'Connectivity' $d "Cannot reach: $(($unreach.Endpoint) -join ', ')" }
    }
    if ($Intune) {
        $n = @($Intune.Issues | Where-Object { $_ -notmatch '^SECTION ERROR' }).Count
        if ($n -gt 0) { $d=[math]::Min(15,$n*4); $score-=$d; Add-Ded $items 'Intune / MDM' $d "$n MDM finding(s)" }
    }
    if ($Gpo) {
        $errs = @($Gpo.Conflicts | Where-Object { $_.Severity -eq 'Error' }).Count
        if ($errs -gt 0) { $d=[math]::Min(12,$errs*3); $score-=$d; Add-Ded $items 'Group Policy' $d "$errs GPO conflict(s) with differing values" }
        $cseFail = @($Gpo.Extensions | Where-Object { $_.Status -and $_.Status -ne 'Success' }).Count
        if ($cseFail -gt 0) { $score-=6; Add-Ded $items 'Group Policy' 6 "$cseFail client-side extension(s) failed" }
    }
    if ($Certs) {
        $personal = @($Certs | Where-Object { $_.Store -eq 'Personal' })
        $exp = @($personal | Where-Object { $_.Status -eq 'Expired' }).Count
        $crit = @($personal | Where-Object { $_.Status -eq 'Critical' }).Count
        if ($exp -gt 0)  { $d=[math]::Min(10,$exp*3); $score-=$d; Add-Ded $items 'Certificates' $d "$exp expired personal certificate(s)" }
        if ($crit -gt 0) { $d=[math]::Min(8,$crit*2); $score-=$d; Add-Ded $items 'Certificates' $d "$crit certificate(s) expire within 15 days" }
    }
    if ($Firewall) {
        $off = @($Firewall.Profiles | Where-Object { -not $_.Enabled })
        if ($off.Count -gt 0) { $d=[math]::Min(15,$off.Count*5); $score-=$d; Add-Ded $items 'Firewall' $d "Firewall disabled on: $(($off.Profile) -join ', ')" }
        $allowIn = @($Firewall.Profiles | Where-Object { $_.DefaultInboundAction -eq 'Allow' })
        if ($allowIn.Count -gt 0) { $d=[math]::Min(10,$allowIn.Count*5); $score-=$d; Add-Ded $items 'Firewall' $d "Default inbound is ALLOW on: $(($allowIn.Profile) -join ', ')" }
        if ($Firewall.Service -and $Firewall.Service.Status -ne 'Running') { $score-=10; Add-Ded $items 'Firewall' 10 'MpsSvc firewall service is not running' }
    }
    if ($Dns) {
        $bad = @($Dns.Reachability | Where-Object { -not $_.Reachable })
        if ($bad.Count -gt 0) { $d=[math]::Min(10,$bad.Count*4); $score-=$d; Add-Ded $items 'DNS' $d "$($bad.Count) configured DNS server(s) unreachable" }
        $unres = @($Dns.Probes | Where-Object { -not $_.Resolved })
        if ($unres.Count -gt 0) { $d=[math]::Min(8,$unres.Count*3); $score-=$d; Add-Ded $items 'DNS' $d "$($unres.Count) test name(s) failed to resolve" }
    }
    if ($score -lt 0) { $score = 0 }
    $grade = 'Critical'
    if ($score -ge 90) { $grade='Healthy' } elseif ($score -ge 75) { $grade='Good' }
    elseif ($score -ge 60) { $grade='Degraded' } elseif ($score -ge 40) { $grade='At risk' }
    [pscustomobject]@{ Score=$score; Grade=$grade; Deductions=@($items.ToArray()) }
}

# =============================================================================
# region  Quick actions
# =============================================================================

function Invoke-DxQuickAction {
    param(
        [ValidateSet('GpupdateForce','IntuneSync','RestartIME','SFC','DISM','FlushDNS','ClearWUCache',
                     'ResetWinsock','RestartSpooler','MdmDiagReport','GpresultHtml','ClearIMECache',
                     'CertPulse','FirewallLogOn','FirewallReset','RegisterDns','ReleaseRenew','ResetIpStack')]
        [string]$Name
    )
    switch ($Name) {
        'GpupdateForce'  { return Invoke-DxProcess -FilePath 'gpupdate.exe' -Arguments '/force' -TimeoutSec 300 }
        'IntuneSync'     { return Invoke-DxIntuneSync }
        'CertPulse'      { return Invoke-DxProcess -FilePath 'certutil.exe' -Arguments '-pulse' -TimeoutSec 120 }
        'FlushDNS'       { return Invoke-DxProcess -FilePath 'ipconfig.exe' -Arguments '/flushdns' -TimeoutSec 60 }
        'RegisterDns'    { return Invoke-DxProcess -FilePath 'ipconfig.exe' -Arguments '/registerdns' -TimeoutSec 90 }
        'ReleaseRenew'   {
            $a = Invoke-DxProcess -FilePath 'ipconfig.exe' -Arguments '/release' -TimeoutSec 60
            $b = Invoke-DxProcess -FilePath 'ipconfig.exe' -Arguments '/renew' -TimeoutSec 120
            return "$a`r`n$b"
        }
        'ResetIpStack'   {
            $a = Invoke-DxProcess -FilePath 'netsh.exe' -Arguments 'int ip reset' -TimeoutSec 90
            $b = Invoke-DxProcess -FilePath 'netsh.exe' -Arguments 'winsock reset' -TimeoutSec 90
            return "$a`r`n$b`r`nA restart is required for these resets to take effect."
        }
        'FirewallLogOn'  {
            Invoke-DxSafe { Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogMaxSizeKilobytes 8192 -ErrorAction Stop }
            return "Dropped-packet logging enabled on all profiles.`r`n$(Invoke-DxSafe { Get-NetFirewallProfile | Select-Object Name,LogBlocked,LogFileName | Out-String })"
        }
        'FirewallReset'  { return Invoke-DxProcess -FilePath 'netsh.exe' -Arguments 'advfirewall reset' -TimeoutSec 120 }
        'RestartIME'     {
            Invoke-DxSafe { Restart-Service -Name 'IntuneManagementExtension' -Force -ErrorAction Stop }
            return "IntuneManagementExtension service state: $((Get-Service IntuneManagementExtension).Status)"
        }
        'SFC'            { return Invoke-DxProcess -FilePath 'sfc.exe' -Arguments '/scannow' -TimeoutSec 1800 }
        'DISM'           { return Invoke-DxProcess -FilePath 'dism.exe' -Arguments '/Online /Cleanup-Image /RestoreHealth' -TimeoutSec 3600 }
        'ResetWinsock'   { return Invoke-DxProcess -FilePath 'netsh.exe' -Arguments 'winsock reset' -TimeoutSec 60 }
        'RestartSpooler' {
            Invoke-DxSafe { Restart-Service -Name Spooler -Force -ErrorAction Stop }
            return "Spooler state: $((Get-Service Spooler).Status)"
        }
        'ClearWUCache'   {
            $log = @()
            foreach ($s in @('wuauserv','bits','cryptsvc')) { Invoke-DxSafe { Stop-Service $s -Force -ErrorAction Stop }; $log += "Stopped $s" }
            Invoke-DxSafe { Rename-Item "$env:SystemRoot\SoftwareDistribution" "SoftwareDistribution.old-$(Get-Date -f yyyyMMddHHmmss)" -ErrorAction Stop; $log += 'Renamed SoftwareDistribution' }
            foreach ($s in @('cryptsvc','bits','wuauserv')) { Invoke-DxSafe { Start-Service $s -ErrorAction Stop }; $log += "Started $s" }
            return ($log -join "`r`n")
        }
        'ClearIMECache'  {
            Invoke-DxSafe { Stop-Service IntuneManagementExtension -Force -ErrorAction Stop }
            Invoke-DxSafe { Remove-Item "$env:ProgramData\Microsoft\IntuneManagementExtension\Content\*" -Recurse -Force -ErrorAction Stop }
            Invoke-DxSafe { Start-Service IntuneManagementExtension -ErrorAction Stop }
            return 'IME content cache cleared and service restarted.'
        }
        'MdmDiagReport'  { $r = Invoke-DxMdmDiagReport; return "Report: $($r.ZipPath)`r`n$($r.Output)" }
        'GpresultHtml'   {
            $p = Join-Path $script:DxWork ("gpresult-{0}.html" -f (Get-Date -f 'yyyyMMdd-HHmmss'))
            $o = Invoke-DxProcess -FilePath 'gpresult.exe' -Arguments ('/h "{0}" /f' -f $p) -TimeoutSec 240
            if (Test-Path $p) { Invoke-DxSafe { Start-Process $p } }
            return "HTML RSoP report: $p`r`n$o"
        }
    }
}

# =============================================================================
# region  Reporting
# =============================================================================

function New-DxHtmlReport {
    param(
        [Parameter(Mandatory)]$Snapshot,
        $EventStats, $EventSummary, $Intune, $Gpo, $SysDiag, $Health, $Certs, $Firewall, $Dns,
        [string]$Path
    )
    if (-not $Path) {
        $Path = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("Sysadmin-{0}-{1}.html" -f $env:COMPUTERNAME, (Get-Date -f 'yyyyMMdd-HHmmss'))
    }
    function HE { param($t) if ($null -eq $t) { return '' }; [System.Net.WebUtility]::HtmlEncode([string]$t) }
    function Tbl {
        param($Data, [string[]]$Cols)
        if (-not $Data -or @($Data).Count -eq 0) { return '<p class="none">No records.</p>' }
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append('<table><thead><tr>')
        foreach ($c in $Cols) { [void]$sb.Append("<th>$(HE $c)</th>") }
        [void]$sb.Append('</tr></thead><tbody>')
        foreach ($row in @($Data)) {
            [void]$sb.Append('<tr>')
            foreach ($c in $Cols) {
                $v = $row.$c
                if ($v -is [array]) { $v = $v -join '; ' }
                [void]$sb.Append("<td>$(HE $v)</td>")
            }
            [void]$sb.Append('</tr>')
        }
        [void]$sb.Append('</tbody></table>')
        return $sb.ToString()
    }
    $css = @'
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#F1F5F9;color:#0F172A}
 header{background:linear-gradient(135deg,#0F172A,#1E293B,#312E81);color:#fff;padding:30px 42px}
 header h1{margin:0;font-size:26px;font-weight:600}
 header p{margin:8px 0 0;opacity:.82;font-size:13px}
 main{padding:24px 42px 60px}
 h2{margin:34px 0 12px;font-size:19px;border-left:5px solid #4F46E5;padding-left:11px}
 h3{margin:18px 0 8px;font-size:15px;color:#334155}
 table{border-collapse:collapse;width:100%;background:#fff;font-size:12.5px;box-shadow:0 1px 3px rgba(15,23,42,.08);margin-bottom:14px;border-radius:8px;overflow:hidden}
 th{background:#F1F5F9;text-align:left;padding:9px 11px;border-bottom:2px solid #E2E8F0;font-weight:600}
 td{padding:8px 11px;border-bottom:1px solid #F1F5F9;vertical-align:top}
 .cards{display:flex;flex-wrap:wrap;gap:14px;margin-top:8px}
 .card{background:#fff;border-radius:12px;padding:18px 22px;min-width:150px;flex:1;box-shadow:0 1px 3px rgba(15,23,42,.08)}
 .card .v{font-size:30px;font-weight:700}
 .card .l{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;color:#64748B}
 .crit{color:#B91C1C}.err{color:#DC2626}.warn{color:#D97706}.ok{color:#059669}.info{color:#2563EB}
 .none{color:#64748B;font-style:italic;font-size:13px}
 .kb{background:#fff;border-left:4px solid #4F46E5;padding:14px 18px;margin:10px 0;box-shadow:0 1px 3px rgba(15,23,42,.06);border-radius:0 8px 8px 0}
 .kb h4{margin:0 0 6px;font-size:14px}
 .kb ol{margin:6px 0 6px 18px;padding:0}
 .kb li{margin:3px 0;font-size:12.5px}
 code{background:#0F172A;color:#E2E8F0;padding:3px 7px;border-radius:4px;font-size:11.5px;display:inline-block;margin:2px 0}
 footer{padding:20px 42px;color:#64748B;font-size:11.5px}
</style>
'@
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8"><title>Sys@dmin Report</title>' + $css + '</head><body>')
    [void]$sb.AppendLine("<header><h1>Sys@dmin &mdash; Endpoint Health &amp; Diagnostics Report</h1><p>$(HE $Snapshot.ComputerName) &nbsp;|&nbsp; $(HE $Snapshot.OSName) $(HE $Snapshot.DisplayVersion) (build $(HE $Snapshot.Build)) &nbsp;|&nbsp; Generated $(Get-Date -f 'dd MMM yyyy HH:mm') by $(HE $Snapshot.UserName)</p></header><main>")

    if ($Health) {
        $cls = 'ok'
        if ($Health.Score -lt 60) { $cls='err' } elseif ($Health.Score -lt 80) { $cls='warn' }
        [void]$sb.AppendLine('<h2>Health summary</h2><div class="cards">')
        [void]$sb.AppendLine("<div class='card'><div class='l'>Health score</div><div class='v $cls'>$($Health.Score)</div><div class='l'>$(HE $Health.Grade)</div></div>")
        if ($EventStats) {
            [void]$sb.AppendLine("<div class='card'><div class='l'>Critical</div><div class='v crit'>$($EventStats.Critical)</div></div>")
            [void]$sb.AppendLine("<div class='card'><div class='l'>Errors</div><div class='v err'>$($EventStats.Error)</div></div>")
            [void]$sb.AppendLine("<div class='card'><div class='l'>Warnings</div><div class='v warn'>$($EventStats.Warning)</div></div>")
            [void]$sb.AppendLine("<div class='card'><div class='l'>Information</div><div class='v info'>$($EventStats.Information)</div></div>")
        }
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine('<h3>Score deductions</h3>' + (Tbl $Health.Deductions @('Area','Points','Reason')))
    }

    [void]$sb.AppendLine('<h2>Device</h2>')
    $sysRows = @(
        [pscustomobject]@{ Property='Computer'; Value=$Snapshot.ComputerName },
        [pscustomobject]@{ Property='Model'; Value="$($Snapshot.Manufacturer) $($Snapshot.Model)" },
        [pscustomobject]@{ Property='Serial'; Value=$Snapshot.SerialNumber },
        [pscustomobject]@{ Property='OS'; Value="$($Snapshot.OSName) $($Snapshot.DisplayVersion) ($($Snapshot.Build)) $($Snapshot.Architecture)" },
        [pscustomobject]@{ Property='Domain'; Value=$Snapshot.Domain },
        [pscustomobject]@{ Property='CPU'; Value="$($Snapshot.CPU) - $($Snapshot.Cores) cores / $($Snapshot.LogicalCPUs) logical" },
        [pscustomobject]@{ Property='Memory'; Value="$($Snapshot.MemoryTotalGB) GB total, $($Snapshot.MemoryFreeGB) GB free ($($Snapshot.MemoryUsedPct)% used)" },
        [pscustomobject]@{ Property='Last boot'; Value="$($Snapshot.LastBoot)  (up $($Snapshot.UptimeText))" },
        [pscustomobject]@{ Property='TPM'; Value="Present=$($Snapshot.TpmPresent) Ready=$($Snapshot.TpmReady) Version=$($Snapshot.TpmVersion)" },
        [pscustomobject]@{ Property='Secure Boot'; Value=$Snapshot.SecureBoot },
        [pscustomobject]@{ Property='BitLocker'; Value="$($Snapshot.BitLockerStatus) ($($Snapshot.BitLockerPct)%)" },
        [pscustomobject]@{ Property='Defender RTP'; Value=$Snapshot.DefenderRTP }
    )
    [void]$sb.AppendLine((Tbl $sysRows @('Property','Value')))
    [void]$sb.AppendLine('<h3>Disks</h3>' + (Tbl $Snapshot.Disks @('Drive','Label','SizeGB','FreeGB','FreePct')))

    if ($Firewall) {
        [void]$sb.AppendLine('<h2>Firewall</h2><h3>Findings</h3><ul>')
        foreach ($i in @($Firewall.Issues)) { [void]$sb.AppendLine("<li>$(HE $i)</li>") }
        foreach ($i in @($Firewall.SectionErrors)) { [void]$sb.AppendLine("<li>SECTION ERROR $(HE $i)</li>") }
        [void]$sb.AppendLine('</ul>')
        [void]$sb.AppendLine('<h3>Profiles</h3>' + (Tbl $Firewall.Profiles @('Profile','Status','DefaultInboundAction','DefaultOutboundAction','LogBlocked')))
        [void]$sb.AppendLine('<h3>Active network profiles</h3>' + (Tbl $Firewall.ConnectionProfiles @('Interface','NetworkName','Category','IPv4Connectivity')))
        [void]$sb.AppendLine('<h3>Enabled rules (first 100)</h3>' + (Tbl (@($Firewall.Rules) | Select-Object -First 100) @('DisplayName','Direction','Action','Profile','Protocol','LocalPort','Program')))
    }

    if ($Dns) {
        [void]$sb.AppendLine('<h2>DNS</h2><h3>Findings</h3><ul>')
        foreach ($i in @($Dns.Issues)) { [void]$sb.AppendLine("<li>$(HE $i)</li>") }
        [void]$sb.AppendLine('</ul>')
        [void]$sb.AppendLine('<h3>Configured servers</h3>' + (Tbl $Dns.Servers @('Interface','Servers','Count')))
        [void]$sb.AppendLine('<h3>Server reachability</h3>' + (Tbl $Dns.Reachability @('Server','Interface','TcpPort53','IcmpReply','Reachable')))
        [void]$sb.AppendLine('<h3>Resolution probes</h3>' + (Tbl $Dns.Probes @('Name','Resolved','Addresses','Ms')))
    }

    if ($Certs) {
        [void]$sb.AppendLine('<h2>Certificates</h2><h3>Findings</h3><ul>')
        foreach ($i in (Get-DxCertFindings -Certs $Certs)) { [void]$sb.AppendLine("<li>$(HE $i)</li>") }
        [void]$sb.AppendLine('</ul>')
        [void]$sb.AppendLine('<h3>Inventory (soonest expiry first)</h3>' +
            (Tbl (@($Certs) | Select-Object -First 200) @('Scope','Store','SubjectCN','IssuerCN','Purpose','NotAfter','DaysLeft','Status','HasKey','KeySize','Thumbprint')))
    }

    if ($EventSummary) {
        [void]$sb.AppendLine('<h2>Event analysis &amp; recommended resolutions</h2>')
        [void]$sb.AppendLine((Tbl $EventSummary @('Level','Provider','Id','Count','FirstSeen','LastSeen','Title')))
        foreach ($s in @($EventSummary | Where-Object { $_.LevelValue -le 3 } | Select-Object -First 25)) {
            [void]$sb.AppendLine('<div class="kb">')
            [void]$sb.AppendLine("<h4>[$(HE $s.Level)] $(HE $s.Provider) &mdash; Event ID $($s.Id) &nbsp;(&times;$($s.Count))</h4>")
            [void]$sb.AppendLine("<p><b>$(HE $s.Title)</b></p>")
            [void]$sb.AppendLine("<p><b>Likely cause:</b> $(HE $s.Cause)</p>")
            [void]$sb.AppendLine("<p><b>Impact:</b> $(HE $s.Impact)</p><p><b>Resolution:</b></p><ol>")
            foreach ($st in @($s.Steps)) { [void]$sb.AppendLine("<li>$(HE $st)</li>") }
            [void]$sb.AppendLine('</ol>')
            if (@($s.Commands).Count -gt 0) {
                [void]$sb.AppendLine('<p><b>Commands:</b></p>')
                foreach ($c in @($s.Commands)) { [void]$sb.AppendLine("<div><code>$(HE $c)</code></div>") }
            }
            if ($s.Docs) { [void]$sb.AppendLine("<p><a href='$(HE $s.Docs)'>Microsoft documentation</a></p>") }
            $sample = [string]$s.SampleText
            if ($sample.Length -gt 400) { $sample = $sample.Substring(0,400) + ' ...' }
            [void]$sb.AppendLine("<p class='none'>Sample: $(HE $sample)</p></div>")
        }
    }

    if ($Intune) {
        [void]$sb.AppendLine('<h2>Intune / MDM</h2>')
        $ir = @(
            [pscustomobject]@{ Property='Entra joined';  Value=$Intune.DsReg.AzureAdJoined },
            [pscustomobject]@{ Property='Domain joined'; Value=$Intune.DsReg.DomainJoined },
            [pscustomobject]@{ Property='Device ID';     Value=$Intune.DsReg.DeviceId },
            [pscustomobject]@{ Property='Tenant';        Value="$($Intune.DsReg.TenantName) ($($Intune.DsReg.TenantId))" },
            [pscustomobject]@{ Property='MDM URL';       Value=$Intune.DsReg.MdmUrl },
            [pscustomobject]@{ Property='Entra PRT';     Value=$Intune.DsReg.AzureAdPrt },
            [pscustomobject]@{ Property='IME service';   Value=$Intune.ImeService.Status }
        )
        [void]$sb.AppendLine((Tbl $ir @('Property','Value')))
        [void]$sb.AppendLine('<h3>Findings</h3><ul>')
        foreach ($i in @($Intune.Issues)) { [void]$sb.AppendLine("<li>$(HE $i)</li>") }
        [void]$sb.AppendLine('</ul>')
        [void]$sb.AppendLine('<h3>Win32 apps</h3>' + (Tbl $Intune.Win32Apps @('Scope','AppId','State','ErrorCode','Targeting')))
        [void]$sb.AppendLine('<h3>Platform PowerShell scripts</h3>' + (Tbl $Intune.Scripts @('Scope','ScriptId','State','ErrorCode','Detail')))
        [void]$sb.AppendLine('<h3>Remediations</h3>' + (Tbl $Intune.Remediations @('Scope','ScriptId','State','ErrorCode','LastRun','Detail')))
        [void]$sb.AppendLine('<h3>MDM sync tasks</h3>' + (Tbl $Intune.Tasks @('TaskName','State','LastRunTime','LastResult','NextRunTime')))
    }

    if ($Gpo) {
        [void]$sb.AppendLine('<h2>Group Policy</h2>')
        if (@($Gpo.SectionErrors).Count -gt 0) {
            [void]$sb.AppendLine('<h3>Collector notes</h3><ul>')
            foreach ($e in @($Gpo.SectionErrors)) { [void]$sb.AppendLine("<li>$(HE $e)</li>") }
            [void]$sb.AppendLine('</ul>')
        }
        [void]$sb.AppendLine('<h3>Conflicts and risks</h3>' + (Tbl $Gpo.Conflicts @('Severity','Type','Scope','Subject','Detail','Winner')))
        [void]$sb.AppendLine('<h3>Applied GPOs</h3>' + (Tbl $Gpo.AppliedGpos @('Scope','Order','Name','Link','Enforced')))
    }

    if ($SysDiag) {
        [void]$sb.AppendLine('<h2>System diagnostics</h2>')
        [void]$sb.AppendLine('<h3>Connectivity</h3>' + (Tbl $SysDiag.Connectivity @('Target','Endpoint','Port','Reachable')))
        [void]$sb.AppendLine('<h3>Problem devices</h3>' + (Tbl $SysDiag.ProblemDevices @('Device','Class','ErrorCode','Meaning')))
        [void]$sb.AppendLine('<h3>Stopped automatic services</h3>' + (Tbl $SysDiag.StoppedAutoServices @('Name','DisplayName','State','StartMode')))
        [void]$sb.AppendLine('<h3>Recent updates</h3>' + (Tbl $SysDiag.RecentUpdates @('HotFixID','Description','InstalledOn')))
    }

    [void]$sb.AppendLine('</main><footer>Generated by Sys@dmin. Knowledge-base rules live in KnowledgeBase.json.</footer></body></html>')
    Set-Content -Path $Path -Value $sb.ToString() -Encoding UTF8
    return $Path
}

function Export-DxJson {
    param($Data, [string]$Path)
    if (-not $Path) {
        $Path = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ("Sysadmin-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -f 'yyyyMMdd-HHmmss'))
    }
    $Data | ConvertTo-Json -Depth 6 | Set-Content -Path $Path -Encoding UTF8
    return $Path
}

# =============================================================================
# region  POLICY  (MDM Policy CSP + Group Policy + local)   [Part 10]
# =============================================================================
#  On an Entra-joined or Cloud PC device, gpresult shows almost nothing while
#  Policy CSP carries nearly all the configuration. This collector reads all
#  three sources and works out which one actually wins.
# =============================================================================

$script:DxPolicyAreaNames = @{
    'Accounts'='Accounts'; 'ApplicationManagement'='App management'; 'AppRuntime'='App runtime'
    'AttachmentManager'='Attachment manager'; 'Authentication'='Authentication'
    'Autoplay'='AutoPlay'; 'BitLocker'='BitLocker encryption'; 'Bluetooth'='Bluetooth'
    'Browser'='Legacy Edge browser'; 'Camera'='Camera'; 'Connectivity'='Connectivity'
    'CredentialProviders'='Credential providers'; 'CredentialsUI'='Credentials UI'
    'Cryptography'='Cryptography'; 'DataProtection'='Data protection'
    'Defender'='Microsoft Defender'; 'DeliveryOptimization'='Delivery Optimization'
    'DeviceGuard'='Device Guard'; 'DeviceInstallation'='Device installation'
    'DeviceLock'='Password and device lock'; 'Display'='Display'
    'ErrorReporting'='Error reporting'; 'EventLogService'='Event log service'
    'Experience'='User experience'; 'ExploitGuard'='Exploit Guard'
    'FileExplorer'='File Explorer'; 'Firewall'='Firewall'; 'Games'='Games'
    'Handwriting'='Handwriting'; 'InternetExplorer'='Internet Explorer'
    'Kerberos'='Kerberos'; 'LanmanWorkstation'='SMB client'
    'LocalPoliciesSecurityOptions'='Local security options'
    'LocalUsersAndGroups'='Local users and groups'; 'LockDown'='Lockdown'
    'Maps'='Maps'; 'Messaging'='Messaging'; 'MixedReality'='Mixed reality'
    'MSSecurityGuide'='MS Security Guide'; 'MSSLegacy'='MSS legacy'
    'NetworkIsolation'='Network isolation'; 'NetworkListManager'='Network list manager'
    'Notifications'='Notifications'; 'Power'='Power'; 'Printers'='Printers'
    'Privacy'='Privacy'; 'RemoteAssistance'='Remote Assistance'
    'RemoteDesktopServices'='Remote Desktop'; 'RemoteManagement'='WinRM remote management'
    'RemoteProcedureCall'='RPC'; 'RemoteShell'='Remote shell'
    'RestrictedGroups'='Restricted groups'; 'Search'='Search'; 'Security'='Security'
    'ServiceControlManager'='Service control manager'; 'Settings'='Settings app'
    'SmartScreen'='SmartScreen'; 'Speech'='Speech'; 'Start'='Start menu'
    'Storage'='Storage'; 'System'='System / telemetry'; 'SystemServices'='System services'
    'TaskScheduler'='Task Scheduler'; 'TextInput'='Text input'; 'TimeLanguageSettings'='Time and language'
    'Update'='Windows Update'; 'UserRights'='User rights assignment'
    'Virtualization'='Virtualisation'; 'Wifi'='Wi-Fi'; 'WindowsAutoPilot'='Autopilot'
    'WindowsDefenderSecurityCenter'='Defender Security Center'; 'WindowsInkWorkspace'='Windows Ink'
    'WindowsLogon'='Windows logon'; 'WindowsPowerShell'='PowerShell'
    'WindowsSandbox'='Windows Sandbox'; 'WirelessDisplay'='Wireless display'
}

function Get-DxPolicyAreaName {
    param([string]$Area)
    if (-not $Area) { return '' }
    if ($script:DxPolicyAreaNames.ContainsKey($Area)) { return $script:DxPolicyAreaNames[$Area] }
    # split CamelCase so unknown areas still read reasonably
    return ($Area -creplace '([a-z])([A-Z])', '$1 $2')
}

function Format-DxPolicyValue {
    # Registry values arrive as int, string, byte[] or string[]. Anything
    # enumerable must be flattened or a DataGrid renders "System.Object[]".
    param($Value)
    if ($null -eq $Value) { return '' }
    try {
        if ($Value -is [byte[]]) {
            $hex = ($Value | Select-Object -First 16 | ForEach-Object { '{0:X2}' -f $_ }) -join ' '
            if ($Value.Length -gt 16) { $hex = "$hex ..." }
            return "(binary $($Value.Length) bytes) $hex"
        }
        if ($Value -is [string]) { return $Value }
        if ($Value -is [System.Collections.IEnumerable]) {
            return ((@($Value) | ForEach-Object { "$_" }) -join ' | ')
        }
        return "$Value"
    }
    catch { return "$Value" }
}

function Get-DxEnrollmentMap {
    # Maps enrolment GUID -> readable owner, for _WinningProvider lookups.
    $map = @{}
    try {
        foreach ($k in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop)) {
            $id   = "$($k.PSChildName)"
            $prov = "$(Get-DxRegValue -Path $k.PSPath -Name 'ProviderID')"
            $upn  = "$(Get-DxRegValue -Path $k.PSPath -Name 'UPN')"
            if (-not $prov -and -not $upn) { continue }
            $label = $prov
            if ($upn) { $label = "$prov ($upn)" }
            if (-not $label) { $label = $id }
            $map[$id] = $label
        }
    } catch { }
    return $map
}

function Get-DxMdmPolicy {
    # Walks the Policy CSP tree:
    #   HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\<Area>    (device)
    #   HKLM\SOFTWARE\Microsoft\PolicyManager\current\<UserSID>\<Area> (user)
    # Per setting "Foo" Windows also stores Foo_ProviderSet /
    # Foo_WinningProvider / Foo_LastWrite. Those are filtered from the listing
    # but _WinningProvider names the owning enrolment.
    param($ErrorLog)

    $out  = New-Object System.Collections.ArrayList
    $emap = Get-DxEnrollmentMap
    $meta = @('_ProviderSet','_WinningProvider','_LastWrite','_RebootRequired','(default)',
              'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')

    $roots = New-Object System.Collections.ArrayList
    $null = $roots.Add([pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'; Scope='Device' })
    try {
        foreach ($u in @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current' -ErrorAction Stop)) {
            $n = "$($u.PSChildName)"
            if ($n -match '^S-1-') {
                $null = $roots.Add([pscustomobject]@{ Path=$u.PSPath; Scope=(Resolve-DxSidName $n) })
            }
        }
    } catch { }

    foreach ($root in $roots) {
        $null = Invoke-DxSection -Name "Policy/MDM/$($root.Scope)" -ErrorLog $ErrorLog -Script {
            if (-not (Test-Path $root.Path)) { return }
            foreach ($areaKey in @(Get-ChildItem $root.Path -ErrorAction Stop)) {
                $area = "$($areaKey.PSChildName)"
                if ($area -eq 'ControlPolicyConflict') { continue }
                $props = $null
                try { $props = Get-ItemProperty -Path $areaKey.PSPath -ErrorAction Stop } catch { continue }
                if (-not $props) { continue }

                foreach ($p in $props.PSObject.Properties) {
                    $name = "$($p.Name)"
                    if ($meta -contains $name) { continue }
                    if ($name -like '*_ProviderSet' -or $name -like '*_WinningProvider' -or
                        $name -like '*_LastWrite' -or $name -like 'PS*') { continue }

                    $winner = ''
                    $wp = $props.PSObject.Properties["${name}_WinningProvider"]
                    if ($wp) {
                        $g = "$($wp.Value)"
                        if ($g -and $emap.ContainsKey($g)) { $winner = $emap[$g] } else { $winner = $g }
                    }

                    $null = $out.Add([pscustomobject]@{
                        Source   = 'MDM'
                        Scope    = "$($root.Scope)"
                        Area     = $area
                        AreaName = (Get-DxPolicyAreaName $area)
                        Setting  = $name
                        Value    = (Format-DxPolicyValue $p.Value)
                        Owner    = $winner
                        KeyPath  = ("$($areaKey.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                    })
                }
            }
        }
    }
    return @($out.ToArray())
}

function Get-DxLegacyPolicy {
    # Registry policy written by Group Policy or set locally. Anything here
    # with no matching Policy CSP entry is effectively legacy/local.
    param($ErrorLog, [int]$MaxPerHive = 900)

    $out = New-Object System.Collections.ArrayList
    $roots = @(
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Policies'; Scope='Device' },
        [pscustomobject]@{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'; Scope='Device' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Policies'; Scope='Current user' },
        [pscustomobject]@{ Path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'; Scope='Current user' }
    )
    $skip = @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','(default)')

    foreach ($root in $roots) {
        $null = Invoke-DxSection -Name "Policy/Legacy/$($root.Path)" -ErrorLog $ErrorLog -Script {
            if (-not (Test-Path $root.Path)) { return }
            $n = 0
            foreach ($k in @(Get-ChildItem $root.Path -Recurse -ErrorAction SilentlyContinue)) {
                if ($n -ge $MaxPerHive) { break }
                $props = $null
                try { $props = Get-ItemProperty -Path $k.PSPath -ErrorAction Stop } catch { continue }
                if (-not $props) { continue }
                $clean = ("$($k.PSPath)" -replace '^Microsoft\.PowerShell\.Core\\Registry::', '')
                $leaf  = "$($k.PSChildName)"
                foreach ($p in $props.PSObject.Properties) {
                    if ($skip -contains "$($p.Name)") { continue }
                    if ("$($p.Name)" -like 'PS*') { continue }
                    $null = $out.Add([pscustomobject]@{
                        Source   = 'Registry policy'
                        Scope    = "$($root.Scope)"
                        Area     = $leaf
                        AreaName = $leaf
                        Setting  = "$($p.Name)"
                        Value    = (Format-DxPolicyValue $p.Value)
                        Owner    = ''
                        KeyPath  = $clean
                    })
                    $n++
                    if ($n -ge $MaxPerHive) { break }
                }
            }
        }
    }
    return @($out.ToArray())
}

function Get-DxPolicyState {
    # Effective-policy view across MDM Policy CSP, Group Policy and registry
    # policy. Pass an already-collected -Gpo object to avoid a second gpresult.
    param($Gpo)

    $sectionErrors = New-Object System.Collections.ArrayList

    $mdm    = @(Get-DxMdmPolicy    -ErrorLog $sectionErrors)
    $legacy = @(Get-DxLegacyPolicy -ErrorLog $sectionErrors)

    $gpoSettings = @()
    if ($Gpo) { $gpoSettings = @($Gpo.Settings) }

    # ---- who wins where both configure the same thing ----------------------
    $mdmWins = $null
    foreach ($p in @(
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\ControlPolicyConflict',
        'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device'
    )) {
        $v = Get-DxRegValue -Path $p -Name 'MDMWinsOverGP'
        if ($null -ne $v) { $mdmWins = $v; break }
    }
    if ($null -eq $mdmWins) {
        $mdmWins = Get-DxRegValue -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -Name 'ControlPolicyConflict'
    }
    $mdmWinsBool = ("$mdmWins" -eq '1')

    # ---- overlap detection -------------------------------------------------
    # Policy CSP names and GPO display names are NOT a 1:1 mapping, so this
    # matches normalised setting names and is a STRONG HINT, not proof.
    $conflicts = New-Object System.Collections.ArrayList
    $null = Invoke-DxSection -Name 'Policy/Conflicts' -ErrorLog $sectionErrors -Script {
        $gpoIndex = @{}
        foreach ($g in $gpoSettings) {
            $k = ("$($g.Setting)" -replace '[^A-Za-z0-9]', '').ToLower()
            if (-not $k) { continue }
            if (-not $gpoIndex.ContainsKey($k)) { $gpoIndex[$k] = $g }
        }
        foreach ($m in $mdm) {
            $k = ("$($m.Setting)" -replace '[^A-Za-z0-9]', '').ToLower()
            if (-not $k -or -not $gpoIndex.ContainsKey($k)) { continue }
            $g = $gpoIndex[$k]
            $winner = 'Group Policy'
            if ($mdmWinsBool) { $winner = 'Intune (MDM)' }
            $null = $conflicts.Add([pscustomobject]@{
                Severity = 'Warning'
                Setting  = "$($m.Setting)"
                Area     = "$($m.AreaName)"
                MdmValue = "$($m.Value)"
                GpoValue = "$($g.Value)"
                GpoName  = "$($g.GPO)"
                Winner   = $winner
                Detail   = "Configured by BOTH Policy CSP and Group Policy. Name matching is heuristic - confirm against $($m.KeyPath)."
            })
        }
    }

    # ---- summary + findings ------------------------------------------------
    $areas  = @($mdm | Group-Object Area)
    $issues = New-Object System.Collections.ArrayList

    if (@($mdm).Count -eq 0) {
        $null = $issues.Add('No Policy CSP settings found. The device has no Intune configuration profiles applied, or PolicyManager is not populated.')
    } else {
        $null = $issues.Add("$(@($mdm).Count) Policy CSP setting(s) across $(@($areas).Count) area(s) - this is where the device is actually configured from.")
    }
    if (@($gpoSettings).Count -eq 0) {
        $null = $issues.Add('No Group Policy settings in RSoP. On an Entra-joined or cloud-only device this is expected and correct, not a fault.')
    }
    if ($conflicts.Count -gt 0) {
        if ($mdmWinsBool) {
            $null = $issues.Add("$($conflicts.Count) setting(s) appear in BOTH Policy CSP and Group Policy. MDMWinsOverGP is enabled so Intune wins.")
        } else {
            $null = $issues.Add("$($conflicts.Count) setting(s) appear in BOTH Policy CSP and Group Policy. MDMWinsOverGP is NOT set, so Group Policy wins by default - a very common cause of Intune profiles appearing to do nothing.")
        }
    }
    if ((-not $mdmWinsBool) -and @($mdm).Count -gt 0 -and @($gpoSettings).Count -gt 0) {
        $null = $issues.Add('MDMWinsOverGP is not enabled. Where GPO and Intune configure the same setting, Group Policy silently overrides Intune.')
    }
    foreach ($e in @($sectionErrors.ToArray())) { $null = $issues.Add("SECTION ERROR $e") }

    $palette = @('#4F46E5','#0EA5E9','#7C3AED','#059669','#D97706','#DB2777','#0891B2','#65A30D','#DC2626','#F59E0B')
    $i = 0
    $areaChart = @($areas | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
        $c = $palette[$i % $palette.Count]; $i++
        [pscustomobject]@{ Label=(Get-DxPolicyAreaName "$($_.Name)"); Value=$_.Count; Color=$c }
    })

    $sourceChart = @(
        [pscustomobject]@{ Label='MDM (Policy CSP)'; Value=@($mdm).Count;         Color='#4F46E5' },
        [pscustomobject]@{ Label='Group Policy';     Value=@($gpoSettings).Count; Color='#0EA5E9' },
        [pscustomobject]@{ Label='Registry policy';  Value=@($legacy).Count;      Color='#D97706' }
    )

    $areaList = @($areas | ForEach-Object {
        [pscustomobject]@{ Area=(Get-DxPolicyAreaName "$($_.Name)"); RawArea="$($_.Name)"; Count=$_.Count }
    } | Sort-Object Count -Descending)

    [pscustomobject]@{
        Mdm           = $mdm
        Gpo           = @($gpoSettings)
        Legacy        = $legacy
        Areas         = $areaList
        Conflicts     = @($conflicts.ToArray())
        MdmWinsOverGP = $mdmWinsBool
        Issues        = @($issues.ToArray())
        SectionErrors = @($sectionErrors.ToArray())
        AreaChart     = $areaChart
        SourceChart   = $sourceChart
        Counts        = [pscustomobject]@{
            Mdm=@($mdm).Count; Gpo=@($gpoSettings).Count; Legacy=@($legacy).Count
            Areas=@($areas).Count; Conflicts=$conflicts.Count
        }
    }
}


# =============================================================================
#  ADVANCED SYSTEM HEALTH   [Part 12]
# =============================================================================
#  Hardware and posture data that the event log cannot tell you. These answer
#  the questions that otherwise end in a pointless reimage: is the battery
#  worn out, is the SSD wearing out, is the machine actually protected, is it
#  simply out of memory.
#
#  Every phase is isolated. Several of these WMI classes are absent on
#  desktops, VMs and Server Core, so "not present" is a normal answer and is
#  reported as such rather than as a failure.
# =============================================================================

function Get-DxBatteryHealth {
    <#
      Wear is the number that matters and it is not exposed directly - it is
      derived from FullChargedCapacity against DesignedCapacity, which live in
      two different root\wmi classes. Desktops have neither, which is not an
      error.
    #>
    param($ErrorLog)
    $out = [ordered]@{
        Present=$false; Batteries=@(); WorstWearPct=$null; Note=''
    }
    $batts = New-Object System.Collections.ArrayList

    $static = Invoke-DxSection -Name 'Battery:static' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData -ErrorAction Stop)
    }
    $full = Invoke-DxSection -Name 'Battery:fullcharge' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity -ErrorAction Stop)
    }
    $cycle = Invoke-DxSection -Name 'Battery:cyclecount' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -Namespace root\wmi -ClassName BatteryCycleCount -ErrorAction Stop)
    }
    $win32 = Invoke-DxSection -Name 'Battery:win32' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -ClassName Win32_Battery -ErrorAction Stop)
    }

    if (@($static).Count -eq 0 -and @($win32).Count -eq 0) {
        $out.Note = 'No battery detected - normal on a desktop, VM or Cloud PC.'
        return [pscustomobject]$out
    }
    $out.Present = $true

    $statusMap = @{
        1='Discharging'; 2='On mains'; 3='Fully charged'; 4='Low'; 5='Critical'
        6='Charging'; 7='Charging and high'; 8='Charging and low'; 9='Charging and critical'
        10='Undefined'; 11='Partially charged'
    }

    $i = 0
    foreach ($s in @($static)) {
        $design = 0; $fullCap = 0; $cycles = $null
        try { $design = [int]$s.DesignedCapacity } catch { }
        try { if (@($full).Count -gt $i) { $fullCap = [int](@($full)[$i]).FullChargedCapacity } } catch { }
        try { if (@($cycle).Count -gt $i) { $cycles = [int](@($cycle)[$i]).CycleCount } } catch { }

        $wear = $null; $health = 'Unknown'
        if ($design -gt 0 -and $fullCap -gt 0) {
            $wear = [math]::Round((1 - ($fullCap / $design)) * 100, 1)
            if ($wear -lt 0) { $wear = 0 }
            if ($wear -ge 40)      { $health = 'Replace' }
            elseif ($wear -ge 25)  { $health = 'Degraded' }
            elseif ($wear -ge 15)  { $health = 'Fair' }
            else                   { $health = 'Good' }
        }

        $w = $null
        try { if (@($win32).Count -gt $i) { $w = @($win32)[$i] } } catch { }
        $statusText = ''
        if ($w) {
            $sv = 0; try { $sv = [int]$w.BatteryStatus } catch { }
            if ($statusMap.ContainsKey($sv)) { $statusText = $statusMap[$sv] } else { $statusText = "Status $sv" }
        }

        $null = $batts.Add([pscustomobject]@{
            Name          = "$($s.DeviceName)"
            Manufacturer  = "$($s.ManufactureName)"
            Chemistry     = "$($s.Chemistry)"
            SerialNumber  = "$($s.SerialNumber)"
            DesignedmWh   = $design
            FullChargemWh = $fullCap
            WearPct       = $wear
            CycleCount    = $cycles
            Health        = $health
            ChargePct     = if ($w) { $w.EstimatedChargeRemaining } else { $null }
            Status        = $statusText
        })
        $i++
    }

    # Win32_Battery alone (some firmware exposes no root\wmi data at all)
    if ($batts.Count -eq 0) {
        foreach ($w in @($win32)) {
            $sv = 0; try { $sv = [int]$w.BatteryStatus } catch { }
            $null = $batts.Add([pscustomobject]@{
                Name="$($w.Name)"; Manufacturer=''; Chemistry=''; SerialNumber=''
                DesignedmWh=$null; FullChargemWh=$null; WearPct=$null; CycleCount=$null
                Health='Unknown - firmware exposes no capacity data'
                ChargePct=$w.EstimatedChargeRemaining
                Status=$(if($statusMap.ContainsKey($sv)){$statusMap[$sv]}else{"Status $sv"})
            })
        }
    }

    $out.Batteries = @($batts.ToArray())
    $worst = @($out.Batteries | Where-Object { $null -ne $_.WearPct } | Sort-Object WearPct -Descending)
    if (@($worst).Count -gt 0) { $out.WorstWearPct = $worst[0].WearPct }
    if (-not $out.Note) {
        if ($null -eq $out.WorstWearPct) {
            $out.Note = 'Battery present but the firmware does not report design capacity, so wear cannot be calculated.'
        }
    }
    return [pscustomobject]$out
}

function Get-DxStorageReliability {
    <#
      Reliability counters are the closest thing to SMART that Windows exposes
      without a vendor tool. Wear is only meaningful on SSDs; spinning disks
      report it as null and that is not a fault.
    #>
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList

    $disks = Invoke-DxSection -Name 'Storage:physicaldisk' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-PhysicalDisk -ErrorAction Stop)
    }

    foreach ($d in @($disks)) {
        $rc = Invoke-DxSection -Name "Storage:counters:$($d.DeviceId)" -ErrorLog $ErrorLog -Default $null -Script {
            $d | Get-StorageReliabilityCounter -ErrorAction Stop
        }
        $wear = $null; $temp = $null; $tempMax = $null; $hours = $null
        $readErr = $null; $writeErr = $null; $realloc = $null; $starts = $null
        if ($rc) {
            try { $wear     = $rc.Wear } catch { }
            try { $temp     = $rc.Temperature } catch { }
            try { $tempMax  = $rc.TemperatureMax } catch { }
            try { $hours    = $rc.PowerOnHours } catch { }
            try { $readErr  = $rc.ReadErrorsTotal } catch { }
            try { $writeErr = $rc.WriteErrorsTotal } catch { }
            try { $realloc  = $rc.ReallocatedSectors } catch { }
            try { $starts   = $rc.StartStopCycleCount } catch { }
        }

        $verdict = 'OK'
        if ($null -ne $wear -and $wear -ge 80)      { $verdict = 'Wear critical' }
        elseif ($null -ne $wear -and $wear -ge 50)  { $verdict = 'Wear high' }
        if ("$($d.HealthStatus)" -notmatch '^(?i)healthy') { $verdict = "Health: $($d.HealthStatus)" }
        if ($null -ne $realloc -and $realloc -gt 0)  { $verdict = 'Reallocated sectors' }

        $null = $rows.Add([pscustomobject]@{
            Disk=$d.DeviceId; Model="$($d.FriendlyName)"; Media="$($d.MediaType)"
            Bus="$($d.BusType)"; SizeGB=[math]::Round($d.Size/1GB,1)
            Health="$($d.HealthStatus)"; WearPct=$wear
            TempC=$temp; TempMaxC=$tempMax; PowerOnHours=$hours
            ReadErrors=$readErr; WriteErrors=$writeErr
            ReallocatedSectors=$realloc; StartStopCycles=$starts
            Verdict=$verdict
        })

        if ($null -ne $wear -and $wear -ge 50) {
            $null = $findings.Add("$($d.FriendlyName): SSD wear indicator at $wear% - plan replacement before it becomes read-only.")
        }
        if ($null -ne $realloc -and $realloc -gt 0) {
            $null = $findings.Add("$($d.FriendlyName): $realloc reallocated sector(s) - the drive is remapping failures. Back up and replace.")
        }
        if ($null -ne $temp -and $temp -ge 70) {
            $null = $findings.Add("$($d.FriendlyName): running at $temp C - check airflow; sustained heat shortens NAND life.")
        }
        if ("$($d.HealthStatus)" -notmatch '^(?i)healthy') {
            $null = $findings.Add("$($d.FriendlyName): reported health is '$($d.HealthStatus)' rather than Healthy.")
        }
    }

    $smart = Invoke-DxSection -Name 'Storage:smartpredict' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -Namespace root\wmi -ClassName MSStorageDriver_FailurePredictStatus -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{ Instance="$($_.InstanceName)"; PredictFailure=[bool]$_.PredictFailure; Reason=$_.Reason }
            })
    }
    foreach ($s in @($smart)) {
        if ($s.PredictFailure) {
            $null = $findings.Add("SMART failure prediction is ACTIVE on $($s.Instance) - treat as imminent failure and replace the drive.")
        }
    }

    $note = ''
    if (@($rows).Count -eq 0) {
        $note = 'No physical disks returned reliability data. Common on virtual machines and on Cloud PCs, where the host abstracts the storage.'
    }

    return [pscustomobject]@{
        Disks=@($rows.ToArray()); SmartPredict=@($smart)
        Findings=@($findings.ToArray()); Note=$note
    }
}

function Get-DxSecurityPosture {
    <#
      Reports what is actually ON, not what policy intends. The gap between the
      two is the whole point of the card.
    #>
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList

    function Add-DxPostureRow {
        param($List, [string]$Area, [string]$Setting, $Value, [string]$Expected, [string]$State, [string]$Detail = '')
        $null = $List.Add([pscustomobject]@{
            Area=$Area; Setting=$Setting; Value="$Value"; Expected=$Expected; State=$State; Detail=$Detail
        })
    }

    # ---- Secure Boot ----
    $sb = Invoke-DxSection -Name 'Posture:secureboot' -ErrorLog $ErrorLog -Default 'Unknown' -Script {
        try { if (Confirm-SecureBootUEFI) { 'Enabled' } else { 'Disabled' } }
        catch { 'Not supported (legacy BIOS or not exposed)' }
    }
    $sbState = 'Unknown'
    if ($sb -eq 'Enabled') { $sbState = 'OK' } elseif ($sb -eq 'Disabled') { $sbState = 'Risk' }
    Add-DxPostureRow $rows 'Boot' 'Secure Boot' $sb 'Enabled' $sbState
    if ($sb -eq 'Disabled') { $null = $findings.Add('Secure Boot is disabled - the device cannot attest boot integrity and will fail most compliance policies.') }

    # ---- TPM ----
    $tpm = Invoke-DxSection -Name 'Posture:tpm' -ErrorLog $ErrorLog -Default $null -Script {
        Get-Tpm -ErrorAction Stop
    }
    if ($tpm) {
        $ready = [bool]$tpm.TpmReady
        Add-DxPostureRow $rows 'Hardware' 'TPM present'  ([bool]$tpm.TpmPresent) 'True' $(if([bool]$tpm.TpmPresent){'OK'}else{'Risk'})
        Add-DxPostureRow $rows 'Hardware' 'TPM ready'    $ready 'True' $(if($ready){'OK'}else{'Risk'})
        Add-DxPostureRow $rows 'Hardware' 'TPM enabled'  ([bool]$tpm.TpmEnabled) 'True' $(if([bool]$tpm.TpmEnabled){'OK'}else{'Risk'})
        $ver = ''
        try { $ver = "$($tpm.ManufacturerVersionFull20)" } catch { }
        if (-not $ver) { try { $ver = "$($tpm.ManufacturerVersion)" } catch { } }
        Add-DxPostureRow $rows 'Hardware' 'TPM version' $ver '2.0' 'Info' 'Windows Hello and BitLocker key protection depend on this.'
        if (-not $ready) { $null = $findings.Add('TPM is not ready - Windows Hello provisioning and BitLocker key protection will fail until it is.') }
    } else {
        Add-DxPostureRow $rows 'Hardware' 'TPM' 'Not available' '2.0, ready' 'Unknown' 'Get-Tpm returned nothing - needs elevation, or no TPM is exposed.'
    }

    # ---- Virtualisation-based security ----
    $dg = Invoke-DxSection -Name 'Posture:deviceguard' -ErrorLog $ErrorLog -Default $null -Script {
        Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    }
    if ($dg) {
        $svcMap = @{ 1='Credential Guard'; 2='HVCI (memory integrity)'; 3='System Guard secure launch' }
        $running = @($dg.SecurityServicesRunning) | Where-Object { $_ -ne 0 }
        $configured = @($dg.SecurityServicesConfigured) | Where-Object { $_ -ne 0 }
        $vbs = switch ([int]$dg.VirtualizationBasedSecurityStatus) { 0 {'Off'} 1 {'Configured but not running'} 2 {'Running'} default {'Unknown'} }
        Add-DxPostureRow $rows 'VBS' 'Virtualisation-based security' $vbs 'Running' $(if($vbs -eq 'Running'){'OK'}else{'Risk'})
        foreach ($k in $svcMap.Keys) {
            $isRun = ($running -contains $k); $isCfg = ($configured -contains $k)
            $state = 'Info'
            if ($isRun) { $state = 'OK' } elseif ($isCfg) { $state = 'Risk' }
            $detail = ''
            if ($isCfg -and -not $isRun) { $detail = 'Configured by policy but NOT running - usually a firmware or driver incompatibility.' }
            Add-DxPostureRow $rows 'VBS' $svcMap[$k] $(if($isRun){'Running'}elseif($isCfg){'Configured, not running'}else{'Not configured'}) 'Running' $state $detail
            if ($isCfg -and -not $isRun) {
                $null = $findings.Add("$($svcMap[$k]) is configured by policy but is not running - the device reports as compliant while being unprotected.")
            }
        }
    }

    # ---- BitLocker ----
    $bl = Invoke-DxSection -Name 'Posture:bitlocker' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-BitLockerVolume -ErrorAction Stop)
    }
    $blRows = New-Object System.Collections.ArrayList
    foreach ($v in @($bl)) {
        $prot = "$($v.ProtectionStatus)"
        $null = $blRows.Add([pscustomobject]@{
            Mount="$($v.MountPoint)"; VolumeType="$($v.VolumeType)"
            Protection=$prot; Encryption="$($v.EncryptionMethod)"
            Percent=$v.EncryptionPercentage
            KeyProtectors=((@($v.KeyProtector) | ForEach-Object { "$($_.KeyProtectorType)" }) -join ', ')
            LockStatus="$($v.LockStatus)"
        })
        if ("$($v.VolumeType)" -match '(?i)operatingsystem' -and $prot -notmatch '^(?i)on') {
            $null = $findings.Add("BitLocker protection is '$prot' on the OS volume $($v.MountPoint) - the disk is not protected at rest.")
        }
        $hasRecovery = @($v.KeyProtector) | Where-Object { "$($_.KeyProtectorType)" -match '(?i)recovery' }
        if ($prot -match '^(?i)on' -and @($hasRecovery).Count -eq 0) {
            $null = $findings.Add("$($v.MountPoint) is encrypted but has no recovery password protector - there is no escrowed way back in.")
        }
    }
    if (@($bl).Count -gt 0) {
        $osVol = @($bl | Where-Object { "$($_.VolumeType)" -match '(?i)operatingsystem' })
        $osProt = 'Unknown'
        if (@($osVol).Count -gt 0) { $osProt = "$($osVol[0].ProtectionStatus)" }
        Add-DxPostureRow $rows 'Encryption' 'BitLocker (OS volume)' $osProt 'On' $(if($osProt -match '^(?i)on'){'OK'}else{'Risk'})
    }

    # ---- Defender ----
    $mp = Invoke-DxSection -Name 'Posture:defender' -ErrorLog $ErrorLog -Default $null -Script {
        Get-MpComputerStatus -ErrorAction Stop
    }
    if ($mp) {
        Add-DxPostureRow $rows 'Antivirus' 'Defender running mode' "$($mp.AMRunningMode)" 'Normal' $(if("$($mp.AMRunningMode)" -match '(?i)normal'){'OK'}else{'Info'}) 'Passive means a third-party product is primary.'
        Add-DxPostureRow $rows 'Antivirus' 'Real-time protection' ([bool]$mp.RealTimeProtectionEnabled) 'True' $(if([bool]$mp.RealTimeProtectionEnabled){'OK'}else{'Risk'})
        Add-DxPostureRow $rows 'Antivirus' 'Tamper protection' ([bool]$mp.IsTamperProtected) 'True' $(if([bool]$mp.IsTamperProtected){'OK'}else{'Info'})
        $age = $null; try { $age = [int]$mp.AntivirusSignatureAge } catch { }
        Add-DxPostureRow $rows 'Antivirus' 'Signature age (days)' $age '0-2' $(if($null -ne $age -and $age -le 2){'OK'}elseif($null -ne $age){'Risk'}else{'Unknown'})
        if (-not [bool]$mp.RealTimeProtectionEnabled) { $null = $findings.Add('Defender real-time protection is off.') }
        if ($null -ne $age -and $age -gt 7) { $null = $findings.Add("Defender signatures are $age days old - the update path is broken, not just late.") }
    }

    return [pscustomobject]@{
        Rows=@($rows.ToArray()); BitLocker=@($blRows.ToArray()); Findings=@($findings.ToArray())
    }
}

function Get-DxMemoryInventory {
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList
    $formMap = @{ 8='DIMM'; 12='SODIMM'; 0='Unknown'; 2='Unknown' }
    $typeMap = @{ 20='DDR'; 21='DDR2'; 24='DDR3'; 26='DDR4'; 34='DDR5'; 0='Unknown' }

    $dimms = Invoke-DxSection -Name 'Memory:dimms' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -ClassName Win32_PhysicalMemory -ErrorAction Stop)
    }
    foreach ($m in @($dimms)) {
        $ff = 0; try { $ff = [int]$m.FormFactor } catch { }
        $mt = 0; try { $mt = [int]$m.SMBIOSMemoryType } catch { }
        $null = $rows.Add([pscustomobject]@{
            Slot="$($m.DeviceLocator)"; Bank="$($m.BankLabel)"
            CapacityGB=[math]::Round($m.Capacity/1GB,1)
            SpeedMHz=$m.Speed; ConfiguredMHz=$m.ConfiguredClockSpeed
            Type=$(if($typeMap.ContainsKey($mt)){$typeMap[$mt]}else{"Type $mt"})
            Form=$(if($formMap.ContainsKey($ff)){$formMap[$ff]}else{"Form $ff"})
            Manufacturer="$($m.Manufacturer)"; PartNumber="$("$($m.PartNumber)".Trim())"
            Serial="$($m.SerialNumber)"
        })
    }

    $arr = Invoke-DxSection -Name 'Memory:array' -ErrorLog $ErrorLog -Default $null -Script {
        Get-CimInstance -ClassName Win32_PhysicalMemoryArray -ErrorAction Stop | Select-Object -First 1
    }
    $os = Invoke-DxSection -Name 'Memory:os' -ErrorLog $ErrorLog -Default $null -Script {
        Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    }
    $pf = Invoke-DxSection -Name 'Memory:pagefile' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop |
            ForEach-Object { [pscustomobject]@{
                Name="$($_.Name)"; AllocatedMB=$_.AllocatedBaseSize
                CurrentMB=$_.CurrentUsage; PeakMB=$_.PeakUsage } })
    }

    $slots = $null; $used = @($rows).Count
    try { if ($arr) { $slots = [int]$arr.MemoryDevices } } catch { }
    $totalGB = $null; $freeGB = $null; $usedPct = $null
    if ($os) {
        try {
            $totalGB = [math]::Round($os.TotalVisibleMemorySize/1MB,1)
            $freeGB  = [math]::Round($os.FreePhysicalMemory/1MB,1)
            if ($totalGB -gt 0) { $usedPct = [math]::Round((1-($freeGB/$totalGB))*100,1) }
        } catch { }
    }

    $findings = New-Object System.Collections.ArrayList
    if ($null -ne $usedPct -and $usedPct -ge 90) {
        $null = $findings.Add("Physical memory is $usedPct% used - check the top consumers before blaming the disk or the network.")
    }
    if ($null -ne $slots -and $slots -gt $used -and $used -gt 0) {
        $null = $findings.Add("$used of $slots memory slots populated - there is headroom to add RAM without replacing modules.")
    }
    $speeds = @(@($rows) | Where-Object { $_.SpeedMHz } | Select-Object -ExpandProperty SpeedMHz -Unique)
    if (@($speeds).Count -gt 1) {
        $null = $findings.Add("Mixed memory speeds detected ($($speeds -join ', ') MHz) - the whole array runs at the slowest module.")
    }
    if (@($rows).Count -eq 1 -and $null -ne $slots -and $slots -gt 1) {
        $null = $findings.Add('Single module in a multi-slot system - running single-channel, which measurably hurts integrated-graphics performance.')
    }

    return [pscustomobject]@{
        Modules=@($rows.ToArray()); PageFiles=@($pf)
        SlotsTotal=$slots; SlotsUsed=$used
        TotalGB=$totalGB; FreeGB=$freeGB; UsedPct=$usedPct
        Findings=@($findings.ToArray())
    }
}

function Get-DxTopProcesses {
    <#
      Two samples a second apart, because a single snapshot of CPU time is
      cumulative since process start and tells you nothing about now.
    #>
    param($ErrorLog, [int]$Top = 15)
    $rows = New-Object System.Collections.ArrayList
    $res = Invoke-DxSection -Name 'Processes:sample' -ErrorLog $ErrorLog -Default @() -Script {
        $cpuCount = [Environment]::ProcessorCount
        $a = @{}
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            try { $a[$p.Id] = $p.TotalProcessorTime.TotalMilliseconds } catch { }
        }
        Start-Sleep -Milliseconds 1000
        $list = New-Object System.Collections.ArrayList
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            $cpuPct = $null
            try {
                if ($a.ContainsKey($p.Id)) {
                    $delta = $p.TotalProcessorTime.TotalMilliseconds - $a[$p.Id]
                    $cpuPct = [math]::Round(($delta / 1000.0) / $cpuCount * 100, 1)
                    if ($cpuPct -lt 0) { $cpuPct = 0 }
                }
            } catch { }
            $startTime = $null
            try { $startTime = $p.StartTime } catch { }
            $null = $list.Add([pscustomobject]@{
                Name=$p.ProcessName; Id=$p.Id
                CpuPct=$cpuPct
                WorkingSetMB=[math]::Round($p.WorkingSet64/1MB,1)
                PrivateMB=[math]::Round($p.PrivateMemorySize64/1MB,1)
                Handles=$p.HandleCount; Threads=$p.Threads.Count
                Started=$startTime
            })
        }
        @($list.ToArray())
    }

    $byMem = @(@($res) | Sort-Object WorkingSetMB -Descending | Select-Object -First $Top)
    $byCpu = @(@($res) | Where-Object { $null -ne $_.CpuPct } | Sort-Object CpuPct -Descending | Select-Object -First $Top)

    $findings = New-Object System.Collections.ArrayList
    foreach ($p in @($byMem | Select-Object -First 3)) {
        if ($p.WorkingSetMB -ge 2048) {
            $null = $findings.Add("$($p.Name) (PID $($p.Id)) is holding $($p.WorkingSetMB) MB - check for a leak if it grows across hours.")
        }
    }
    foreach ($p in @($res)) {
        if ($p.Handles -ge 20000) {
            $null = $findings.Add("$($p.Name) (PID $($p.Id)) holds $($p.Handles) handles - a handle leak eventually destabilises the whole session.")
        }
    }

    return [pscustomobject]@{
        ByMemory=$byMem; ByCpu=$byCpu; Findings=@($findings.ToArray())
    }
}

function Get-DxDriverHealth {
    <#
      Stale and unsigned drivers are the usual root of "random" bugchecks and
      of VBS being configured but not running.
    #>
    param($ErrorLog, [int]$StaleYears = 5)
    $rows = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList

    $drv = Invoke-DxSection -Name 'Drivers:signed' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-CimInstance -ClassName Win32_PnPSignedDriver -ErrorAction Stop |
            Where-Object { $_.DeviceName })
    }
    $cutoff = (Get-Date).AddYears(-1 * $StaleYears)
    foreach ($d in @($drv)) {
        $date = $null
        try { $date = [datetime]$d.DriverDate } catch { }
        $age = $null
        if ($date) { $age = [math]::Round(((Get-Date) - $date).TotalDays / 365.25, 1) }
        $signed = $true
        try { $signed = [bool]$d.IsSigned } catch { }
        $flag = ''
        if (-not $signed) { $flag = 'UNSIGNED' }
        elseif ($date -and $date -lt $cutoff) { $flag = "Stale ($age yr)" }
        $null = $rows.Add([pscustomobject]@{
            Device="$($d.DeviceName)"; Class="$($d.DeviceClass)"
            Provider="$($d.DriverProviderName)"; Version="$($d.DriverVersion)"
            DriverDate=$date; AgeYears=$age; Signed=$signed
            InfName="$($d.InfName)"; Flag=$flag
        })
    }

    $unsigned = @(@($rows) | Where-Object { -not $_.Signed })
    $stale    = @(@($rows) | Where-Object { $_.Flag -like 'Stale*' })
    if (@($unsigned).Count -gt 0) {
        $null = $findings.Add("$(@($unsigned).Count) unsigned driver(s) present - these block HVCI from running and are a common bugcheck source.")
    }
    if (@($stale).Count -gt 0) {
        $null = $findings.Add("$(@($stale).Count) driver(s) older than $StaleYears years. Storage, network and graphics drivers are the ones worth chasing.")
    }

    $key = @(@($rows) | Where-Object { $_.Class -match '(?i)^(net|display|diskdrive|scsiadapter|hdc|system|bluetooth)$' } |
        Sort-Object AgeYears -Descending)

    return [pscustomobject]@{
        All=@($rows.ToArray()); Unsigned=$unsigned; Stale=$stale
        KeyClasses=$key; Findings=@($findings.ToArray())
    }
}

function Get-DxUptimeHistory {
    <#
      Boot durations and unclean shutdown counts over the window. A machine
      that reboots cleanly every night looks identical to one that bugchecks
      every night until you count 6008s.
    #>
    param($ErrorLog, [int]$Hours = 720)
    $since = (Get-Date).AddHours(-1 * [math]::Abs($Hours))

    $boots = Invoke-DxSection -Name 'Uptime:boots' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-WinEvent -FilterHashtable @{ LogName='System'; Id=6005,6006,6008,41,1074; StartTime=$since } -ErrorAction Stop |
            ForEach-Object {
                $kind = switch ([int]$_.Id) {
                    6005 { 'Event log started (boot)' }
                    6006 { 'Event log stopped (clean shutdown)' }
                    6008 { 'UNEXPECTED shutdown' }
                    41   { 'Kernel-Power 41 (no clean shutdown)' }
                    1074 { 'Initiated shutdown/restart' }
                    default { "Id $($_.Id)" }
                }
                [pscustomobject]@{
                    Time=$_.TimeCreated; Id=$_.Id; Kind=$kind
                    Detail=(($_.Message -replace '\s+',' ').Trim())
                }
            })
    }

    $perf = Invoke-DxSection -Name 'Uptime:bootperf' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; Id=100; StartTime=$since } -ErrorAction Stop |
            ForEach-Object {
                $x = [xml]$_.ToXml()
                $get = {
                    param($n)
                    $v = ($x.Event.EventData.Data | Where-Object { $_.Name -eq $n }).'#text'
                    if ($v) { [int]$v } else { $null }
                }
                [pscustomobject]@{
                    Time=$_.TimeCreated
                    BootSec=[math]::Round((& $get 'BootTime')/1000.0,1)
                    MainPathSec=[math]::Round((& $get 'MainPathBootTime')/1000.0,1)
                    PostBootSec=[math]::Round((& $get 'BootPostBootTime')/1000.0,1)
                    DegradationSec=[math]::Round((& $get 'BootDegradationTime')/1000.0,1)
                }
            })
    }

    $unclean = @(@($boots) | Where-Object { $_.Id -in 6008,41 })
    $findings = New-Object System.Collections.ArrayList
    if (@($unclean).Count -ge 3) {
        $null = $findings.Add("$(@($unclean).Count) unclean shutdown(s) in the window - this is a hardware, power or driver problem, not a user habit.")
    }
    $slow = @(@($perf) | Where-Object { $_.BootSec -ge 90 })
    if (@($slow).Count -gt 0) {
        $avg = [math]::Round((@($perf) | Measure-Object BootSec -Average).Average,1)
        $null = $findings.Add("$(@($slow).Count) boot(s) took 90s or more (average $avg s) - check the Winlogon subscriber and Group Policy events for the phase that stalls.")
    }

    $lastBoot = $null
    try { $lastBoot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime } catch { }
    $upDays = $null
    if ($lastBoot) { $upDays = [math]::Round(((Get-Date) - $lastBoot).TotalDays,1) }
    if ($null -ne $upDays -and $upDays -ge 30) {
        $null = $findings.Add("Uptime is $upDays days - patches requiring a restart cannot have completed. Confirm the pending-reboot state.")
    }

    return [pscustomobject]@{
        Events=@($boots); BootPerf=@($perf); UncleanCount=@($unclean).Count
        LastBoot=$lastBoot; UptimeDays=$upDays; Findings=@($findings.ToArray())
    }
}

function Get-DxSystemHealthAdvanced {
    <#
      Composes the advanced collectors. Each is isolated, so a machine that has
      no battery, no TPM or no reliability counters still returns everything
      else. $SectionErrors distinguishes "this device has none" from "the
      collector broke".
    #>
    param([int]$Hours = 720)
    $sectionErrors = New-Object System.Collections.ArrayList

    $battery  = Invoke-DxSection -Name 'Adv:Battery'  -ErrorLog $sectionErrors -Default $null -Script { Get-DxBatteryHealth      -ErrorLog $sectionErrors }
    $storage  = Invoke-DxSection -Name 'Adv:Storage'  -ErrorLog $sectionErrors -Default $null -Script { Get-DxStorageReliability -ErrorLog $sectionErrors }
    $posture  = Invoke-DxSection -Name 'Adv:Posture'  -ErrorLog $sectionErrors -Default $null -Script { Get-DxSecurityPosture    -ErrorLog $sectionErrors }
    $memory   = Invoke-DxSection -Name 'Adv:Memory'   -ErrorLog $sectionErrors -Default $null -Script { Get-DxMemoryInventory    -ErrorLog $sectionErrors }
    $procs    = Invoke-DxSection -Name 'Adv:Procs'    -ErrorLog $sectionErrors -Default $null -Script { Get-DxTopProcesses       -ErrorLog $sectionErrors }
    $drivers  = Invoke-DxSection -Name 'Adv:Drivers'  -ErrorLog $sectionErrors -Default $null -Script { Get-DxDriverHealth       -ErrorLog $sectionErrors }
    $uptime   = Invoke-DxSection -Name 'Adv:Uptime'   -ErrorLog $sectionErrors -Default $null -Script { Get-DxUptimeHistory      -ErrorLog $sectionErrors -Hours $Hours }

    $all = New-Object System.Collections.ArrayList
    foreach ($o in @($storage, $posture, $memory, $procs, $drivers, $uptime)) {
        if ($o -and $o.Findings) { foreach ($f in @($o.Findings)) { $null = $all.Add("$f") } }
    }
    if ($battery -and $null -ne $battery.WorstWearPct -and $battery.WorstWearPct -ge 25) {
        $null = $all.Add("Battery wear is $($battery.WorstWearPct)% - runtime complaints on this device are expected, not a software fault.")
    }

    return [pscustomobject]@{
        Battery=$battery; Storage=$storage; Posture=$posture; Memory=$memory
        Processes=$procs; Drivers=$drivers; Uptime=$uptime
        Findings=@($all.ToArray())
        SectionErrors=@($sectionErrors.ToArray())
    }
}


# =============================================================================
#  DEEP INTUNE / MDM DIAGNOSTICS   [Part 13]
# =============================================================================
#  Get-DxIntuneState answers "what is configured". This answers "why is it not
#  working", which is a different question and needs different data:
#
#    Sync         when did OMA-DM last COMPLETE, not when was it last tried
#    Endpoints    can this device actually reach the service, from SYSTEM
#    Certificates both the MDM device cert and the Entra device cert
#    Autopilot    profile and ESP state
#    Apps         MSI/LOB alongside Win32, with names where resolvable
#    Timeline     one chronological merge of every MDM-relevant signal
# =============================================================================

function Get-DxMdmSyncHealth {
    <#
      "Last sync" is the most misread field in Intune support. The scheduled
      task's LastRunTime says the task FIRED, not that a session completed -
      a device with a broken channel shows a recent LastRunTime forever. The
      authoritative signal is the OMA-DM session result in the event log.
    #>
    param($ErrorLog, $Tasks)
    $out = [ordered]@{
        LastAttempt=$null; LastSuccess=$null; AgeHours=$null; Verdict='Unknown'
        Sessions=@(); ServerAccount=''; Note=''
    }

    $log = 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    $sessions = Invoke-DxSection -Name 'MdmSync:sessions' -ErrorLog $ErrorLog -Default @() -Script {
        # No Id filter. The v4.5 build asked for 208/209/201/202 and got an
        # empty grid on a working device - filtering to IDs that may not be
        # emitted proves nothing except that those IDs were absent. Take the
        # recent log and classify what is actually there.
        @(Get-WinEvent -FilterHashtable @{ LogName=$log } -MaxEvents 200 -ErrorAction Stop |
            ForEach-Object {
                $kind = switch ([int]$_.Id) {
                    208 { 'Sync session finished' }
                    209 { 'Sync session result' }
                    201 { 'Server response processed' }
                    202 { 'Server node processed' }
                    209.0 { 'Sync session result' }
                    813 { 'Policy applied' }
                    814 { 'Policy area processed' }
                    1905 { 'Enrollment session' }
                    default { "Channel event $($_.Id)" }
                }
                [pscustomobject]@{
                    Time=$_.TimeCreated; Id=$_.Id; Kind=$kind
                    Level="$($_.LevelDisplayName)"
                    Detail=(($_.Message -replace '\s+',' ').Trim())
                }
            })
    }
    $out.Sessions = @($sessions)

    # A session that logged at Information level is the closest thing to a
    # confirmed success the channel exposes.
    $ok = @(@($sessions) | Where-Object { $_.Id -in 208,209 -and $_.Level -match '(?i)^info' } | Sort-Object Time -Descending)
    if (@($ok).Count -gt 0) { $out.LastSuccess = $ok[0].Time }

    $anyTask = @(@($Tasks) | Where-Object { $_.LastRunTime } | Sort-Object LastRunTime -Descending)
    if (@($anyTask).Count -gt 0) { $out.LastAttempt = $anyTask[0].LastRunTime }
    if (-not $out.LastSuccess -and @($sessions).Count -gt 0) {
        $out.LastSuccess = (@($sessions) | Sort-Object Time -Descending)[0].Time
        $out.Note = 'No clean session-finished event found; falling back to the most recent channel event, which may represent a failure.'
    }

    # A scheduled task firing is NOT evidence that a session completed - that
    # is the exact misreading this collector exists to prevent, and the v4.5
    # build fell for it by scoring the task attempt when no session was found.
    # No session evidence now means Unknown, not Healthy.
    if ($out.LastSuccess) {
        $out.AgeHours = [math]::Round(((Get-Date) - $out.LastSuccess).TotalHours, 1)
        # Intune's own cadence is roughly every 8 hours once enrolled.
        if ($out.AgeHours -le 12)      { $out.Verdict = 'Healthy' }
        elseif ($out.AgeHours -le 24)  { $out.Verdict = 'Late' }
        elseif ($out.AgeHours -le 72)  { $out.Verdict = 'Stale' }
        else                           { $out.Verdict = 'Not syncing' }
    } elseif ($out.LastAttempt) {
        $out.AgeHours = [math]::Round(((Get-Date) - $out.LastAttempt).TotalHours, 1)
        $out.Verdict = 'Unknown - task ran, no session confirmed'
        $out.Note = 'The MDM scheduled task fired but no OMA-DM session event was found. A task firing is not proof a session completed; the channel may be failing silently. Check the Service endpoints tab before trusting the age shown.'
    } else {
        $out.Verdict = 'Unknown - no evidence'
        $out.Note = 'No MDM channel events and no task history. Either the device has never enrolled, or the diagnostics-provider log has been cleared.'
    }

    $acct = Invoke-DxSection -Name 'MdmSync:omadm' -ErrorLog $ErrorLog -Default '' -Script {
        $base = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts'
        if (-not (Test-Path $base)) { return '' }
        $k = @(Get-ChildItem $base -ErrorAction Stop) | Select-Object -First 1
        if ($k) { "$($k.PSChildName)" } else { '' }
    }
    $out.ServerAccount = "$acct"

    return [pscustomobject]$out
}

function Test-DxIntuneEndpoints {
    <#
      Reachability from SYSTEM context, which is what actually matters - the
      IME and the OMA-DM client do not use a per-user proxy, so a device that
      browses fine can still be unable to sync.

      TCP 443 only. These endpoints drop ICMP by design, so ping proves
      nothing and produces confident false negatives.
    #>
    param($ErrorLog, [int]$TimeoutMs = 3000)
    $targets = @(
        [pscustomobject]@{ Host='login.microsoftonline.com';          Purpose='Entra authentication / token acquisition' }
        [pscustomobject]@{ Host='device.login.microsoftonline.com';   Purpose='Device authentication (PRT)' }
        [pscustomobject]@{ Host='enterpriseregistration.windows.net'; Purpose='Device registration / MDM enrollment' }
        [pscustomobject]@{ Host='manage.microsoft.com';               Purpose='Intune service - OMA-DM channel' }
        [pscustomobject]@{ Host='portal.manage.microsoft.com';        Purpose='Company Portal / Intune portal' }
        [pscustomobject]@{ Host='graph.microsoft.com';                Purpose='Microsoft Graph' }
        [pscustomobject]@{ Host='config.office.com';                  Purpose='Microsoft 365 Apps configuration' }
    )
    $rows = New-Object System.Collections.ArrayList
    foreach ($t in $targets) {
        $r = Invoke-DxSection -Name "Endpoint:$($t.Host)" -ErrorLog $ErrorLog -Default $null -Script {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $client = New-Object Net.Sockets.TcpClient
            try {
                $iar = $client.BeginConnect($t.Host, 443, $null, $null)
                $done = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
                if ($done -and $client.Connected) {
                    $client.EndConnect($iar)
                    $sw.Stop()
                    [pscustomobject]@{ Ok=$true; Ms=[int]$sw.ElapsedMilliseconds; Error='' }
                } else {
                    $sw.Stop()
                    [pscustomobject]@{ Ok=$false; Ms=$null; Error="No TCP 443 response within $TimeoutMs ms" }
                }
            } finally {
                try { $client.Close() } catch { }
            }
        }
        $ok = $false; $ms = $null; $err = 'Check did not run'
        if ($r) { $ok = [bool]$r.Ok; $ms = $r.Ms; $err = "$($r.Error)" }
        $state = 'Fail'
        if ($ok) { $state = 'OK'; if ($null -ne $ms -and $ms -gt 1500) { $state = 'Slow' } }
        $null = $rows.Add([pscustomobject]@{
            Endpoint=$t.Host; Purpose=$t.Purpose; State=$state
            LatencyMs=$ms; Detail=$err
        })
    }

    $proxy = Invoke-DxSection -Name 'Endpoint:winhttp' -ErrorLog $ErrorLog -Default '' -Script {
        $o = (netsh winhttp show proxy) 2>&1
        (($o | Out-String) -replace '\s+',' ').Trim()
    }

    $bad = @(@($rows.ToArray()) | Where-Object { $_.State -eq 'Fail' })
    $findings = New-Object System.Collections.ArrayList
    foreach ($b in $bad) {
        $null = $findings.Add("$($b.Endpoint) is unreachable on TCP 443 - $($b.Purpose) will fail.")
    }
    if (@($bad).Count -ge 3) {
        $null = $findings.Add('Several endpoints are unreachable at once. Check the WinHTTP proxy for SYSTEM context and any TLS-inspecting appliance before investigating Intune itself.')
    }

    return [pscustomobject]@{
        Results=@($rows.ToArray()); WinHttpProxy="$proxy"
        FailCount=@($bad).Count; Findings=@($findings.ToArray())
    }
}

function Get-DxMdmCertificates {
    <#
      Two different certificates, routinely confused:
        MS-Organization-Access      the Entra DEVICE certificate - the PRT
                                    and Conditional Access depend on it
        Microsoft Intune MDM ...    the MDM management certificate - the
                                    OMA-DM channel depends on it
      Losing either produces a different failure, so both are reported.
    #>
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList

    $certs = Invoke-DxSection -Name 'MdmCert:store' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop)
    }
    $wanted = @(
        [pscustomobject]@{ Match='Microsoft Intune MDM Device CA'; Role='MDM management (OMA-DM channel)' }
        [pscustomobject]@{ Match='MS-Organization-Access';         Role='Entra device identity (PRT, Conditional Access)' }
        [pscustomobject]@{ Match='MS-Organization-P2P-Access';     Role='Entra peer-to-peer authentication' }
    )
    foreach ($w in $wanted) {
        $hit = @(@($certs) | Where-Object { "$($_.Issuer)" -match [regex]::Escape($w.Match) } |
                 Sort-Object NotAfter -Descending) | Select-Object -First 1
        if (-not $hit) {
            $null = $rows.Add([pscustomobject]@{
                Role=$w.Role; Issuer=$w.Match; Subject='(absent)'; Thumbprint=''
                NotBefore=$null; NotAfter=$null; DaysLeft=$null; HasPrivateKey=$false; State='Missing'
            })
            if ($w.Match -ne 'MS-Organization-P2P-Access') {
                $null = $findings.Add("No '$($w.Match)' certificate in LocalMachine\My - $($w.Role) cannot work.")
            }
            continue
        }
        $days = $null
        try { $days = [math]::Round(($hit.NotAfter - (Get-Date)).TotalDays, 1) } catch { }
        $hasKey = $false
        try { $hasKey = [bool]$hit.HasPrivateKey } catch { }
        $state = 'OK'
        if ($null -ne $days -and $days -lt 0)       { $state = 'EXPIRED' }
        elseif ($null -ne $days -and $days -le 30)  { $state = 'Expiring' }
        if (-not $hasKey)                           { $state = 'No private key' }
        $null = $rows.Add([pscustomobject]@{
            Role=$w.Role; Issuer=(("$($hit.Issuer)" -split ',')[0]); Subject="$($hit.Subject)"
            Thumbprint="$($hit.Thumbprint)"; NotBefore=$hit.NotBefore; NotAfter=$hit.NotAfter
            DaysLeft=$days; HasPrivateKey=$hasKey; State=$state
        })
        if ($state -eq 'EXPIRED') {
            $null = $findings.Add("The $($w.Role) certificate EXPIRED on $($hit.NotAfter).")
        } elseif ($state -eq 'Expiring') {
            $null = $findings.Add("The $($w.Role) certificate expires in $days day(s). Renewal happens on a successful sync, so fix sync first.")
        } elseif (-not $hasKey) {
            $null = $findings.Add("The $($w.Role) certificate has no private key - it cannot be used and must be re-issued.")
        }
    }

    return [pscustomobject]@{ Certificates=@($rows.ToArray()); Findings=@($findings.ToArray()) }
}

function Get-DxAutopilotState {
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList
    $findings = New-Object System.Collections.ArrayList

    function Add-DxApRow { param($L, [string]$K, $V, [string]$N = '')
        $null = $L.Add([pscustomobject]@{ Setting=$K; Value="$V"; Note=$N })
    }

    $null = Invoke-DxSection -Name 'Autopilot:registry' -ErrorLog $ErrorLog -Script {
        $ap = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'
        if (Test-Path $ap) {
            Add-DxApRow $rows 'Autopilot profile present' 'Yes'
            foreach ($n in @('CloudAssignedTenantDomain','CloudAssignedTenantId','CloudAssignedOobeConfig','DeploymentProfileName','AutopilotServiceCorrelationId')) {
                $v = Get-DxRegValue -Path $ap -Name $n
                if ($null -ne $v -and "$v" -ne '') { Add-DxApRow $rows $n $v }
            }
        } else {
            Add-DxApRow $rows 'Autopilot profile present' 'No' 'Normal for a manually enrolled or hybrid-joined device.'
        }
        $esp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\FirstLogonAnim'
        $oobe = Get-DxRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' -Name 'SetupDisplayedEula'
        if ($null -ne $oobe) { Add-DxApRow $rows 'OOBE completed marker' $oobe }
        $tpmAttest = Get-DxRegValue -Path 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot' -Name 'CloudAssignedDeviceName'
        if ($tpmAttest) { Add-DxApRow $rows 'Assigned device name' $tpmAttest }
    }

    $null = Invoke-DxSection -Name 'Autopilot:esp' -ErrorLog $ErrorLog -Script {
        $base = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
        foreach ($k in @(Get-ChildItem $base -ErrorAction Stop)) {
            $fs = Join-Path $k.PSPath 'FirstSync'
            if (Test-Path $fs) {
                foreach ($n in @('IsSyncDone','SkipDeviceStatusPage','SkipUserStatusPage','BlockInStatusPage','DeviceStatusPageTimeout')) {
                    $v = Get-DxRegValue -Path $fs -Name $n
                    if ($null -ne $v) { Add-DxApRow $rows "ESP: $n" $v }
                }
                $sync = Get-DxRegValue -Path $fs -Name 'IsSyncDone'
                if ($null -ne $sync -and "$sync" -ne '1') {
                    $null = $findings.Add('Enrollment Status Page has not completed (IsSyncDone is not 1). Provisioning is still in progress or stalled.')
                }
            }
        }
    }

    $events = Invoke-DxSection -Name 'Autopilot:events' -ErrorLog $ErrorLog -Default @() -Script {
        @(Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin' } -MaxEvents 60 -ErrorAction Stop |
            ForEach-Object {
                [pscustomobject]@{
                    Time=$_.TimeCreated; Id=$_.Id; Level="$($_.LevelDisplayName)"
                    Detail=(($_.Message -replace '\s+',' ').Trim())
                }
            })
    }

    return [pscustomobject]@{
        Rows=@($rows.ToArray()); Events=@($events); Findings=@($findings.ToArray())
    }
}

function Get-DxManagedApps {
    <#
      Win32 apps are covered by Get-DxIntuneState. MSI/LOB apps travel a
      completely different path (EnterpriseDesktopAppManagement, not the IME)
      and are invisible in the Win32 view, so a missing LOB app looks like
      nothing was ever assigned.
    #>
    param($ErrorLog)
    $rows = New-Object System.Collections.ArrayList

    $null = Invoke-DxSection -Name 'Apps:msi' -ErrorLog $ErrorLog -Script {
        $base = 'HKLM:\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement'
        if (-not (Test-Path $base)) { return }
        foreach ($sid in @(Get-ChildItem $base -ErrorAction Stop)) {
            $scope = Resolve-DxSidName $sid.PSChildName
            $msi = Join-Path $sid.PSPath 'MSI'
            if (-not (Test-Path $msi)) { continue }
            foreach ($app in @(Get-ChildItem $msi -ErrorAction SilentlyContinue)) {
                $map = Get-DxRegValueMap -Path $app.PSPath
                $status = Get-DxRegValueAny -Map $map -Names @('Status','CurrentStatus')
                $statusText = switch ("$status") {
                    '10' { 'Initialised' }   '20' { 'Downloading' }
                    '30' { 'Downloaded' }    '40' { 'Installing' }
                    '50' { 'Waiting reboot' } '60' { 'Retry pending' }
                    '70' { 'Installed' }     '80' { 'Uninstalled' }
                    '90' { 'FAILED' }        '100' { 'FAILED (download)' }
                    default { if ("$status") { "Status $status" } else { '' } }
                }
                $null = $rows.Add([pscustomobject]@{
                    Scope=$scope; Kind='MSI / LOB'; ProductCode=$app.PSChildName
                    Name="$(Get-DxRegValueAny -Map $map -Names @('DownloadInstall','Name','DisplayName'))"
                    Status=$statusText
                    LastError="$(Get-DxRegValueAny -Map $map -Names @('LastError','ErrorCode'))"
                    Version="$(Get-DxRegValueAny -Map $map -Names @('ProductVersion','Version'))"
                    DownloadCount="$(Get-DxRegValueAny -Map $map -Names @('DownloadCount','DownloadRetryCount','RetryCount'))"
                    ValueNames=((@($map.Keys) | Select-Object -First 8) -join ', ')
                })
            }
        }
    }

    $findings = New-Object System.Collections.ArrayList
    foreach ($r in @($rows.ToArray())) {
        if ($r.Status -like 'FAILED*') {
            $null = $findings.Add("MSI/LOB app $($r.ProductCode) is in state '$($r.Status)' (last error $($r.LastError)).")
        }
    }
    return [pscustomobject]@{ Apps=@($rows.ToArray()); Findings=@($findings.ToArray()) }
}

function Get-DxIntuneTimeline {
    <#
      One chronological merge. Triage almost always starts with "what happened
      around 09:14", and answering that from four separate grids is the slow
      way to do it.
    #>
    param($Intune, $Sync, $Autopilot, [int]$Max = 300)
    $rows = New-Object System.Collections.ArrayList

    foreach ($e in @($Intune.EnrollEvents)) {
        $null = $rows.Add([pscustomobject]@{ Time=$e.Time; Source='Enrollment'; Signal="$($e.Result)"; Detail="$($e.Message)" })
    }
    foreach ($e in @($Intune.MdmEvents)) {
        $null = $rows.Add([pscustomobject]@{ Time=$e.TimeCreated; Source='MDM channel'; Signal="$($e.LevelDisplayName) $($e.Id)"; Detail="$($e.Message)" })
    }
    foreach ($e in @($Sync.Sessions)) {
        $null = $rows.Add([pscustomobject]@{ Time=$e.Time; Source='Sync'; Signal="$($e.Kind)"; Detail="$($e.Detail)" })
    }
    foreach ($e in @($Autopilot.Events)) {
        $null = $rows.Add([pscustomobject]@{ Time=$e.Time; Source='Provisioning'; Signal="$($e.Level) $($e.Id)"; Detail="$($e.Detail)" })
    }
    foreach ($t in @($Intune.Tasks)) {
        if ($t.LastRunTime) {
            $res = 'ok'
            if ($null -ne $t.LastResult -and $t.LastResult -ne 0) { $res = ('0x{0:X8}' -f $t.LastResult) }
            $null = $rows.Add([pscustomobject]@{ Time=$t.LastRunTime; Source='Sync task'; Signal="$($t.TaskName) -> $res"; Detail='' })
        }
    }

    $sorted = @(@($rows.ToArray()) | Where-Object { $_.Time } | Sort-Object Time -Descending | Select-Object -First $Max)
    return @($sorted)
}

function Get-DxIntuneDeep {
    param($Intune)
    $sectionErrors = New-Object System.Collections.ArrayList

    if (-not $Intune) {
        $Intune = Invoke-DxSection -Name 'Deep:base' -ErrorLog $sectionErrors -Default $null -Script { Get-DxIntuneState }
    }
    if (-not $Intune) {
        return [pscustomobject]@{
            Sync=$null; Endpoints=$null; Certificates=$null; Autopilot=$null; Apps=$null
            Timeline=@(); Findings=@('Base Intune collector returned nothing - nothing further could be evaluated.')
            SectionErrors=@($sectionErrors.ToArray()); Verdict='Unknown'; Score=$null
        }
    }

    $sync  = Invoke-DxSection -Name 'Deep:Sync'      -ErrorLog $sectionErrors -Default $null -Script { Get-DxMdmSyncHealth    -ErrorLog $sectionErrors -Tasks $Intune.Tasks }
    $endp  = Invoke-DxSection -Name 'Deep:Endpoints' -ErrorLog $sectionErrors -Default $null -Script { Test-DxIntuneEndpoints -ErrorLog $sectionErrors }
    $certs = Invoke-DxSection -Name 'Deep:Certs'     -ErrorLog $sectionErrors -Default $null -Script { Get-DxMdmCertificates  -ErrorLog $sectionErrors }
    $ap    = Invoke-DxSection -Name 'Deep:Autopilot' -ErrorLog $sectionErrors -Default $null -Script { Get-DxAutopilotState   -ErrorLog $sectionErrors }
    $apps  = Invoke-DxSection -Name 'Deep:Apps'      -ErrorLog $sectionErrors -Default $null -Script { Get-DxManagedApps      -ErrorLog $sectionErrors }
    $tl    = Invoke-DxSection -Name 'Deep:Timeline'  -ErrorLog $sectionErrors -Default @()   -Script { Get-DxIntuneTimeline -Intune $Intune -Sync $sync -Autopilot $ap }

    $findings = New-Object System.Collections.ArrayList
    foreach ($o in @($endp, $certs, $ap, $apps)) {
        if ($o -and $o.Findings) { foreach ($f in @($o.Findings)) { $null = $findings.Add("$f") } }
    }
    if ($sync) {
        if ($sync.Verdict -eq 'Not syncing') {
            $null = $findings.Add("No successful MDM sync for $($sync.AgeHours) hour(s). Policy, apps and compliance are all frozen at the last good sync.")
        } elseif ($sync.Verdict -eq 'Stale') {
            $null = $findings.Add("Last MDM sync was $($sync.AgeHours) hour(s) ago - beyond the usual 8-hour cadence.")
        }
        if ($sync.Note) { $null = $findings.Add($sync.Note) }
    }

    # ---- verdict: weighted on what actually blocks management -------------
    $score = 100
    if ($sync) {
        switch ($sync.Verdict) {
            'Late'        { $score -= 5 }
            'Stale'       { $score -= 20 }
            'Not syncing' { $score -= 40 }
            'Unknown'     { $score -= 10 }
        }
    }
    if ($endp) { $score -= [math]::Min(30, 10 * [int]$endp.FailCount) }
    if ($certs) {
        foreach ($c in @($certs.Certificates)) {
            if ($c.State -eq 'EXPIRED')        { $score -= 25 }
            elseif ($c.State -eq 'Missing' -and $c.Role -notmatch 'peer-to-peer') { $score -= 20 }
            elseif ($c.State -eq 'Expiring')   { $score -= 8 }
            elseif ($c.State -eq 'No private key') { $score -= 20 }
        }
    }
    $failedApps = @(@($Intune.Win32Apps) | Where-Object { "$($_.State)" -like 'FAILED*' })
    $score -= [math]::Min(15, 5 * @($failedApps).Count)
    if ($Intune.ImeService -and "$($Intune.ImeService.Status)" -ne 'Running') { $score -= 15 }
    if ($score -lt 0) { $score = 0 }

    $verdict = 'Healthy'
    if ($score -lt 50)      { $verdict = 'Broken' }
    elseif ($score -lt 75)  { $verdict = 'Degraded' }
    elseif ($score -lt 95)  { $verdict = 'Minor issues' }

    return [pscustomobject]@{
        Sync=$sync; Endpoints=$endp; Certificates=$certs; Autopilot=$ap; Apps=$apps
        Timeline=@($tl); Findings=@($findings.ToArray())
        SectionErrors=@($sectionErrors.ToArray())
        Verdict=$verdict; Score=$score
    }
}

