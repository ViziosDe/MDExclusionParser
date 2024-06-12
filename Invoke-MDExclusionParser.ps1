

function Get-ASRConfiguration{
    param (
        [string]$LogName = "Microsoft-Windows-Windows Defender/Operational",
        [int]$EventIDASRRules = 5007,
        [int]$EventIDTriggeredASRRules = 1121
    )

    $asrRules = [ordered]@{}
    $observedASRRules = @{}
    $observedASRExclusionRules = @{}

    $patterns = @{
        "GUID" = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
        "ASRMask" = "0x[1|2|4|6]"
        "ASRExclusionPattern" = "[^\s]+(?=\S*$)"
    }

    $asrRuleAccessMatrix = @{
        "0x0" = "Not configured"
        "0x1" = "Block"
        "0x2" = "Audit"
        "0x6" = "Warn"
    }

    $asrRuleToGuidMatrix = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
        "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
        "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
        "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
        "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
        "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }      

    $events = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventIDASRRules}
    $asrEvents = $events | Where-Object { $_.Message -match "Windows Defender Exploit Guard\\ASR\\Rules"}

    $eventsTriggeredASR = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventIDTriggeredASRRules}
    $asrTriggeredEvents = $eventsTriggeredASR | Where-Object { $_.Message -match "Microsoft Defender Exploit Guard has blocked an operation"}

    $asrExclusionEvents = $events | Where-Object { $_.Message -match "New value:(.+)\\ASR\\ASROnlyPerRuleExclusions\\[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"}


    # Pushed ASR Changes
    $asrEvents | ForEach-Object {
        
        $message = $_.Message
        $asrRuleTimeCreated = $_.TimeCreated

        if($message -match $patterns["GUID"]){
            $asrRuleName = $asrRuleToGuidMatrix[$matches[0]]

            if($message -match $patterns["ASRMask"] -And -Not ($observedASRRules.ContainsKey($asrRuleName))){
                $asrRuleMode = $asrRuleAccessMatrix[$matches[0]]

                $entry = [PSCustomObject]@{
                    ASRRuleName = $asrRuleName
                    ASRRuleMode = $asrRuleMode
                }
            
                $asrRules.Add($asrRuleTimeCreated, $entry)
                $observedASRRules.Add($asrRuleName, $message)
            } 
            # Write-Host "[ASR] ASR Rule: " $asrRuleName $asrRuleMode
        }
    }

    # Triggered ASR Events
    $asrTriggeredEvents | ForEach-Object{
        $message = $_.Message
        $asrRuleTimeCreated = $_.TimeCreated

        if($message -match $patterns["GUID"]){
            $asrRuleName = $asrRuleToGuidMatrix[$matches[0]]

            if(-Not $observedASRRules.ContainsKey($asrRuleName)){
                # TODO: 0x1 for now. Further testing required. 
                $asrRuleMode = $asrRuleAccessMatrix["0x1"]

                $entry = [PSCustomObject]@{
                    ASRRuleName = $asrRuleName
                    ASRRuleMode = $asrRuleMode
                }
            
                $asrRules.Add($asrRuleTimeCreated, $entry)
                $observedASRRules.Add($asrRuleName, $message)
            }
        }
    }

    # Pushed ASR Exclusions
    $asrExclusionEvents | ForEach-Object {
        
        $message = $_.Message
        $asrRuleTimeCreated = $_.TimeCreated

        if($message -match $patterns["GUID"]){
            $asrRuleName = $asrRuleToGuidMatrix[$matches[0]]

            if(-Not $observedASRExclusionRules.ContainsKey($asrRuleName)){
                if(-Not $observedASRRules.ContainsKey($asrRuleName)){
                    # ASR Rule not in $observedASRRules yet. Adding with Exclusions
                    # TODO: 0x1 for now. Further testing required. 
                    $asrRuleMode = $asrRuleAccessMatrix["0x1"]
                    $asrExclusionList = if ($message -match $patterns["ASRExclusionPattern"]) { $matches[0] }
                    $entry = [PSCustomObject]@{
                        ASRRuleName = $asrRuleName
                        ASRRuleMode = $asrRuleMode
                        ASRExclusionList =  $($asrExclusionList -split '>')
                    }
                
                    $asrRules.Add($asrRuleTimeCreated, $entry)
                    $observedASRRules.Add($asrRuleName, $message)
                }else{
                    # ASR Rule in $observedASRRules. Updating.
                    foreach ($key in $asrRules.Keys){
                        if($asrRules[$key].ASRRuleName -eq $asrRuleName){
                            $asrExclusionList = if ($message -match $patterns["ASRExclusionPattern"]) { $matches[0] }
                            $asrRules[$key] | Add-Member NoteProperty -Name 'ASRExclusionList' -Value $($asrExclusionList -split '>')
                            $observedASRExclusionRules.Add($asrRuleName, $message)
                        }
                    }
                }
            } 
        }
    }

    if($asrRules.Count -gt 0){
        Write-Host "[i] ASR Rules Found:" -f Green
        $asrRules.Values | Sort-Object -Property "ASRRuleName" -Descending | Format-Table
    } else {
        Write-Host "[i] No ASR Rules found in Event Log." -f Red
    }
    
    
}

function Get-DefenderExclusions{
    param (
        [string]$LogName = "Microsoft-Windows-Windows Defender/Operational",
        [int]$EventID = 5007
    )

    $defenderExclusions = [ordered]@{}
    $deletedExclusions = @{}

    # Get all event logs with the specified Event ID efficiently in descending order
    $events = Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventID}

    # Filter events that contain the word "Exclusions"
    $exclusionEvents = $events | Where-Object { $_.Message -match "Exclusions" }

    # Define the regex patterns to match exclusion paths, extensions, and processes
    $patternDeletedExclusion = "(.+)Old value:(.+)\n(.+)New value:\s$"

    $patterns = @{
        Path = "\\Exclusions\\Paths\\(.+?)\s*="
        Extension = "\\Exclusions\\Extensions\\(.+?)\s*="
        Process = "\\Exclusions\\Processes\\(.+?)\s*="
    }

    $exclusionEvents | ForEach-Object {
        
        $message = $_.Message

        foreach ($type in $patterns.Keys){
            if ($message -match $patterns[$type]){

                $exclusionTimeCreated = $_.TimeCreated
                $exclusionType = $type
                $exclusionDetail = $matches[1]

                if($message -match $patternDeletedExclusion){
                    if(-not $deletedExclusions.Contains($exclusionDetail)){
                        $deletedExclusions.Add($exclusionDetail, $message)
                    }
                }elseif (-not $deletedExclusions.ContainsKey($exclusionDetail)) {
                    $entry = [PSCustomObject]@{
                        ExclusionType = $exclusionType
                        exclusionDetail = $exclusionDetail  
                    }
                    $defenderExclusions.Add($exclusionTimeCreated, $entry)
                }
            }
        }
    } 

    if($defenderExclusions.Count -gt 0){
        Write-Host "[i] Defender Exclusions Found:" -f Green
        $defenderExclusions.Values | Sort-Object -Property "ExclusionType" -Descending | Format-Table
    } else {
        Write-Host "[i] No Defender Exclusions found in Event Log." -f Red
    }
    
}

Write-Host "`r`n"
Write-Host "MDExclusionParser`r`n"
Write-Host "Credit: ViziosDe (https://x.com/ViziosDe)`r`n"
Write-Host "Acknowledgements:"
Write-Host "`t- Lawrence (https://x.com/zux0x3a)"
Write-Host "`t- VakninHai (https://x.com/VakninHai/status/1796628601535652289)"
Write-Host "`r`n"


Write-Host "[i] Parsing for Defender Exclusions`r`n" -f Green
Get-DefenderExclusions
Write-Host "[i] Parsing for ASR Configuration`r`n" -f Green
Get-ASRConfiguration
