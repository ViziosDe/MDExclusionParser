# MDExclusionParser
MDExclusionParser is a PowerShell script to quickly scan Event Log ID 5007 and 1121 for published Windows Defender Exclusions and Attack Surface Reduction (ASR) rule configuration. 

## Features
- **Windows Defender Exclusions:** Determine Windows Defender Path, Process and Extension exclusions.
- **ASR Rules:** Determine Attack Surface Reduction (ASR) Rules and their corresponding configuration mode (Disabled, Audit, Warn, Block)
- **ASR Exclusions:** Determine Attack Surface Reduction (ASR) Rule Exclusions and their corresponding Path.

## Usage:
Simply run the script or invoke it directly from GitHub via:

```
PS > powershell -Exec Bypas -NoProfile -c "(New-Object Net.WebClient).DownloadString('<URL>') | iex"
```

![image](https://github.com/ViziosDe/MDExclusionParser/assets/23127806/d8fdcbcb-79af-49ed-acfb-8f85b9f59f43)

## Background:
Commands like Get-MpPreference do not display Defender/ASR Exclusions and ASR Rule Configuration anymore for low priviledged Users. 
Fortunately, changes in those configurations still create a 5007 Event for new / updated / deleted configuration (e.g. via Intune or local configuration). Further, Event 1121 is created whenever an ASR Rule is triggered.
This allows for querying those Event IDs from a low privileged User context and extracting the relevant information.

## Limitations:
This tool relies solely on Events being present in the Event Log.

## Acknowledgements:
- Lawrence (https://twitter.com/zux0x3a)
- VakninHai (https://x.com/VakninHai/status/1796628601535652289)
