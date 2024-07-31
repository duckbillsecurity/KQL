```
//name: World Writable Execution - Temp
// description: Detect process execution from C:\Windows\Temp.
// author: ASD's ACSC
DeviceProcessEvents
| where FolderPath startswith "C:\\Windows\\Temp\\" and (not((FolderPath matches regex "(?i)C:\\\\Windows\\\\Temp\\\\\\{[a-fA-F0-9]{8}-([a-fA-F0-9]{4}-){3}[a-fA-F0-9]{12}\\}\\\\" or (AccountName contains "SYSTEM" or AccountName contains "NETWORK SERVICE") or FolderPath endswith "dismhost.exe" or (InitiatingProcessFolderPath endswith "\\esif_uf.exe" or InitiatingProcessFolderPath endswith "\\vmtoolsd.exe" or InitiatingProcessFolderPath endswith "\\cwainstaller.exe" or InitiatingProcessFolderPath endswith "\\trolleyexpress.exe"))))

// name: World Writable Execution - Non-Temp System Subdirectory
// description: Detect process execution from a world writable location in a subdirectory of the Windows OS install location.
// author: ASD's ACSC
DeviceProcessEvents
| where (FolderPath contains ":\\$Recycle.Bin\\" or FolderPath contains ":\\AMD\\Temp\\" or FolderPath contains ":\\Intel\\" or FolderPath contains ":\\PerfLogs\\" or FolderPath contains ":\\Windows\\addins\\" or FolderPath contains ":\\Windows\\appcompat\\" or FolderPath contains ":\\Windows\\apppatch\\" or FolderPath contains ":\\Windows\\AppReadiness\\" or FolderPath contains ":\\Windows\\bcastdvr\\" or FolderPath contains ":\\Windows\\Boot\\" or FolderPath contains ":\\Windows\\Branding\\" or FolderPath contains ":\\Windows\\CbsTemp\\" or FolderPath contains ":\\Windows\\Containers\\" or FolderPath contains ":\\Windows\\csc\\" or FolderPath contains ":\\Windows\\Cursors\\" or FolderPath contains ":\\Windows\\debug\\" or FolderPath contains ":\\Windows\\diagnostics\\" or FolderPath contains ":\\Windows\\DigitalLocker\\" or FolderPath contains ":\\Windows\\dot3svc\\" or FolderPath contains ":\\Windows\\en-US\\" or FolderPath contains ":\\Windows\\Fonts\\" or FolderPath contains ":\\Windows\\Globalization\\" or FolderPath contains ":\\Windows\\Help\\" or FolderPath contains ":\\Windows\\IdentityCRL\\" or FolderPath contains ":\\Windows\\IME\\" or FolderPath contains ":\\Windows\\ImmersiveControlPanel\\" or FolderPath contains ":\\Windows\\INF\\" or FolderPath contains ":\\Windows\\intel\\" or FolderPath contains ":\\Windows\\L2Schemas\\" or FolderPath contains ":\\Windows\\LiveKernelReports\\" or FolderPath contains ":\\Windows\\Logs\\" or FolderPath contains ":\\Windows\\media\\" or FolderPath contains ":\\Windows\\Migration\\" or FolderPath contains ":\\Windows\\ModemLogs\\" or FolderPath contains ":\\Windows\\ms\\" or FolderPath contains ":\\Windows\\OCR\\" or FolderPath contains ":\\Windows\\panther\\" or FolderPath contains ":\\Windows\\Performance\\" or FolderPath contains ":\\Windows\\PLA\\" or FolderPath contains ":\\Windows\\PolicyDefinitions\\" or FolderPath contains ":\\Windows\\Prefetch\\" or FolderPath contains ":\\Windows\\PrintDialog\\" or FolderPath contains ":\\Windows\\Provisioning\\" or FolderPath contains ":\\Windows\\Registration\\CRMLog\\" or FolderPath contains ":\\Windows\\RemotePackages\\" or FolderPath contains ":\\Windows\\rescache\\" or FolderPath contains ":\\Windows\\Resources\\" or FolderPath contains ":\\Windows\\SchCache\\" or FolderPath contains ":\\Windows\\schemas\\" or FolderPath contains ":\\Windows\\security\\" or FolderPath contains ":\\Windows\\ServiceState\\" or FolderPath contains ":\\Windows\\servicing\\" or FolderPath contains ":\\Windows\\Setup\\" or FolderPath contains ":\\Windows\\ShellComponents\\" or FolderPath contains ":\\Windows\\ShellExperiences\\" or FolderPath contains ":\\Windows\\SKB\\" or FolderPath contains ":\\Windows\\TAPI\\" or FolderPath contains ":\\Windows\\Tasks\\" or FolderPath contains ":\\Windows\\TextInput\\" or FolderPath contains ":\\Windows\\tracing\\" or FolderPath contains ":\\Windows\\Vss\\" or FolderPath contains ":\\Windows\\WaaS\\" or FolderPath contains ":\\Windows\\Web\\" or FolderPath contains ":\\Windows\\wlansvc\\" or FolderPath contains ":\\Windows\\System32\\Com\\dmp\\" or FolderPath contains ":\\Windows\\System32\\FxsTmp\\" or FolderPath contains ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\" or FolderPath contains ":\\Windows\\System32\\Speech\\" or FolderPath contains ":\\Windows\\System32\\spool\\drivers\\color\\" or FolderPath contains ":\\Windows\\System32\\spool\\PRINTERS\\" or FolderPath contains ":\\Windows\\System32\\spool\\SERVERS\\" or FolderPath contains ":\\Windows\\System32\\Tasks_Migrated\\Microsoft\\Windows\\PLA\\System\\" or FolderPath contains ":\\Windows\\System32\\Tasks\\" or FolderPath contains ":\\Windows\\SysWOW64\\Com\\dmp\\" or FolderPath contains ":\\Windows\\SysWOW64\\FxsTmp\\" or FolderPath contains ":\\Windows\\SysWOW64\\Tasks\\") and (not((FolderPath contains "\\AppData\\" and AccountName =~ "SYSTEM")))

// name: World Writable Execution - Users
// description: Detect process execution from C:\Users\Public\* and other world writable folders within Users.
// author: ASD's ACSC
DeviceProcessEvents
| where (FolderPath contains ":\\Users\\All Users\\" or FolderPath contains ":\\Users\\Contacts\\" or FolderPath contains ":\\Users\\Default\\" or FolderPath contains ":\\Users\\Public\\" or FolderPath contains ":\\Users\\Searches\\") and (not((FolderPath contains "\\AppData\\" and AccountName =~ "SYSTEM")))



# Function to validate email format
function Validate-Email {
    param (
        [string]$Email
    )
    return $Email -match '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
}

# Function to sanitize and validate input
function Sanitize-Records {
    param (
        [array]$Records
    )
    
    $sanitizedRecords = @()

    foreach ($record in $Records) {
        # Trim whitespace
        $record.Name = $record.Name.Trim()
        $record.Name1 = $record.Name1.Trim()
        $record.Name2 = $record.Name2.Trim()
        $record.Name3 = $record.Name3.Trim()

        # Validate email format
        if (-not (Validate-Email -Email $record.EmailAddress)) {
            Write-Host "Invalid email address: $($record.EmailAddress)" -ForegroundColor Red
            continue
        }

        # Add to sanitized records if all checks pass
        $sanitizedRecords += $record
    }

    return $sanitizedRecords
}




```


// name: World Writable Execution - Non-Temp System Subdirectory
// description: Detect process execution from a world writable location in a subdirectory of the Windows OS install location.
// author: ASD's ACSC
DeviceProcessEvents
| where FolderPath has_any (
    ":\\$Recycle.Bin\\", ":\\AMD\\Temp\\", ":\\Intel\\", ":\\PerfLogs\\", ":\\Windows\\addins\\",
    ":\\Windows\\appcompat\\", ":\\Windows\\apppatch\\", ":\\Windows\\AppReadiness\\", ":\\Windows\\bcastdvr\\",
    ":\\Windows\\Boot\\", ":\\Windows\\Branding\\", ":\\Windows\\CbsTemp\\", ":\\Windows\\Containers\\",
    ":\\Windows\\csc\\", ":\\Windows\\Cursors\\", ":\\Windows\\debug\\", ":\\Windows\\diagnostics\\",
    ":\\Windows\\DigitalLocker\\", ":\\Windows\\dot3svc\\", ":\\Windows\\en-US\\", ":\\Windows\\Fonts\\",
    ":\\Windows\\Globalization\\", ":\\Windows\\Help\\", ":\\Windows\\IdentityCRL\\", ":\\Windows\\IME\\",
    ":\\Windows\\ImmersiveControlPanel\\", ":\\Windows\\INF\\", ":\\Windows\\intel\\", ":\\Windows\\L2Schemas\\",
    ":\\Windows\\LiveKernelReports\\", ":\\Windows\\Logs\\", ":\\Windows\\media\\", ":\\Windows\\Migration\\",
    ":\\Windows\\ModemLogs\\", ":\\Windows\\ms\\", ":\\Windows\\OCR\\", ":\\Windows\\panther\\",
    ":\\Windows\\Performance\\", ":\\Windows\\PLA\\", ":\\Windows\\PolicyDefinitions\\", ":\\Windows\\Prefetch\\",
    ":\\Windows\\PrintDialog\\", ":\\Windows\\Provisioning\\", ":\\Windows\\Registration\\CRMLog\\",
    ":\\Windows\\RemotePackages\\", ":\\Windows\\rescache\\", ":\\Windows\\Resources\\", ":\\Windows\\SchCache\\",
    ":\\Windows\\schemas\\", ":\\Windows\\security\\", ":\\Windows\\ServiceState\\", ":\\Windows\\servicing\\",
    ":\\Windows\\Setup\\", ":\\Windows\\ShellComponents\\", ":\\Windows\\ShellExperiences\\", ":\\Windows\\SKB\\",
    ":\\Windows\\TAPI\\", ":\\Windows\\Tasks\\", ":\\Windows\\TextInput\\", ":\\Windows\\tracing\\",
    ":\\Windows\\Vss\\", ":\\Windows\\WaaS\\", ":\\Windows\\Web\\", ":\\Windows\\wlansvc\\",
    ":\\Windows\\System32\\Com\\dmp\\", ":\\Windows\\System32\\FxsTmp\\", ":\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys\\",
    ":\\Windows\\System32\\Speech\\", ":\\Windows\\System32\\spool\\drivers\\color\\", ":\\Windows\\System32\\spool\\PRINTERS\\",
    ":\\Windows\\System32\\spool\\SERVERS\\", ":\\Windows\\System32\\Tasks_Migrated\\Microsoft\\Windows\\PLA\\System\\",
    ":\\Windows\\System32\\Tasks\\", ":\\Windows\\SysWOW64\\Com\\dmp\\", ":\\Windows\\SysWOW64\\FxsTmp\\",
    ":\\Windows\\SysWOW64\\Tasks\\"
)
| where not (FolderPath contains "\\AppData\\" and AccountName =~ "SYSTEM")

