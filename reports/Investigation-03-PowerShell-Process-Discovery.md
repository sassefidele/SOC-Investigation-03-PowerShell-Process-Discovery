# Investigation Report — SOC-INV-003

**Case:** PowerShell Process Discovery Detection  
**Date:** November 23, 2026  
**Endpoint:** `SOC-WIN11-01` (Windows 11 ARM64)  
**SIEM:** Wazuh on `wazuh-siem-01` (Ubuntu Server)  
**Disposition:** Benign, authorized test; detection pipeline validated

## 1. Alert summary

A PowerShell script block containing `Get-Process` and `Get-LocalUser` was recorded on the endpoint and forwarded to Wazuh. The Wazuh manager emitted rule **91815** (level **4**), **“Powershell executing process discovery,”** with MITRE ATT&CK mapping **T1057 — Process Discovery**.

**Validated alert time (UTC):** `2026-11-23T14:33:49.690+0000`  
**Windows Event ID:** `4104`  
**Script Block ID:** `91505d99-e924-4d7f-9c9c-ca3d9b3f1d93`

## 2. Questions investigated

- Was the PowerShell activity captured on the endpoint? **Yes.**
- Did the Wazuh agent initially collect the PowerShell Operational channel? **No; the configuration listing did not include it.**
- Did adding the channel result in Wazuh alert ingestion? **Yes.**
- Did the alert correspond to the controlled test script? **Yes; the script block included the unique validation marker.**
- Does this indicate malicious execution? **No; the activity was deliberately generated as a test.**

## 3. Test procedure and artifacts

### Local logging validation

The registry setting `EnableScriptBlockLogging` was observed with value `1`. A local `Get-WinEvent` query returned PowerShell Operational Event ID 4104 records.

### Test execution

```powershell
$LabMarker = "SOC-INV-003-WAZUH-VALIDATION"
Write-Output $LabMarker
Get-LocalUser | Select-Object Name, Enabled
Get-Process | Select-Object -First 5 Name, Id
```

### Ingestion troubleshooting

An initial manager search for agent `SOC-WIN11-01` and event `4104` returned no alert matches. The Windows Wazuh agent's `ossec.conf` was inspected: it contained Application, Security, System, and Sysmon channels but not `Microsoft-Windows-PowerShell/Operational`. After backing up the file, the PowerShell Operational channel was added as `eventchannel`, and `WazuhSvc` was restarted and observed running.

### Wazuh verification

A later `alerts.json` search returned event 4104 alerts. The validation script appeared in the `scriptBlockText` field of a rule 91815 alert. A Wazuh Threat Hunting screenshot shows one rule 91815 hit in the selected 24-hour window. The dashboard's count is scoped to its filters and time range, not a lifetime event total.

## 4. Key evidence fields

| Attribute | Value |
|---|---|
| `agent.name` | `SOC-WIN11-01` |
| `data.win.system.eventID` | `4104` |
| `data.win.system.channel` | `Microsoft-Windows-PowerShell/Operational` |
| `rule.id` | `91815` |
| `rule.level` | `4` |
| `rule.description` | `Powershell executing process discovery` |
| `rule.mitre.id` | `T1057` |
| `data.win.eventdata.scriptBlockId` | `91505d99-e924-4d7f-9c9c-ca3d9b3f1d93` |
| Lab marker | `SOC-INV-003-WAZUH-VALIDATION` |

## 5. ATT&CK interpretation

The process enumeration command `Get-Process` aligns with **T1057 — Process Discovery**. The script also enumerates local users, but the verified rule 91815 alert specifically mapped to T1057. Additional observed rule 91816 alerts mapped to T1082; those are separate observations and were not conclusively attributed to the validation script.

## 6. Triage and conclusion

**Observed:** Script Block Logging captured commands and Wazuh produced a rule 91815 alert.  
**Context:** The analyst executed the commands intentionally in a controlled lab.  
**Assessment:** Benign authorized activity; the detection pipeline functioned as intended.  
**Limitations:** This test does not prove detection of every PowerShell technique, malicious intent, or end-to-end alert response in production. No automated response was validated.

In a real SOC, additional triage would inspect initiating account, PowerShell parent process, nearby authentication events, script origin, command-line history, and whether execution was approved.

## 7. Lessons learned

1. Endpoint logging alone does not guarantee SIEM visibility; event-channel collection must be configured.
2. Search scope matters: `alerts.json` contains alerts, not necessarily every collected event.
3. A unique test marker helps correlate local events with forwarded SIEM records.
4. ATT&CK mappings describe behavioral similarity, not proof of an attack.

## 8. Evidence index

See the repository [README evidence table](../README.md#evidence) and numbered files in [`screenshots/`](../screenshots/).
