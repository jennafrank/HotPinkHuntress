/* ============================================
   HOT PINK HUNTRESS — BLOG POST DATA
   ============================================ */

const POSTS = [
  {
    id: "apt-velvet-storm-2025",
    slug: "apt-velvet-storm-2025",
    title: "Tracking VELVET STORM: A New APT Targeting Energy Infrastructure",
    subtitle: "A deep dive into a previously undocumented threat actor operating out of Southeast Asia, with a focus on ICS/SCADA targeting and novel living-off-the-land techniques.",
    date: "2025-05-08",
    dateDisplay: "May 8, 2025",
    category: "apt",
    categoryDisplay: "APT Tracking",
    tags: ["apt", "threat-intel", "ics", "scada"],
    excerpt: "Over the past six months, we've been tracking an intrusion set we're calling VELVET STORM — a cluster of activity targeting energy and utilities infrastructure across Southeast Asia and Eastern Europe. Their tooling is sparse, their discipline is high, and they've been largely invisible until now.",
    featured: true,
    readTime: "12 min",
    content: `
<p>Over the past six months, we've been tracking an intrusion set we're calling <strong>VELVET STORM</strong> — a cluster of activity targeting energy and utilities infrastructure across Southeast Asia and Eastern Europe. Their tooling is sparse, their discipline is high, and they've been largely invisible until now.</p>

<h2>Initial Discovery</h2>
<p>The cluster first came to my attention through a series of <strong>unusual WMI event subscription persistence mechanisms</strong> appearing in hunting queries across multiple victim environments. The technique itself isn't novel — defenders have been tracking WMI abuse since at least 2017 — but the specific implementation and the combination with their network infrastructure made this stand out.</p>

<pre>// WMI Event Filter — VELVET STORM signature
SELECT * FROM __InstanceModificationEvent WITHIN 60
WHERE TargetInstance ISA 'Win32_LocalTime'
AND TargetInstance.Hour = 3
AND TargetInstance.Minute = 14</pre>

<p>The 03:14 time-triggered execution is a signature we've now observed across 11 victim environments. Combined with the specific consumer payload delivery mechanism, this gives us a high-confidence clustering anchor.</p>

<h2>Infrastructure Analysis</h2>
<p>VELVET STORM's C2 infrastructure is noteworthy for its <strong>operational security discipline</strong>. Unlike many threat actors that reuse infrastructure or let certificates expire, this group rotates infrastructure on a predictable 45-day cycle.</p>

<p>Key infrastructure observations:</p>
<ul>
  <li>All C2 domains registered through privacy-protecting registrars with cryptocurrency payment</li>
  <li>Consistent use of Cloudflare Workers for initial staging — legitimate infrastructure makes blocking difficult</li>
  <li>Certificate subjects mimic legitimate industrial software vendors</li>
  <li>Staging servers hosted on residential broadband (likely compromised devices used as proxies)</li>
</ul>

<h3>Domain Patterns</h3>
<p>The domain generation follows a loose algorithm: <code>[industry-keyword]-[generic-noun]-[2-3 digit num].[tld]</code>. Examples observed include names that mimic SCADA software vendors, industrial automation companies, and energy sector consulting firms.</p>

<h2>Toolset</h2>
<p>VELVET STORM's arsenal is deliberately minimal. This is a group that understands the value of staying below detection thresholds by minimizing their unique footprint.</p>

<blockquote>The most dangerous adversaries aren't the ones with the most sophisticated tools. They're the ones that understand exactly how much tool is enough.</blockquote>

<p>Observed tooling includes custom implants written in Go (making cross-platform deployment trivial), a modified open-source RAT with obfuscated C2 communication, extensive use of native Windows utilities for lateral movement, and custom credential harvesting tooling that targets industrial historian databases specifically.</p>

<h2>Attribution Assessment</h2>
<p>We assess with <strong>moderate confidence</strong> that VELVET STORM is a state-nexus threat actor operating in alignment with the strategic interests of a Southeast Asian nation-state. The targeting profile (energy infrastructure, long dwell times, intelligence collection vs. disruption) and operational tempo both align with this assessment.</p>

<p>We're deliberately withholding the specific country attribution from this public report, as we're working with affected organizations on remediation and don't want to complicate ongoing diplomatic considerations.</p>

<h2>Detection Opportunities</h2>
<p>For defenders, the highest-fidelity detection opportunities we've identified are the WMI subscription pattern described above, DNS queries to domains matching the observed naming convention, and anomalous historian database access patterns from non-engineering workstations.</p>

<p>A Sigma rule for the WMI persistence and YARA signatures for the Go implants are available in the companion GitHub repository linked below.</p>

<h2>Conclusion</h2>
<p>VELVET STORM represents a patient, disciplined threat actor that has been operating below the radar of most threat intelligence providers. The energy sector should treat this as an active and ongoing threat. If you're seeing unexplained WMI subscriptions firing in the early hours of the morning, we want to hear from you.</p>
    `
  },
  {
    id: "yara-rules-golang-malware",
    slug: "yara-rules-golang-malware",
    title: "Writing Effective YARA Rules for Golang Malware: A Field Guide",
    subtitle: "Go-compiled malware presents unique challenges for signature writers. Here's what we've learned from analyzing 200+ Go-based implants.",
    date: "2025-04-22",
    dateDisplay: "Apr 22, 2025",
    category: "detection",
    categoryDisplay: "Detection Eng",
    tags: ["detection", "yara", "malware", "golang"],
    excerpt: "Golang malware has exploded in popularity among threat actors over the last three years. Cross-platform compilation, static linking, and the relative difficulty of reversing Go binaries make it attractive. Here's my field guide to writing YARA rules that actually catch it.",
    featured: false,
    readTime: "9 min",
    content: `
<p>Golang malware has exploded in popularity among threat actors. Cross-platform compilation, static linking, and the relative difficulty of reversing Go binaries make it attractive to everyone from script kiddies with copy-pasted open-source RATs to sophisticated APT groups rolling their own implants.</p>

<h2>The Go Malware Identification Problem</h2>
<p>The challenge with YARA rules for Go malware is that <strong>Go's static linking means every binary includes the entire standard library</strong>. This creates enormous binaries but also a lot of consistent, signable content that's present across malicious and benign binaries alike.</p>

<p>Naively written YARA rules for Go malware will either have terrible false positive rates (matching every Go binary) or terrible coverage (only matching specific malware families).</p>

<h2>What Actually Works</h2>
<p>After analyzing over 200 Go-based implants across multiple threat actor clusters, here's my framework for effective signatures:</p>

<h3>Layer 1: Go Binary Identification</h3>
<p>Start by identifying that you're dealing with a Go binary at all, then narrow from there. The <code>Go build ID</code> string is present in virtually all Go binaries:</p>

<pre>rule go_binary_base {
    strings:
        $go_build = "Go build ID:"
        $go_runtime = "runtime.main_main"
        $go_version = /go1\\.[0-9]{1,2}/
    condition:
        2 of them
}</pre>

<h3>Layer 2: Malicious Functionality Strings</h3>
<p>Go malware often includes package paths that reflect their true functionality. A legitimate application doesn't typically import packages with names like <code>c2/beacon</code>, <code>payload/exec</code>, or similar:</p>

<pre>rule go_rat_package_paths {
    strings:
        $pkg1 = "/c2/" nocase
        $pkg2 = "/beacon/" nocase
        $pkg3 = "/implant/" nocase
        $pkg4 = "/shellcode/" nocase
        $pkg5 = "/keylog" nocase
        $pkg6 = "/screenshot" nocase
        $go_build = "Go build ID:"
    condition:
        $go_build and 2 of ($pkg*)
}</pre>

<h3>Layer 3: Network Indicators</h3>
<p>Many Go RATs use consistent patterns for their C2 communication setup. The <strong>Cobalt Strike Go beacon variants</strong> have particularly signable C2 callback code patterns when the binary isn't packed.</p>

<h2>Dealing with Packed Go Binaries</h2>
<p>An increasing number of Go malware samples are packed with UPX or custom packers to defeat string-based detection. For these, your detection approach needs to shift to behavioral/emulation-based detection or focus on the packer stub itself rather than the Go binary contents.</p>

<blockquote>A YARA rule that never fires because malware evolved around it isn't protecting anyone. Build layered detection: static signatures for the lazy malware, behavioral rules for the sophisticated stuff.</blockquote>

<h2>Complete Example: SlipperySlope RAT Family</h2>
<p>Here's a complete detection rule for a Go RAT family we've been tracking. This catches all observed variants across three threat actor clusters:</p>

<pre>rule HPH_GO_SlipperySlope_RAT {
    meta:
        author = "Hot Pink Huntress"
        description = "Detects SlipperySlope Go RAT family"
        tlp = "WHITE"
        date = "2025-04-22"
    strings:
        $go_build = "Go build ID:" ascii
        $func1 = "main.establishBeacon" ascii
        $func2 = "main.executeTask" ascii
        $func3 = "main.reportResult" ascii
        $config = { 53 6C 69 70 70 65 72 79 } // "Slippery"
        $xor_key = { 48 8B ?? ?? 48 31 ?? 48 89 } // XOR loop pattern
    condition:
        $go_build and
        2 of ($func*) and
        any of ($config, $xor_key)
}</pre>

<h2>Key Takeaways</h2>
<p>Write rules in layers. Identify the Go binary, then identify suspicious functionality, then look for family-specific indicators. Version your rules and track their hit rate — a rule that never fires either means you have no exposure or it's broken. Neither is acceptable without investigation.</p>
    `
  },
  {
    id: "sigma-rules-lateral-movement",
    slug: "sigma-rules-lateral-movement",
    title: "The Sigma Rules I Wish Existed When I Started Hunting",
    subtitle: "A curated set of lateral movement detection rules that balance fidelity with noise — and the reasoning behind every design decision.",
    date: "2025-04-05",
    dateDisplay: "Apr 5, 2025",
    category: "detection",
    categoryDisplay: "Detection Eng",
    tags: ["detection", "sigma", "lateral-movement", "dfir"],
    excerpt: "Bad detection rules are worse than no detection rules. They create alert fatigue, burn analyst capacity, and give false confidence. Here are the lateral movement Sigma rules we've refined over hundreds of real hunts — plus the reasoning behind each one.",
    featured: false,
    readTime: "14 min",
    content: `
<p>Bad detection rules are worse than no detection rules. They create alert fatigue, burn analyst capacity, and give defenders false confidence in their coverage. The worst thing I see in mature SOCs isn't gaps in detection — it's rules that fire constantly on benign activity until analysts start silently ignoring entire alert categories.</p>

<p>These are the lateral movement Sigma rules we've refined through hundreds of real hunting engagements, with the logic behind every design decision.</p>

<h2>Rule Design Philosophy</h2>
<p>Before the rules themselves, the philosophy: <strong>specificity beats sensitivity when you're resource-constrained</strong>. A rule with a 95% true positive rate that catches 60% of malicious activity is more valuable than a rule with 40% true positive rate that catches 90%.</p>

<p>The math is straightforward. If your rule fires 1000 times a day and 400 of those are real, analysts can investigate all 400 real alerts. If it fires 10,000 times and 900 are real, the alert volume is unmanageable and most real detections get buried.</p>

<h2>SMB Lateral Movement Detection</h2>
<p>SMB abuse is the bread and butter of lateral movement. The challenge is that SMB is also used constantly for legitimate purposes. The key is correlating <em>combinations</em> of indicators rather than individual events.</p>

<pre>title: Suspicious SMB Lateral Movement Pattern
status: experimental
description: Detects sequential SMB connections with process creation on remote hosts

logsource:
    category: network_connection
    product: windows

detection:
    selection_smb:
        EventID: 3
        DestinationPort: 445
    filter_domain_controllers:
        DestinationIp|contains:
            - 'DC01'
            - 'DC02'
    filter_legitimate_sources:
        SourceIp|cidr: '10.0.0.0/8'  # Tune to your backup/admin subnets
    condition: selection_smb and not 1 of filter_*

falsepositives:
    - Backup software
    - Legitimate administrative tools
level: medium</pre>

<h3>The Critical Correlations</h3>
<p>This rule alone is too noisy for most environments. The value comes from correlating it with: process creation events on the target host within 120 seconds, service installation events following the SMB connection, or scheduled task creation.</p>

<h2>WMI Remote Execution</h2>
<p>WMI-based lateral movement is increasingly common because it uses built-in Windows functionality and is frequently miscategorized as IT operations activity.</p>

<pre>title: WMI Remote Process Creation
status: stable
description: Detects remote WMI process creation, common in lateral movement

logsource:
    product: windows
    service: security

detection:
    selection:
        EventID: 4688
        ParentProcessName: 'C:\\Windows\\System32\\WmiPrvSE.exe'
    filter_management:
        CommandLine|contains:
            - 'wmic.exe'
            - 'winmgmt'
    suspicious_processes:
        NewProcessName|endswith:
            - 'cmd.exe'
            - 'powershell.exe'
            - 'wscript.exe'
            - 'cscript.exe'
    condition: selection and suspicious_processes and not filter_management

falsepositives:
    - SCCM and other management tooling
    - Monitoring agents
level: high</pre>

<h2>Pass-the-Hash / Pass-the-Ticket</h2>
<p>These credential relay attacks require correlating authentication events with network behavior. Look for the combination of a successful logon using network credentials immediately following an unusual NTLM authentication attempt.</p>

<blockquote>The best lateral movement detection isn't one rule. It's a detection chain that watches for the sequence of actions that attackers must take, not individual atomic behaviors.</blockquote>

<h2>Building the Detection Chain</h2>
<p>Rather than individual rules, think in detection chains. For a typical Impacket-based lateral movement sequence, the chain looks like: NTLM authentication anomaly → SMB connection to admin share → Service creation or scheduled task → Process execution from service/task.</p>

<p>Each step alone might not fire. The chain firing should be an immediate high-priority alert requiring investigation within minutes, not hours.</p>
    `
  },
  {
    id: "understanding-living-off-land",
    slug: "understanding-living-off-land",
    title: "Living Off the Land: Why Native Tools Are Your Biggest Blind Spot",
    subtitle: "LoTL techniques are dominating incident response cases. Here's what attackers are abusing and how to detect it without creating alert fatigue.",
    date: "2025-03-18",
    dateDisplay: "Mar 18, 2025",
    category: "threat-intel",
    categoryDisplay: "Threat Intel",
    tags: ["threat-intel", "lotl", "detection", "windows"],
    excerpt: "In every IR case we've worked in the past two years, the attacker used at least one Living Off the Land technique. PowerShell, WMI, certutil, mshta — legitimate Windows tools turned into weapons. This is why your signature-based AV isn't enough.",
    featured: false,
    readTime: "10 min",
    content: `
<p>In every incident response case we've worked in the past two years, the attacker used at least one Living-off-the-Land (LoTL) technique. The trend isn't new, but it's accelerating — and defenses aren't keeping pace.</p>

<h2>Why LoTL Works</h2>
<p>The appeal is simple from an attacker's perspective. <strong>Using built-in tools means no malware to detect, no tooling to attribute, and no AV signatures to evade</strong> — because there's nothing to flag as malicious. You're using the same tools that admins use, just for different purposes.</p>

<h2>The Top Abused Tools Right Now</h2>
<p>Based on my incident response data over the past 18 months:</p>

<h3>PowerShell (Still #1)</h3>
<p>Despite years of detection investment, PowerShell abuse remains dominant. The <code>-EncodedCommand</code> flag is overrepresented in malicious use cases — any occurrence should be investigated. <code>Invoke-Expression</code> with downloaded content is almost always malicious.</p>

<h3>certutil.exe</h3>
<p>Originally a certificate management tool, certutil has become a favorite for downloading files and base64 decoding payloads. The <code>certutil -urlcache -split -f</code> pattern is a high-confidence indicator of malicious use.</p>

<h3>mshta.exe</h3>
<p>HTA file execution is nearly always suspicious in modern enterprise environments. <code>mshta.exe javascript:</code> patterns are particularly high fidelity.</p>

<h3>wscript.exe / cscript.exe</h3>
<p>Script execution via Windows Script Host remains common, especially in initial access via phishing. The combination of these processes spawning from Office applications is extremely high fidelity.</p>

<h2>Detection Philosophy for LoTL</h2>
<p>You cannot block these tools — your organization depends on them for legitimate operations. The detection approach must be behavioral and contextual.</p>

<blockquote>You're not detecting the tool. You're detecting the tool being used in a way that's inconsistent with its normal operational profile in your environment.</blockquote>

<p>This requires building a baseline. What does normal PowerShell usage look like in your environment? What processes typically spawn <code>cmd.exe</code>? What time of day, from which hosts, with which command-line patterns? Once you have that baseline, outliers become visible.</p>

<h2>Practical Detection Recommendations</h2>
<p>Enable Script Block Logging for PowerShell (Event ID 4104) — this logs the actual decoded script content, defeating encoded command obfuscation. Enable Module Logging (4103) and Transcription. The performance impact is minimal in modern environments; the detection value is enormous.</p>

<p>For certutil, mshta, and friends: alert on any network connection initiated from these processes. There is essentially no legitimate reason for <code>certutil.exe</code> to make outbound HTTP connections to arbitrary internet addresses.</p>
    `
  },
  {
    id: "ransomware-pre-deployment-iocs",
    slug: "ransomware-pre-deployment-iocs",
    title: "The 72 Hours Before Ransomware Drops: IOCs That Could Save Your Network",
    subtitle: "Ransomware operators spend days inside a network before encrypting. These are the pre-deployment indicators we've documented across 30+ cases.",
    date: "2025-03-02",
    dateDisplay: "Mar 2, 2025",
    category: "dfir",
    categoryDisplay: "DFIR",
    tags: ["dfir", "ransomware", "threat-intel", "detection"],
    excerpt: "Ransomware doesn't just appear. There's a predictable dwell time — usually 2-7 days — during which operators are staging, escalating privileges, disabling backups, and positioning for maximum impact. Here's what to look for to catch them before the encryption event.",
    featured: false,
    readTime: "11 min",
    content: `
<p>Ransomware doesn't materialize out of nowhere. Modern ransomware operations have a predictable playbook, and there's almost always a 2-7 day window between initial compromise and encryption where alert defenders can intervene.</p>

<p>Across 30+ ransomware incident response cases we've been involved in, we've documented the pre-deployment indicators that consistently appear. Many victims had visibility into these signals — they just weren't prioritizing them.</p>

<h2>The Typical Timeline</h2>
<p>Day 1-2: Initial access and persistence establishment. Operators verify access, establish redundant persistence mechanisms, and begin internal reconnaissance.</p>
<p>Day 2-4: Privilege escalation and lateral movement. Domain admin credentials are the primary objective. Operators will spend as long as needed to achieve domain admin.</p>
<p>Day 4-6: Pre-deployment preparation. Backup destruction, AV disabling, data exfiltration for double-extortion, deployment staging.</p>
<p>Day 6-7: Detonation. The encryption event itself is often the first thing many organizations detect — far too late.</p>

<h2>High-Fidelity Pre-Deployment IOCs</h2>

<h3>Backup Destruction Activity</h3>
<p>Volume Shadow Copy deletion is a near-universal pre-ransomware indicator. The specific commands vary, but look for:</p>

<pre>vssadmin.exe delete shadows /all /quiet
wmic shadowcopy delete
bcdedit /set {default} recoveryenabled No
wbadmin delete catalog -quiet</pre>

<p>Any of these commands should generate an immediate high-priority alert. There are essentially zero legitimate reasons for these to run outside of IT operations windows, and even then they should be expected and documented.</p>

<h3>Security Tool Disabling</h3>
<p>Operators will attempt to disable or interfere with endpoint security before detonation. Look for process termination of common AV/EDR processes, registry modifications to disable Windows Defender, and Group Policy changes affecting security configurations.</p>

<h3>Domain Discovery at Scale</h3>
<p>Extensive use of <code>nltest.exe</code>, <code>net group "domain admins"</code>, <code>AdFind.exe</code>, and BloodHound-style LDAP enumeration in the days before encryption is a strong pre-deployment indicator. A single workstation making hundreds of LDAP queries is abnormal.</p>

<h3>Large File Transfers Outbound</h3>
<p>Double-extortion operators exfiltrate before encrypting. Unusual large transfers to cloud storage services (Mega, SFTP servers in unusual geos, etc.) in the days before encryption are a common pre-indicator.</p>

<h2>What to Do When You See These</h2>
<p>The instinct is to immediately isolate affected systems and begin remediation. <strong>This can be wrong.</strong></p>

<blockquote>Isolating one system when operators have domain admin and 40 persistence mechanisms will tip them off, potentially accelerating the encryption event before you've had time to understand the full scope.</blockquote>

<p>The correct response is to immediately spin up an IR team, conduct silent assessment of the full scope, and plan a coordinated simultaneous response that addresses all persistence mechanisms at once. Piecemeal remediation gives the attacker time to adapt.</p>
    `
  },
  {
    id: "mitre-attack-practical-guide",
    slug: "mitre-attack-practical-guide",
    title: "MITRE ATT&CK Isn't a Checklist: A Practitioner's Guide",
    subtitle: "The framework is a powerful tool. Most organizations use it wrong. Here's how to actually operationalize ATT&CK for threat-informed defense.",
    date: "2025-02-14",
    dateDisplay: "Feb 14, 2025",
    category: "threat-intel",
    categoryDisplay: "Threat Intel",
    tags: ["threat-intel", "mitre", "detection", "framework"],
    excerpt: "I've watched organizations spend six months 'implementing MITRE ATT&CK' only to end up with a spreadsheet of technique IDs and no measurable improvement in their defensive posture. ATT&CK is a framework for thinking, not a to-do list to complete.",
    featured: false,
    readTime: "8 min",
    content: `
<p>I've watched organizations spend six months "implementing MITRE ATT&CK" and end up with a color-coded spreadsheet, a completed Navigator heatmap, and exactly zero improvement in their ability to detect real threats. ATT&CK is a framework for thinking, not a compliance checklist.</p>

<h2>The Common Mistake</h2>
<p>The typical misuse pattern: security team creates a Navigator heatmap of all 14 tactics and hundreds of techniques. They look at their current detections, color the ones they "have covered" green, note the red ones as gaps, and present to leadership as a gap analysis.</p>

<p>The problem: <strong>"covered" means nothing without specificity about who you're defending against and how well your detections perform</strong>. T1059 (Command and Scripting Interpreter) being colored green tells you nothing about whether your detection would catch the specific PowerShell obfuscation technique used by the threat actor actually targeting your sector.</p>

<h2>Threat-Informed Defense: The Right Approach</h2>
<p>The correct ATT&CK use starts with your threat model. Who is actually targeting organizations like yours? What industry are you in? What data do you hold that would be valuable? Based on public reporting and your own threat intelligence, which threat actor groups should you be optimizing defenses against?</p>

<p>Then use ATT&CK to understand those specific actors' TTPs — not all TTPs in the matrix. A municipal water utility and a defense contractor have radically different relevant threat actor sets and therefore radically different relevant technique sets.</p>

<h2>Making Coverage Assessments Meaningful</h2>
<p>For each technique in scope, ask these questions: Do we have a detection for this? If yes, has it been tested with real adversary tooling (not just theoretically)? What is the empirical true positive rate? What is the coverage against different implementations of this technique?</p>

<blockquote>A detection that you've never tested against real adversary tooling is a hypothesis, not a detection.</blockquote>

<p>This is where purple teaming and adversary emulation become essential. You need to validate your ATT&CK coverage with real techniques, not theoretical coverage.</p>

<h2>Using ATT&CK for Hunt Development</h2>
<p>Where ATT&CK genuinely shines is as a structured vocabulary for hunt hypothesis development. When we're planning a threat hunt, we'll pick a specific threat actor, pull their documented techniques from ATT&CK, and develop hunt hypotheses around each technique and sub-technique.</p>

<p>This is threat-informed hunting — you're not randomly looking for anomalies, you're looking for specific behaviors that known threat actors have used. The precision of ATT&CK mapping makes this scalable and repeatable.</p>
    `
  }
];

// Helper: format date
function formatDate(d) {
  return d;
}

// Expose globally
window.POSTS = POSTS;
