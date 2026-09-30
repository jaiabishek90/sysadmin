# Sys@dmin v4.5.1 — Windows Endpoint Diagnostics Console

A self-contained WPF desktop app (Windows PowerShell 5.1 + XAML, **zero external modules**) that reads Windows event logs, **explains what each error means and how to fix it**, and adds Network, Certificate, Intune/MDM and Group Policy analysis — with native charts, severity colour coding, and a **fully resizable, responsive layout**.

![alt text](https://github.com/jaiabishek90/sysadmin/blob/main/images/dashboard.png)
---

## 1. Files

| File | Purpose |
|---|---|
| `EndpointDiagX.ps1` | WPF user interface — 8 tabs on a left sidebar, 100 functions |
| `DiagEngine.ps1` | Data-collection + analysis engine, 76 functions (reusable headless) |
| `KnowledgeBase.json` | 75 event-signature rules + 12 text rules → cause, impact, steps, commands, docs |
| `Launch-EndpointDiagX.cmd` | Launcher (`-STA`, `ExecutionPolicy Bypass`, self-elevates) |
| `Build-EndpointDiagX.ps1` | Compiles to `.exe` via PS2EXE and stages the runtime files |
| `README.md` | This file |

**All runtime files must stay in the same folder.**

---

## 2. Run it

Right-click **`Launch-EndpointDiagX.cmd`** → **Run as administrator**.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File .\EndpointDiagX.ps1
.\EndpointDiagX.ps1 -SkipAutoScan    # open without auto-scanning
.\EndpointDiagX.ps1 -NoElevate       # stay in the current token
```

> **Elevation matters.** Without admin you lose the Security log, the LocalMachine certificate store, **firewall rules**, `gpresult /scope:computer`, MDM enrollment keys and every repair action.

**Requirements:** Windows 10/11 or Server 2016+, Windows PowerShell 5.1, .NET Framework 4.7.2+.

---

## 3. Fixes in v4.5.1

### Four grids were bound to properties that do not exist — my regression

Rebuilding the Intune tab in v4.5, I retyped the `DataGrid` column bindings
from memory instead of carrying the originals across. A WPF binding to a
missing property renders **blank and throws nothing**, so it looked exactly
like a collector problem:

| grid | bound to | producer actually emits |
|---|---|---|
| `gridImeLogs` | Severity, File, Title, Line | Time, Severity, **LogFile**, **Message** |
| `gridPsScripts` | Result | **State** (and `Detail` had been dropped) |
| `gridRemediations` | Result | **State** (and `Executions` had been dropped) |

All three are restored to the pre-v4.5 bindings. The verification pass now
checks every column binding against the property names its producer emits,
which is the check that would have caught this before it shipped.

### Registry reads now enumerate instead of guessing

![alt text](https://github.com/jaiabishek90/sysadmin/blob/main/images/events.png)

Win32 app State, Error, Targeting and Complete were all blank while Scope and
App ID populated — the giveaway that every *registry-sourced* column failed
while every *key-name-sourced* column worked. A named read (`Get-ItemProperty
-Name X`) cannot distinguish "wrong name" from "no value", so it fails silently
and gives you nothing to chase.

Both the Win32 and MSI/LOB collectors now read the whole key with
`Get-DxRegValueMap`, try a list of candidate names via `Get-DxRegValueAny`,
descend one level into subkeys if the key itself is bare, and expose a
**Values found** column listing the value names actually present. If the layout
shifts again, the grid shows you what is there instead of going quietly blank.

### Scope column showed raw identifiers

Three shapes appear as a scope key and only one is a real SID.
`S-0-0-00-0000000000-...` is the device-context placeholder
`EnterpriseDesktopAppManagement` writes — it starts with `S-` so it survived the
old all-zeros test. `e3dc27d5-4452-...` is an Entra user **object ID**, which
newer IME builds use instead of a SID and `Translate()` will never resolve.
Both are now labelled rather than printed raw.

### Sync health claimed "Healthy" with no evidence

![alt text](https://github.com/jaiabishek90/sysadmin/blob/main/images/systemhealth.png)

The session query also no longer pre-filters on event IDs 208/209/201/202. Asking
for IDs that may not be emitted and getting nothing proves only that those IDs
were absent; it now reads the channel log and classifies what is actually
present.

### Also restored

Both `.ps1` files were being written with a UTF-8 BOM the originals did not
have, and `DiagEngine.ps1` had been flipped from LF to CRLF — a whole-file diff
against your original for no reason. Both files are back to LF, no BOM. Content
is pure ASCII, so the BOM bought nothing.

---

## 4. What changed in v4.5

### Intune / MDM rebuilt around why it is broken, not what is configured

![alt text](https://github.com/jaiabishek90/sysadmin/blob/main/images/Intune.png)

`Get-DxIntuneState` already answered *what is configured* — enrolment, certs,
Win32 apps, scripts, tasks — and it stays untouched. The new
`Get-DxIntuneDeep` answers the different question that most tickets actually
turn on, through seven new engine collectors:

| collector | answers |
|---|---|
| `Get-DxMdmSyncHealth` | when OMA-DM last **completed**, staleness verdict, session history |
| `Test-DxIntuneEndpoints` | can this device reach the service on TCP 443, from SYSTEM |
| `Get-DxMdmCertificates` | MDM management cert **and** Entra device cert, expiry, private key |
| `Get-DxAutopilotState` | Autopilot profile, ESP completion, provisioning events |
| `Get-DxManagedApps` | MSI/LOB apps, which travel a different path from Win32 |
| `Get-DxIntuneTimeline` | one chronological merge of every MDM signal |
| `Get-DxIntuneDeep` | composes them, scores the result, returns a verdict |

Four judgements worth stating, because they are the difference between a
diagnostic and a dashboard:

**"Last sync" is the most misread field in Intune support.** The scheduled
task's `LastRunTime` says the task *fired*, not that a session *completed* — a
device with a broken channel shows a recent `LastRunTime` forever. The
authoritative signal is the OMA-DM session result in the event log, so that is
what the KPI reports, with the task attempt shown separately beside it.

**Endpoint probes are TCP 443, never ping.** These endpoints drop ICMP by
design, so ping produces confident false negatives. They also run from SYSTEM
context, because the IME and the OMA-DM client do not use a per-user proxy —
which is why a device that browses fine can still be unable to sync. The
WinHTTP proxy for SYSTEM is printed underneath the results.

**Two certificates, routinely confused.** `MS-Organization-Access` is the Entra
*device* certificate that the PRT and Conditional Access depend on;
`Microsoft Intune MDM Device CA` is the *management* certificate the OMA-DM
channel depends on. Losing either produces a different failure, so both are
reported with days-remaining and a private-key check.

**MSI/LOB apps were invisible.** They travel through
`EnterpriseDesktopAppManagement`, not the IME, so a missing LOB app looked like
nothing had ever been assigned. They now have their own view with decoded
status codes.

The tab itself: six KPI cards (management health score, last good sync, MDM
certificate days, endpoints reachable, apps failing, scripts failing), the
enrolment grid and a merged findings list, then twelve sub-tabs — Sync health,
Service endpoints, Certificates, Win32 apps, MSI/LOB apps, PowerShell scripts,
Remediations, Autopilot and ESP, MDM sync tasks, MDM channel events, IME log
findings, Activity timeline.

Every existing `x:Name` was carried across unchanged, so `Update-DxIntuneTab`
keeps populating its grids exactly as before and the new views layer on top.
**Deep diagnostics** and **Test service endpoints** re-run the new work on its
own; the full scan collects it too. Endpoint probes run in the background
runspace — seven TCP connects with a 3s ceiling each would visibly freeze the
UI thread on a bad network.

---

## 5. What changed in v4.4

### Dashboard rebuilt around representation, not availability

Two things were wrong with it. Four of the six KPI cards were
Critical/Error/Warning/Info counts — **the same four numbers the severity
donut's legend already prints**, so two-thirds of the KPI strip restated one
chart. And nothing added since v4.1 reached the dashboard at all: battery,
storage wear, security posture, memory pressure, driver health, unclean
shutdowns, policy counts. Boolean posture data sat mid-way down a 17-row
key/value grid, where state reads as text rather than as state.

Each metric is now matched to the representation its data type calls for:

| data type | representation | card |
|---|---|---|
| single headline number | big number + grade | Health score |
| part-to-whole | donut + counted legend | Event severity mix |
| ranked comparison | horizontal bars | Top event sources |
| change over time | vertical bars | Events over time |
| % against a ceiling | horizontal bars | Volume headroom |
| binary / categorical | status pills | System at a glance |
| key/value reference | grid | Device |
| scored deductions | grid | Why the score dropped |
| ranked list with drill-through | grid | Top recurring issues |

**Six distinct KPI dimensions** replace the four duplicated counters: health
score, total events (with the severity split as a sub-line), posture roll-up
(`n/m` controls passing, naming the worst), tightest volume, memory in use,
uptime.

**System at a glance** is a new strip of status pills — up to fifteen controls
across Secure Boot, TPM, BitLocker, Defender, HVCI, disk space, memory,
pending reboot, battery wear, SSD wear, unsigned drivers, unclean boots,
certificates, DNS, Intune and policy. Sorted worst-first, because the point of
the strip is what needs attention. Pills are built with `Set-DxRes` rather than
`New-DxBrush`, so they follow a theme switch instead of freezing at whatever
theme was active when the scan ran.

One deliberate restraint in `Get-DxPostureChecks`: only fields whose name *and*
meaning are confirmed become a pass/fail state. Where a collector is present
but its semantics are ambiguous, the check reports **Unknown** rather than
guessing — a confidently green pill that is wrong is worse than an honest grey
one. Firewall is currently omitted from the strip for exactly this reason.

---

## 6. What changed in v4.3

### Navigation moved to a floating left sidebar

![alt text](https://github.com/jaiabishek90/sysadmin/blob/main/images/actions.png)

Done by **re-templating the main `TabControl`**, not by restructuring the window
grid. The header, global toolbar, console rail and status bar are untouched; the
template lays out a rounded rail in column 0 and the content card in column 1.

The one thing that needed care: the sidebar styles are **keyed, not implicit**.
An implicit `TabItem` style in `Window.Resources` — or even in the main
`TabControl`'s own `Resources` — cascades to descendants, and would have
rebuilt all **35 horizontal sub-tabs** inside Network, Policy, Intune and
System Health as vertical rail items. Only the eight top-level items carry
`Style="{StaticResource SideNavItem}"`.

- **Active marker is a left bar**, not an underline. An underline is what makes
  a horizontal strip read as a strip; a vertical rail needs the vertical
  equivalent, plus an accent-soft pill behind the row.
- **Icons follow their item's foreground** via
  `{Binding Foreground, RelativeSource={RelativeSource AncestorType=TabItem}}`,
  so the active icon takes the accent instead of staying grey. `Path.Fill` does
  not inherit from `TextElement.Foreground`, which is why this needs a binding
  rather than a setter.
- **Collapse menu** shrinks the rail to icons only. The rail column is
  `Width="Auto"`, so hiding the labels reflows it with no second measurement
  pass. State persists in `%ProgramData%\Sys@dmin\nav.txt` alongside the theme.
- Every item carries its own label as a **tooltip**, read from the header rather
  than a second hardcoded list that would drift the moment a tab is renamed —
  an icon-only rail is unusable without them.
- Collapsing triggers `Redraw-DxAllCharts`: the content area reflows on its own,
  but the canvases inside it are drawn imperatively and do not.
- Two new palette tokens, `DxNavBg` and `DxNavEdge` (72 per theme now), so the
  rail floats above the canvas in both themes rather than blending into the
  cards.

Keyboard navigation works as before — `TabControl` handles arrow keys — and the
rail items now show a visible focus ring.

---

## 7. What changed in v4.2

### Ten tabs became eight

**Event Analysis + Resolutions → Events.** They were always one workflow read
across two tabs: find the event, then find out what it means. Now sub-tabs of
one tab. The dashboard's top-issues drill-through used to jump to
`SelectedIndex = 2`; it now targets `$UI.tabEvents` and `$UI.tabResolutions` by
name, because a magic index breaks silently the next time a tab is added.

**Group Policy + Policy → Policy.** Both answered "what is configured on this
device"; splitting them meant checking two tabs to find one setting. The merged
tab keeps the Policy CSP KPI strip and merges both toolbars, and the five
Group Policy sub-tabs were lifted into the same flat strip, prefixed `GP` so a
ten-way strip still reads clearly:

| from Policy | from Group Policy |
|---|---|
| Effective settings, Registry policy, Group Policy, Overlaps, Findings | GP conflicts, Applied GPOs, GP extension status, GP events, GP precedence map |

Every `x:Name` was preserved verbatim through both merges — the code-behind
writes to `$UI.<name>` throughout, so a rename would have silently emptied a
grid rather than raising an error. `$UI.tabGpo` no longer exists, so the two
places that lazily filled the GPO grids on tab selection now key off
`$UI.tabPolicy`.

### System Health: hardware and posture

Eight new engine collectors, composed by `Get-DxSystemHealthAdvanced`, each
isolated so a machine with no battery, no TPM or no reliability counters still
returns everything else:

| collector | answers |
|---|---|
| `Get-DxBatteryHealth` | wear %, cycle count, design vs full-charge capacity |
| `Get-DxStorageReliability` | SSD wear, temperature, reallocated sectors, power-on hours, SMART prediction |
| `Get-DxSecurityPosture` | Secure Boot, TPM, VBS/HVCI/Credential Guard, BitLocker per volume, Defender mode and signature age |
| `Get-DxMemoryInventory` | DIMM slots, speed, mixed-speed and single-channel detection, page files |
| `Get-DxTopProcesses` | top consumers by working set and by sampled CPU, handle-leak detection |
| `Get-DxDriverHealth` | unsigned drivers, drivers older than five years, key device classes |
| `Get-DxUptimeHistory` | boot durations, unclean shutdown count, uptime |

New UI: a six-card posture strip (battery wear, disk wear, boot integrity,
VBS/HVCI, encryption, uptime) and seven sub-tabs plus an **Advanced findings**
list, joining the existing four.

Three details worth calling out. Battery **wear** is derived, not reported —
`FullChargedCapacity` and `DesignedCapacity` live in two different `root\wmi`
classes and neither exposes the ratio. CPU percentages come from **two samples
a second apart**, because a single snapshot of processor time is cumulative
since process start and says nothing about now. And the posture view reports
what is **actually on**, not what policy intends: a device with HVCI
*configured but not running* reports as compliant while being unprotected, and
that gap is the whole point of the card.

Cost: the driver inventory (`Win32_PnPSignedDriver`) is slow — tens of seconds
on some machines — and the process sampler deliberately sleeps a second. Both
run in the background runspace, never on the UI thread. The full scan now
quotes 90–180 seconds, and **Run hardware and posture checks** re-runs just
this set.

> **Still not run on Windows.** Statically verified only: the XAML parses, the
> merged tab tree resolves, no `$UI` reference is orphaned, every `Get-Dx*`
> call resolves to a definition, the palettes stay symmetric, and brace,
> paren and bracket balance matches the baseline in both files. Nothing has
> been parse-checked by PowerShell or executed.

---

## 8. What changed in v4.1

### The Policy tab never ran

`Invoke-DxPolicyScan` worked when you clicked **Analyse policy**, but the Policy
tab is Part 11 — appended after `Add_ContentRendered` — and `Invoke-DxFullScan`
was never told about it. The full-scan scriptblock collected
`$gpo = Get-DxGpoState` and stopped: `Get-DxPolicyState` was never called,
`Policy` was absent from the returned object, `$script:Data` had no `Policy`
key, and `Update-DxPolicyTab` was never invoked. Because launch runs a full
scan, the tab was empty at startup *and* after every manual full scan, from the
same omission.

The scan now collects effective policy, reusing the already-gathered `$gpo` so
there is no second `gpresult`. `Policy` was added to the `-Expect` shape list so
`Get-DxJobResult` cannot select a partial object, and the console reports the
CSP / area / GPO / registry counts.

### Dark mode was three faults stacked

**Three brushes were stranded inside an XML comment.** The `<!--` above the
theme block ran past its intended end and its `-->` landed *after* the
declarations for `DxFieldBg`, `DxIconFg` and `DxTabStripBg`. All three existed
in both palettes and were referenced with `{DynamicResource}` — but were never
declared, and an undeclared resource key does not throw. Every text field
background and every vector icon silently stopped following the theme.

**64 hardcoded colours in the XAML.** The loudest was the tab strip: selected
background pinned to `#FFEEF2FF` with `#FF4338CA` text, so in Dark the active
tab was a bright lavender chip with dark indigo text. Also 15 row styles
selecting to literal `White`, all four spotlight KPI cards, the console, status
bar, header gradient and every action button.

**~110 more in the code-behind.** `New-DxBrush` returns a *frozen* brush, so
every ping/lookup/trace/port card and every sparkline was pinned to whatever
theme was current when it was built. `Set-DxTheme` cleared `$script:BrushCache`,
but that only affects future lookups — brushes already assigned to live
controls never changed. `Redraw-DxAllCharts` covered four dashboard canvases
and no card at all.

And one design error underneath all of it: the spotlight KPI cards were pinned
to `#FF0F172A`, *darker* than the dark canvas at `#FF0B1220`. An inverted
surface has to invert its direction too, or it reads as a hole punched in the
page rather than a raised panel. `DxSpotBg` now moves **lighter** than
`DxCardBg` in Dark. The v4 comment asserting these were "dark by design" in
both themes was the bug, and has been corrected.

### The theme system now has one vocabulary

| consumer | how it reads a token |
|---|---|
| XAML | `{DynamicResource DxMuted}` |
| control built at runtime | `Set-DxRes $lbl 'Foreground' 'DxMuted'` |
| canvas / chart | `(Get-DxColor 'DxMuted')` |

- **70 symmetric tokens per theme**; chart colours are derived from the palette
  instead of a second, separately-maintained set of literals that had drifted
  from it
- **`Set-DxRes`** finds the DependencyProperty by reflection, because the right
  one depends on the control: `TextBlock.ForegroundProperty` and
  `Control.ForegroundProperty` are different DPs, and setting the wrong one
  does nothing at all rather than failing
- **`DxOnAccent`** flips with the theme, so text on the accent stays readable
  once the dark accent lightens
- **`Test-DxThemeTokens`** runs at launch and reports any XAML brush with no
  palette backing, or asymmetry between the two palettes — the exact failure
  that hid three brushes inside a comment for a whole release
- Zero hardcoded colours remain in the code-behind; three remain in the XAML,
  all the header gradient's pre-theme defaults, and commented as such

### Detached windows could never be themed

The event-detail and text windows set `.Owner = $window`, but **resource lookup
does not walk the Owner chain** — and with no `Application` object, those child
windows saw an empty dictionary, so any `DynamicResource` in them resolved to
nothing. They now share the parent dictionary.

### Visual refresh

Deeper canvas so white cards actually lift; in Dark, card sits clearly above
canvas. Unified shape scale — cards 12→10, buttons 7→6, and runtime cards were
12 while XAML cards were 10 for the same component. Tabular figures on KPI
values, because those numbers are rewritten live during a scan and
proportional digits make the whole row twitch on every update. Grid rows
23→25px, hairline column headers instead of a double border, visible
keyboard-focus ring on text fields, recessed tab-strip surface so the selected
chip has something to sit against.

No shadows and no animation were added: with 222 controls, 33 splitters and
live canvases, the discipline is worth more than the elevation.

### Knowledge base: 49 → 75 rules, 3 → 12 text rules

Weighted to cloud-managed endpoints — Entra ID token/PRT failures, device
registration, Windows Hello for Business, WDAC/Code Integrity, AppLocker,
Defender for Endpoint onboarding, Windows LAPS, Autopilot/ESP, WNS push
channel, Delivery Optimization, CAPI2 revocation, Kerberos and LSA, DHCP/APIPA,
duplicate IP, WLAN 802.1X, VPN/RasClient, SMB client, BITS, MSI installer,
subscription activation, resource exhaustion, processor throttling, Winlogon
slow-logon subscribers, Intune platform scripts and remediations, and Cloud PC
RDP transport.

Ordering is enforced rather than assumed. Rules with an **empty `eventIds` list
match every id from their providers**, so all nine such rules are pinned to the
end; two new specific rules are pinned *above* the existing set because they
would otherwise be shadowed (`W365-RDPCORE` loses id 226 to `SYS-RDP`, and
`NET-TCPIP-DUPIP` shares the `Tcpip` provider with `SYS-NIC`). A shadow
simulation over all 75 rules confirms every id-scoped rule is reachable.

New rules link to `learn.microsoft.com` **search** URLs rather than deep paths:
a search URL cannot rot, whereas a guessed deep link silently 404s and is worse
than no link at all.

> **Not yet run on Windows.** These changes were made and statically verified
> off-box: the XAML parses, the palettes are symmetric, every `DynamicResource`
> key and every code token resolves, brace/paren/bracket balance matches the
> baseline, and the knowledge base passes its ordering checks. Nothing has been
> parse-checked by PowerShell or executed. The `-STA` launch is the first real
> test — particularly `Set-DxRes`'s reflection lookup and the child-window
> resource sharing.

---

## 9. What changed in v4

### The root cause of the empty tabs — fixed

`Invoke-DxSection` declared its error-log parameter as a **strongly typed** `[List[string]]`. Collectors normalise their error list to a plain array and then call the helper again — passing an `object[]` into a `[List[string]]` parameter throws:

```
ArgumentException: Argument types do not match
```

…thrown at the **call site**, which is why stack traces pointed at whatever innocent statement sat next to the call. One landmine emptied Firewall, DNS, Intune and Group Policy at once.

`$ErrorLog` is now **untyped** and appended through a defensive `Add-DxError` helper that works with `List`, `ArrayList` or `object[]`. No collection type can break it again.

A second, independent bug in the same area: the firewall collector had its **rules query and its port/program enrichment inside one `try/catch`**. `Get-NetFirewallPortFilter` returns thousands of objects and is the fragile part — when it threw, the perfectly good rules were discarded too. Those are now four separate isolated sections, so enrichment can fail and you still get every rule.

### Responsive, resizable layout

Every data tab was rebuilt with **star-sized `Grid` rows and columns plus draggable `GridSplitter` bars**:

- **33 splitters** — drag any divider to resize cards horizontally or vertically
- **31 star-sized rows** — cards grow and shrink with the window
- **24 `MinHeight`/`MinWidth` floors** — nothing collapses to unusable
- **0 fixed `Height=` values on data grids** (was the reason nothing adapted before)
- Charts redraw on resize; toolbars use `WrapPanel` so buttons reflow instead of clipping

Splitter bars highlight indigo on hover and darker while dragging.

### Intune additions

- **Platform PowerShell scripts** — from `IntuneManagementExtension\Policies\<SID>\<GUID>`: state, error code, download count, result detail
- **Remediations** — from `SideCarPolicies\Scripts\Execution`: state, error, last run, execution count, and **pre/post detection output** so you can see whether detection or remediation failed
- **Win32 enforcement state decoded** — `1000` → *Success*, `1002` → *Success (reboot required)*, `5001` → *FAILED (download)*, plus a Targeting column; IME bookkeeping keys filtered out
- SIDs resolved to real account names throughout

### Honest empty results

Empty is now distinguished from broken. On a cloud-only device the tool says:

> *"The Win32Apps registry key exists but contains no application entries — no Win32 apps are assigned to this device or user."*

versus a genuine collector fault, which surfaces as a `SECTION ERROR` naming the exact phase. Group Policy also captures `gpresult`'s own error text — it exits 0 even when it fails, which is why that was previously silent.

### Collector diagnostic

A **Collector diagnostic** button (amber, main toolbar) runs Firewall, DNS, Intune and GPO collection **in-process** on the UI thread, times each one, dumps every returned property with counts, lists section errors, compares against what the UI holds, and prints a verdict. Includes **Apply in-process result** to populate the tabs immediately if the background path is at fault, plus Copy all / Save to file.

---

## 4. The tabs

**Dashboard** — health score with deduction breakdown, severity donut, top event sources, events-over-time bars, device inventory, top recurring issues.

**Event Analysis** — filter by channel, level, text or ID. Double-click any row for the full detail window: rendered message, diagnosis, resolution steps, commands, parsed EventData fields and pretty-printed **raw XML**.

**Resolutions** — events grouped into signatures (provider + event ID), each matched to the knowledge base. Unmatched events get a structured triage workflow rather than a dead end.

**Network** — seven sub-tabs:
- **Firewall** — profile state, active network profiles, filterable rule inventory, rule-mix chart, parsed `pfirewall.log`, blocked connections (audit 5152/5157), findings
- **DNS** — servers, per-server reachability (TCP 53 + ICMP), resolution probes with timing chart, suffixes/NRPT, searchable resolver cache with decoded record types
- **Ping** — multi-card, each independent with live stats and a latency sparkline; lost packets render as full-height red bars
- **Lookup** — multi-card nslookup with per-card type and server override
- **Trace Route** — multi-card, one hop per tick so the route builds live
- **Port Check** — multi-card TCP probes with presets and plain-English failure reasons
- **Adapters** — adapter detail plus cloud endpoint reachability

**Certificates** — device and user stores, days-to-expiry, purpose classification, findings for expired/imminent/weak/SHA-1.

**Intune / MDM** — parsed `dsregcmd`, enrolment state, MDM certificate, IME service, sync task results, Win32 apps, **PowerShell scripts**, **Remediations**, MDM channel events, IME log findings.

**Group Policy** — conflicts and risks, applied/filtered GPOs, CSE status, GP events, searchable setting→registry→winning GPO map.

**Policy** — effective policy across MDM Policy CSP, Group Policy and registry
policy, with ADMX namespaces rendered readable, a per-area breakdown, conflict
detection and whether Intune or Group Policy wins (`MDMWinsOverGP`). Built for
cloud-managed devices, where `gpresult` shows almost nothing and the Policy CSP
carries the real configuration. Populated by the full scan as well as by
**Analyse policy**.

**System Health** — disk usage chart, volumes, connectivity, Device Manager error codes in plain English, stopped services, stability, crashes, updates.

**Actions and Report** — guided remediation with live console; exports to HTML, JSON, event CSV, certificate CSV, firewall CSV.

**Console launcher** — 23 consoles along the bottom bar.

---

## 5. Compile to an .exe

```powershell
.\Build-EndpointDiagX.ps1                       # output lands in .\build\
.\Build-EndpointDiagX.ps1 -SignThumbprint '...' # sign it (strongly recommended)
```

Switches that matter: **`-STA`** (mandatory — WPF will not start in MTA), `-noConsole`, `-requireAdmin`, `-DPIAware`, `-x64`.

The app already handles the PS2EXE path trap: `$PSScriptRoot` is **empty** in a compiled executable, so it falls back to `Process.MainModule.FileName`, and self-elevation relaunches the EXE rather than `powershell.exe`.

> **Expect AV/EDR friction.** PS2EXE output is frequently quarantined — EDRs detect the *execution technique*, not your code. Sign the binary, add a Defender exclusion or allow-indicator on the hash, and submit false positives. If the EXE vanishes right after building, that's AV, not a build failure.

---

## 6. Headless / at scale

```powershell
. .\DiagEngine.ps1
$snap  = Get-DxSystemSnapshot
$ev    = Get-DxEvents -Hours 168 -Levels 1,2,3
$st    = Get-DxEventStats -Events $ev
$certs = Get-DxCertificates
$fw    = Get-DxFirewallState
$dns   = Get-DxDnsState
$gpo   = Get-DxGpoState
$mdm   = Get-DxIntuneState
$sys   = Get-DxSystemDiagnostics
$h     = Get-DxHealthScore -Snapshot $snap -EventStats $st -Intune $mdm -Gpo $gpo `
                           -SysDiag $sys -Certs $certs -Firewall $fw -Dns $dns

New-DxHtmlReport -Snapshot $snap -EventStats $st -EventSummary (Get-DxEventSummary -Events $ev) `
                 -Intune $mdm -Gpo $gpo -SysDiag $sys -Health $h -Certs $certs `
                 -Firewall $fw -Dns $dns -Path "\\server\share\$env:COMPUTERNAME.html"
```

Single-shot helpers: `Invoke-DxPingOnce`, `Invoke-DxLookup`, `Invoke-DxTraceHop`, `Test-DxPortQuick`, `Expand-DxPortList`, `Get-DxIntuneScriptState`.

---

## 7. Design notes

- **Section isolation.** Large collectors run each phase inside `Invoke-DxSection`; a failure records the phase name, exception type and stack line, then continues. A single bad statement can no longer empty a tab.
- **Never-throw wrapper.** `Get-DxDnsState` wraps the core collector and, on a late failure, **recovers partial data** rather than discarding what was already gathered.
- **Null-safe binding.** All grid binding goes through `Set-DxItems`, which strips `$null` rows — `@($null)` yields a one-element array containing null, which throws `ArgumentNullException` in a virtualizing `ItemsControl`.
- **Result selection by shape.** `Get-DxJobResult` picks the background object that actually has the expected properties instead of blindly taking index 0.
- **No string injection.** Card targets pass into runspaces as **variables**, never concatenated into script text.
- **Never dies silently.** `DispatcherUnhandledException` is handled, deduplicated and logged to `%ProgramData%\Sys@dmin\crash.log`; it deliberately never shows a modal on the exception path (a modal pumps the message loop, re-running the failing layout pass — that caused a dialog cascade in v1).

---

## 8. Known limitations

- **Ping and traceroute use ICMP.** Many cloud endpoints (including `manage.microsoft.com`) drop it by design — use a **Port Check card on 443** for real evidence.
- Firewall **blocked-connection events** only appear with *Filtering Platform Connection* auditing enabled; the parsed log needs drop logging on (one-click action provided).
- Firewall rule detail is capped at 1500 enabled rules; the grid shows 800 at a time with search.
- GPO conflict detection works from the **resultant** RSoP, so it cannot see settings that lost precedence before reaching RSoP.
- Certificate scanning covers the local device and the **currently signed-in user** only.
- `Out-GridView` (the *Add channel* picker) is unavailable on Server Core.
- On a cloud-only device, **empty Group Policy and Win32 results are frequently correct** — the tool now states which case applies rather than leaving you guessing.
