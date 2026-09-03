# Port Scan Detector

A detection tool that parses OPNsense firewall logs (`filterlog` format) and flags source IPs performing port-scan reconnaissance — one source touching an abnormal number of distinct destination ports within a short time window.

This is the second project in a defensive-security portfolio, following the SSH Triage tool. It reuses the same detection-engineering skeleton (parse → measure a baseline → set a defended threshold → detect → document blind spots) applied to a new log source: firewall logs.

---

## The problem

A port scan is a reconnaissance technique: an attacker probes many ports on a target to find which services are open and potentially exploitable — the groundwork before an actual attack.

In raw firewall logs, each probe is just one more `pass`/`block` line among thousands. The scan isn't any single line — it's the *pattern* across many of them. No human reads firewall logs line by line, so that pattern stays invisible.

This tool reads the logs programmatically, recognizes the scan pattern (one source touching an abnormal number of distinct ports in a short window), and flags the source IP.

---

## How it works

1. **Parse** — read the log line by line; split the syslog wrapper from the `filterlog` CSV and extract the relevant fields.
2. **Validate & tally** — keep IPv4 TCP/UDP lines; reject everything else into three counted buckets (`not IPv4`, `too short`, `no ports`). Nothing is dropped silently — every skipped line is accounted for by reason.
3. **Record** — each valid line becomes a record of `(time, source IP, dest port)`.
4. **Window** — per source IP, maintain a sliding 60-second deque of recent `(time, port)` entries, expiring old ones from the front (possibly several at once if there has been a gap in traffic).
5. **Detect & alert** — count the *distinct* ports in each source's window; if the count reaches 20 or more, flag the source. Alerts are edge-triggered (once per IP per run) to avoid alert fatigue.

---

## Threshold design

The threshold was set from measurement, not guesswork.

Before writing any detection code, I measured the victim's benign baseline — distinct destination ports per 60-second window during normal use (browsing, package updates, idle). Normal traffic peaked at about **7 distinct ports per minute**.

By contrast, a real scan is a different order of magnitude: an `nmap` scan hits **dozens to hundreds of distinct ports in a single second**.

The chosen threshold — **20 distinct destination ports from one source within 60 seconds** — sits in the wide gap between these two: comfortably above benign noise (~7) and far below scan volume (hundreds). Because the gap is so large, the exact value is not sensitive; anywhere from roughly 10 to 50 would separate scans from normal traffic equally well. **The width of the gap is the defense, not the specific number.**

**Distinct ports, not total packets.** A single service like HTTPS (port 443) generates hundreds of packets to the *same* port — counting total packets would flag ordinary browsing as a scan. Counting *distinct* ports captures the real scan shape: normal traffic is high-volume across few ports; a scan is low-volume across many ports. (In code, this is the difference between a `set`, which dedupes to distinct, and a counter, which totals. Choosing the structure is choosing the metric.)

---

## Testing

The detector was validated in both directions, using traffic generated in a controlled home lab (Kali attacker → OPNsense firewall → Ubuntu victim):

- **True negative** — run against a benign traffic log with no scan → no alert (correctly silent on normal traffic).
- **True positive** — run against a capture containing a real `nmap` scan → a single alert correctly identifying the attacker IP (`192.168.2.134`).

---

## Blind spots (scans this detector does *not* catch)

These are named deliberately. A distinct-port-per-source metric with a 60-second window has known gaps:

- **Slow scans** — an attacker who paces probes slowly (e.g. `nmap -T1` / `--scan-delay`) spreads them across minutes. The 60-second window never accumulates 20 distinct ports at once, so the scan evades detection.
- **Small / targeted scans** — an attacker probing only a few high-value ports (SSH, RDP, web, DB) touches fewer than 20 distinct ports and stays under the threshold.
- **Horizontal sweeps** — one port across many hosts is only 1 distinct *port*, so a distinct-port metric scores it as harmless. Catching it would require a distinct-destination-*IP* metric (and a second victim in the lab).

---

## Limitations & scope

- **IPv4 only** — v1 handles IPv4; IPv6 lines are out of scope (skipped and tallied). Defensible because the modeled threat is delivered over IPv4.
- **Batch, not live** — analyzes a saved log file, not a real-time stream.
- **Alert once per IP per run** — an IP that scans, stops, and scans again later will not re-alert within the same run.
- **Clock / NTP caveat** — during capture, the firewall's NTP daemon was down, so its clock had drifted and the log timestamps were skewed off true time. This does *not* affect detection: the sliding window uses *relative* time (`now − oldest`), and since both timestamps come from the same skewed clock, the offset cancels out in the subtraction — a 60-second gap is still 60 seconds. However, accurate time (working NTP) would be needed in production to timestamp alerts correctly and correlate events with other systems' logs.

---

## Usage

1. Place the firewall log to analyze in the project directory, named `firewallLog.log`.
2. Run:
   ```
   python fvm.py
   ```
3. The script prints any port-scan alerts (with the flagged source IP), followed by parse statistics (lines skipped, broken down by reason).

The log must be in OPNsense `filterlog` format (a tab-separated syslog wrapper followed by a comma-separated `filterlog` record).

---

## Possible future work

- Re-arm alerts after a scan ends (cooldown) instead of once-per-run.
- Add TCP-flag signal (lone SYN with no completed handshake) as a harder-to-false-positive indicator.
- Add a distinct-destination-IP metric to catch horizontal sweeps.
- Extend parsing to IPv6.
