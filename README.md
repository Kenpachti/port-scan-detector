# Port Scan Detector

A detection tool that parses OPNsense firewall logs (`filterlog` format) and flags source IPs performing port-scan reconnaissance — one source touching an abnormal number of distinct destination ports within a short time window.

This is the second project in a defensive-security portfolio, following the SSH Triage tool. It reuses the same detection-engineering skeleton (parse → set a defended threshold → detect → document blind spots) applied to a new log source: firewall logs.

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
4. **Sort**: order the records by timestamp before detection. OPNsense exports logs newest-first, and the sliding window only works on oldest-first input (see Testing).
5. **Window** — per source IP, maintain a sliding 60-second deque of recent `(time, port)` entries, expiring old ones from the front (possibly several at once if there has been a gap in traffic).
6. **Detect & alert** — count the distinct ports in each source's window; if the count reaches 20 or more, flag the source. Alerts are edge-triggered: a source alerts once when it crosses the threshold, and is re-armed only when its distinct-port count falls below 10. The gap between the alert level (20) and the reset level (10) stops a source hovering around 20 from alerting repeatedly.

---

## Threshold design

The threshold was set from measurement, not guesswork.

Before writing any detection code, I measured the victim's benign baseline — distinct destination ports per 60-second window during normal use (browsing, package updates, idle). Normal traffic peaked at about **7 distinct ports per minute**.

By contrast, a real scan is a different order of magnitude: an `nmap` scan hits **dozens to hundreds of distinct ports in a single second**.

The chosen threshold — **20 distinct destination ports from one source within 60 seconds** — sits in the wide gap between these two: comfortably above benign noise (~7) and far below scan volume (hundreds). Because the gap is so large, the exact value is not sensitive; anywhere from roughly 10 to 50 would separate scans from normal traffic equally well. **The width of the gap is the defense, not the specific number.**

**Distinct ports, not total packets.** A single service like HTTPS (port 443) generates hundreds of packets to the *same* port — counting total packets would flag ordinary browsing as a scan. Counting *distinct* ports captures the real scan shape: normal traffic is high-volume across few ports; a scan is low-volume across many ports. (In code, this is the difference between a `set`, which dedupes to distinct, and a counter, which totals. Choosing the structure is choosing the metric.)

---

## Testing

Six sample logs are included, each with a known expected result:

| Sample | What it contains | Expected result |
|---|---|---|
| 'tests/scan_sample.log' | Real capture of an `nmap` scan from the Kali attacker (`192.168.2.134`) against the Ubuntu victim, generated in the home lab (Kali → OPNsense → Ubuntu) | **One alert**, on `192.168.2.134` (true positive) |
| 'tests/benign_sample.log' | Real capture of normal victim traffic (browsing, updates, idle) | **No alert**; skip counters `not_ipv4: 174, too_short: 4, junk: 1` (true negative) |
| 'tests/slow_traffic_test.log' | Synthetic regression test: one source touching a new port every 30 seconds, newest-first | **No alert** (never more than 2 distinct ports in any 60 seconds) |
| 'tests/test_one_scan.log' | Synthetic: one scan of 25 distinct ports plus a normal user | One alert |
| 'tests/test_two_scans.log' | Synthetic: the same scan, then a second scan of 30 ports 30 minutes later | Two alerts (the source re-arms during the quiet period) |
| 'tests/test_gap_20s.log' | Synthetic: a second scan starting 20 seconds after the first ends | One alert (the first scan's ports are still in the window, so it counts as one continuing scan) |

The last three `tests/` logs are synthetic, made to check the re-arm behaviour. The real captures are `scan_sample.log` and `benign_sample.log`. To run any of them, copy it to `firewallLog.log` as described in Usage.

### Bug found and fixed: log order

Regenerating the scan capture revealed that OPNsense exports logs **newest-first**. The expiry check (`now - oldest > 60`) assumes oldest-first input; on reversed input the difference is negative, so nothing ever expired and the "60-second window" silently became "the whole file." Slow, harmless traffic was then flagged as a scan (`slow_traffic_test.log` reproduced the false positive).

The original tests had not caught this: the real scan happens within one second, so it alerts either way, and the benign traffic touched too few ports in total to reach the threshold. The fix sorts records by timestamp before detection, so the result no longer depends on input order. `slow_traffic_test.log` is kept as a regression test.

The skip counters also proved their worth during testing: a run on an accidentally empty file produced "no alert" (which looks like a pass), but every counter read zero, which exposed that nothing had been read.

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
- **Clock / NTP caveat** — during capture, the firewall's NTP daemon was down, so its clock had drifted and the log timestamps were skewed off true time. This does *not* affect detection: the sliding window uses *relative* time (`now − oldest`), and since both timestamps come from the same skewed clock, the offset cancels out in the subtraction — a 60-second gap is still 60 seconds. However, accurate time (working NTP) would be needed in production to timestamp alerts correctly and correlate events with other systems' logs.
- **Re-arm needs another packet** — the window only shrinks when a new packet arrives from the same source. In a batch run this makes no difference, but in a live stream a source that scans once and then goes silent would stay in the "already alerted" state until it sends again.
- **Close-together scans merge** — a second scan that starts before the first scan's distinct-port count has fallen below 10 is counted as part of the same scan, so it produces no second alert.

---

## Usage

The script reads a log named `firewallLog.log` from the project folder. Copy one of the samples into that name, then run it:

```
cp scan_sample.log firewallLog.log      # Windows PowerShell: Copy-Item scan_sample.log firewallLog.log -Force
python fvm.py
```

It prints any port-scan alerts (with the flagged source IP), followed by parse statistics (lines skipped, broken down by reason).

To analyse your own capture, export the OPNsense firewall log in raw `filterlog` format (a tab-separated syslog wrapper followed by a comma-separated `filterlog` record, one entry per line) and save it as `firewallLog.log`.

---

## Possible future work

- Add TCP-flag signal (lone SYN with no completed handshake) as a harder-to-false-positive indicator.
- Add a distinct-destination-IP metric to catch horizontal sweeps.
- Extend parsing to IPv6.
