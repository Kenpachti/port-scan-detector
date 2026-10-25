from dataclasses import dataclass
from datetime import datetime
from collections import deque

#Time handling
date_format = "%Y-%m-%dT%H:%M:%S"

#Record Class
@dataclass
class LogRecord:
    unix: float
    sourceIp: str
    destinationPort: int

#Counters
scanAndNoPorts = 0
scanAndNotIP4 = 0
scanAndShort = 0
junkScan = 0
distinct = 0

#Lists
records = []
windows = {}


with open("firewallLog.log") as file:

    for line in file:
        LogLine = line.split();
        if len(LogLine) <= 3:
            junkScan += 1
            continue

        time = datetime.strptime(LogLine[0], date_format)
        ruleLog = LogLine[3].split(",")
        ipVersion = ruleLog[8]

        if ipVersion == "4":
            if len(ruleLog) >= 22:
                src_ip = ruleLog[18]
                protocol = ruleLog[16]
                if protocol in("tcp", "udp"):
                    dst_port = int(ruleLog[21])
                    log = LogRecord(unix= time.timestamp(), sourceIp=src_ip, destinationPort=dst_port)
                    records.append(log)

                else:
                    scanAndNoPorts = scanAndNoPorts + 1
            else:
                scanAndShort = scanAndShort + 1            
        else:
            scanAndNotIP4 = scanAndNotIP4 + 1

    records.sort(key=lambda r: r.unix)
    alerted = set()
    for log in records:
        if log.sourceIp not in windows:
            windows[log.sourceIp] = deque()

        q = windows[log.sourceIp]
        q.append((log.unix, log.destinationPort))

        while len(q) > 0 and (log.unix - q[0][0]) > 60:
            q.popleft()

        ports = set()

        for cards in q:
            ports.add(cards[1])
        distinct = len(ports)

        if(distinct >= 20) and log.sourceIp not in alerted:
            print("Alert more than 20 ports scanned in under one minute from: " + log.sourceIp)
            alerted.add(log.sourceIp)
            
        if (distinct < 10) and log.sourceIp in alerted:
            alerted.discard(log.sourceIp) 




print("Scans not using IPv4 :", scanAndNotIP4)
print("Scans with no ports :", scanAndNoPorts)
print("Scans too short :", scanAndShort)
print("Invalid Scans :", junkScan)
