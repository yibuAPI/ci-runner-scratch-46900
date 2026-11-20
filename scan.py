#!/usr/bin/env python3
# i46900 v2: from 16 fresh Azure GHA runner EIPs, report egress IP and synchronously
# confirm key port state of deploy host 51.161.35.209 (proves distinct source IPs see
# only 22/80/443; no FD-exhaustion ambiguity). SCOPE: ONLY 51.161.35.209.
import os, socket, time, urllib.request

TARGET = os.environ.get("TARGET", "51.161.35.209")
JOB = str(os.environ.get("JOB", "1"))
KEY = [22,80,443,2019,3306,6379,3001,3000,8080,8081,8443,9000,9090,2375,2376,10250,888,8888,7001,7002,5432,27017,9200,15672,11211,8123,2181,6443]
CTRL = ("40.160.50.80", 3000)

def log(*a): print(" ".join(str(x) for x in a), flush=True)
def egress():
    for u in ("https://api.ipify.org","https://icanhazip.com","https://ifconfig.me/ip"):
        try: return urllib.request.urlopen(u, timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"
def tcp(host, port, t=5.0):
    st=time.time()
    try:
        s=socket.create_connection((host,port),timeout=t); s.close(); return "OPEN:%dms"%round((time.time()-st)*1000)
    except ConnectionRefusedError: return "REFUSED"
    except socket.timeout: return "TIMEOUT"
    except Exception as e: return "ERR:"+str(e)[:30]

eg = egress()
ctrl = tcp(*CTRL, t=6.0)
openp = []
det = []
for p in KEY:
    r = tcp(TARGET, p, t=4.0)
    if r.startswith("OPEN"):
        openp.append(p)
    det.append("%d=%s" % (p, r))
log("EGRESS", eg)
log("CONTROL %s:%d=%s" % (CTRL[0], CTRL[1], ctrl))
log("DETAIL", " ".join(det))
print("RESULT job=%s egress=%s ctrl=%s open=%s" % (JOB, eg, ctrl, openp), flush=True)
