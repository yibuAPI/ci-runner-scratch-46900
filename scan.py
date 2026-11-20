#!/usr/bin/env python3
# i46900: full 65535 TCP connect-scan of deploy host 51.161.35.209 from fresh
# Azure GHA runner EIPs. Goal: discover hidden web/admin/DB/SSH ports (Caddy :2019,
# 3306/6379/3001/8080/8081, deploy UI, phpMyAdmin, aaPanel, Portainer, registry...)
# that may be exposed only to certain source ranges. SCOPE: ONLY 51.161.35.209.
import os, sys, socket, time, asyncio

TARGET = os.environ.get("TARGET", "51.161.35.209")
JOB = int(os.environ.get("JOB", "1"))
NJOBS = int(os.environ.get("NJOBS", "16"))
CTRL = [("40.160.50.80", 3000), ("40.160.50.80", 80)]  # main site control (OVH reach)
PRIORITY = [22,80,443,2019,3306,6379,3001,3000,8080,8081,8443,9000,9090,10000,
            2375,2376,6443,10250,888,8888,7001,7002,2017,2018,2020,4000,5000,
            5432,27017,9200,9300,5601,15672,5672,11211,2181,8123,9001,18080]

def log(*a, **kw): print(" ".join(str(x) for x in a), flush=True)

def tcp_sync(ip, port, t=2.0):
    try:
        s = socket.create_connection((ip, port), timeout=t); s.close(); return True
    except Exception:
        return False

async def probe(ip, port, sem, timeout, results, lock):
    async with sem:
        try:
            fut = asyncio.open_connection(ip, port)
            r, w = await asyncio.wait_for(fut, timeout=timeout)
            w.close()
            async with lock:
                results.append(port)
        except Exception:
            pass

async def scan_range(ip, lo, hi, timeout=2.0, conc=1500):
    sem = asyncio.Semaphore(conc)
    results = []
    lock = asyncio.Lock()
    tasks = [asyncio.ensure_future(probe(ip, p, sem, timeout, results, lock)) for p in range(lo, hi)]
    await asyncio.gather(*tasks)
    return sorted(results)

def main():
    step = 65536 // NJOBS
    lo = (JOB - 1) * step
    hi = 65536 if JOB == NJOBS else JOB * step
    log("JOB", JOB, "range", lo, hi, "target", TARGET)
    # control reachability
    ctrl_res = []
    for (h, p) in CTRL:
        ctrl_res.append("%s:%d=%s" % (h, p, "OPEN" if tcp_sync(h, p, 4.0) else "NO"))
    log("CONTROL", ";".join(ctrl_res), flush=True)
    # priority ports first (quick)
    pri = [p for p in PRIORITY if lo <= p < hi]
    popen = [p for p in pri if tcp_sync(TARGET, p, 3.0)]
    log("PRIORITY_OPEN", popen, flush=True)
    # full range async
    t0 = time.time()
    res = asyncio.run(scan_range(TARGET, lo, hi, 2.0, 1500))
    log("FULLSCAN_DONE elapsed=%.1fs open_count=%d open=%s" % (time.time()-t0, len(res), res), flush=True)
    # final marker line for log scraping
    print("RESULT job=%d ctrl=%s priority_open=%s full_open=%s" % (JOB, ctrl_res, popen, res), flush=True)

if __name__ == "__main__":
    main()
