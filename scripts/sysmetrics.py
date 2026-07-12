#!/usr/bin/env python3
"""
sysmetrics.py — Live system metrics for IPDR System Status.

Provides CPU, RAM, disk (multiple mounts), service health, feed freshness,
network I/O, and capacity projection. Uses psutil.
"""

import os
import time
import shutil
import subprocess

try:
    import psutil
    PSUTIL = True
except ImportError:
    PSUTIL = False


def cpu_ram():
    if not PSUTIL:
        return {"cpu_pct": 0, "cpu_cores": 0, "ram_used_gb": 0, "ram_total_gb": 0, "ram_pct": 0,
                "load1": 0, "load5": 0, "load15": 0}
    vm = psutil.virtual_memory()
    try:
        load1, load5, load15 = os.getloadavg()
    except (OSError, AttributeError):
        load1 = load5 = load15 = 0
    return {
        "cpu_pct": psutil.cpu_percent(interval=0.3),
        "cpu_cores": psutil.cpu_count(),
        "ram_used_gb": round(vm.used / 1e9, 1),
        "ram_total_gb": round(vm.total / 1e9, 1),
        "ram_pct": vm.percent,
        "load1": round(load1, 2), "load5": round(load5, 2), "load15": round(load15, 2),
    }


def disk_for(path):
    """Disk usage for the filesystem containing `path`. Returns None if path missing."""
    if not path or not os.path.exists(path):
        return None
    try:
        u = shutil.disk_usage(path)
        return {
            "path": path,
            "used_gb": round(u.used / 1e9, 1),
            "total_gb": round(u.total / 1e9, 1),
            "free_gb": round(u.free / 1e9, 1),
            "pct": round(u.used / u.total * 100, 1) if u.total else 0,
        }
    except Exception:
        return None


def dir_size_gb(path):
    """Actual size of a directory tree in GB (for log dir usage within a shared FS)."""
    if not path or not os.path.exists(path):
        return 0
    total = 0
    try:
        for root, _, files in os.walk(path):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except OSError:
                    pass
    except Exception:
        pass
    return round(total / 1e9, 2)


def uptime():
    if not PSUTIL:
        return "n/a"
    secs = time.time() - psutil.boot_time()
    days = int(secs // 86400)
    hours = int((secs % 86400) // 3600)
    mins = int((secs % 3600) // 60)
    if days > 0:
        return f"{days}d {hours}h {mins}m"
    if hours > 0:
        return f"{hours}h {mins}m"
    return f"{mins}m"


def net_io():
    if not PSUTIL:
        return {"sent_gb": 0, "recv_gb": 0}
    io = psutil.net_io_counters()
    return {"sent_gb": round(io.bytes_sent / 1e9, 1), "recv_gb": round(io.bytes_recv / 1e9, 1)}


def service_status(names):
    """Check systemd service active state. Returns {name: 'active'|'inactive'|'unknown'}."""
    out = {}
    for name in names:
        try:
            r = subprocess.run(["systemctl", "is-active", name],
                               capture_output=True, text=True, timeout=5)
            out[name] = r.stdout.strip() or "unknown"
        except Exception:
            out[name] = "unknown"
    return out
