#!/usr/bin/env python3
"""
Config Scanner - نسخه هوشمند با تست واقعی Xray
"""
import asyncio
import aiohttp
import json
import re
import os
import hashlib
import base64
import subprocess
import tempfile
import time
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

# ========== تنظیمات ==========
BATCH_SIZE = 10
TIMEOUT = 8
MAX_CONFIGS_TO_TEST = 300  # در هر اجرا 300 کانفیگ جدید تست می‌شه
XRAY_VERSION = "1.8.24"
ROOT = Path(__file__).parent
XRAY_DIR = ROOT / "xray-bin"
TEST_URL = "http://www.gstatic.com/generate_204"
TEST_EXPECTED = [204, 200]

CONFIG_PATTERNS = [
    re.compile(r'vmess://[A-Za-z0-9+/=]+'),
    re.compile(r'vless://[^\s\n\r"\'<>]+'),
    re.compile(r'trojan://[^\s\n\r"\'<>]+'),
    re.compile(r'ss://[^\s\n\r"\'<>]+'),
]

def config_hash(config: str) -> str:
    return hashlib.md5(config.encode('utf-8')).hexdigest()[:16]

def extract_configs(text: str) -> set:
    found = set()
    for pattern in CONFIG_PATTERNS:
        for match in pattern.findall(text):
            found.add(match.strip())
    return found

def download_xray():
    if (XRAY_DIR / "xray").exists():
        return True
    XRAY_DIR.mkdir(exist_ok=True)
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip"
    zip_path = XRAY_DIR / "xray.zip"
    print(f"📥 دانلود Xray v{XRAY_VERSION}...")
    subprocess.run(["curl", "-L", "-s", "-o", str(zip_path), url], check=True)
    subprocess.run(["unzip", "-o", "-q", str(zip_path), "-d", str(XRAY_DIR)], check=True)
    os.chmod(XRAY_DIR / "xray", 0o755)
    try: zip_path.unlink()
    except: pass
    return True

def parse_vmess(config):
    try:
        b64 = config[8:]
        b64 += "=" * (-len(b64) % 4)
        return json.loads(base64.b64decode(b64).decode('utf-8'))
    except: return None

def vless_to_outbound(config):
    try:
        u = urlparse(config)
        uuid, host, port = u.username, u.hostname, u.port or 443
        params = parse_qs(u.query)
        if not uuid or not host: return None
        sec = params.get("security", ["none"])[0]
        net = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or params.get("host", [""])[0]
        path = unquote(params.get("path", ["/"])[0])
        host_h = params.get("host", [""])[0]
        stream = {"network": net}
        if net == "ws":
            stream["wsSettings"] = {"path": path or "/", "headers": {"Host": host_h} if host_h else {}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": params.get("serviceName", [""])[0]}
        if sec in ["tls", "xtls"]:
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
        elif sec == "reality":
            pbk = params.get("pbk", [""])[0]
            if not pbk: return None
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": sni, "fingerprint": params.get("fp", ["chrome"])[0],
                "publicKey": pbk, "shortId": params.get("sid", [""])[0],
                "spiderX": params.get("spx", ["/"])[0]
            }
        else:
            stream["security"] = "none"
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "encryption": "none", "flow": params.get("flow", [""])[0] or ""}]}]},
            "streamSettings": stream,
        }
    except: return None

def vmess_to_outbound(config):
    d = parse_vmess(config)
    if not d: return None
    try:
        host, port, uuid = d.get("add", ""), int(d.get("port", 443)), d.get("id", "")
        net, tls = d.get("net", "tcp"), d.get("tls", "")
        sni = d.get("sni", "") or d.get("host", "")
        path, host_h = d.get("path", "/"), d.get("host", "")
        if not host or not uuid: return None
        stream = {"network": net}
        if net == "ws":
            stream["wsSettings"] = {"path": path or "/", "headers": {"Host": host_h} if host_h else {}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": path}
        if tls == "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = {"serverName": sni or host, "allowInsecure": True}
        else:
            stream["security"] = "none"
        return {
            "protocol": "vmess",
            "settings": {"vnext": [{"address": host, "port": port, "users": [{"id": uuid, "alterId": int(d.get("aid", 0)), "security": "auto"}]}]},
            "streamSettings": stream,
        }
    except: return None

def trojan_to_outbound(config):
    try:
        u = urlparse(config)
        pwd, host, port = u.username, u.hostname, u.port or 443
        params = parse_qs(u.query)
        if not pwd or not host: return None
        net = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or params.get("peer", [""])[0] or host
        stream = {"network": net, "security": "tls", "tlsSettings": {"serverName": sni, "allowInsecure": True}}
        if net == "ws":
            stream["wsSettings"] = {"path": unquote(params.get("path", ["/"])[0]), "headers": {"Host": params.get("host", [""])[0]} if params.get("host", [""])[0] else {}}
        elif net == "grpc":
            stream["grpcSettings"] = {"serviceName": params.get("serviceName", [""])[0]}
        return {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port, "password": pwd}]}, "streamSettings": stream}
    except: return None

def ss_to_outbound(config):
    try:
        rest = config[5:].split("#")[0].split("?")[0]
        if "@" not in rest: return None
        userinfo, host_port = rest.rsplit("@", 1)
        if ":" not in host_port: return None
        host, port = host_port.rsplit(":", 1)
        port = int(port)
        try: dec = base64.b64decode(userinfo + "==").decode()
        except: dec = userinfo
        method, pwd = dec.split(":", 1) if ":" in dec else ("aes-256-gcm", dec)
        return {"protocol": "shadowsocks", "settings": {"servers": [{"address": host, "port": port, "method": method, "password": pwd}]}, "streamSettings": {"network": "tcp"}}
    except: return None

def build_xray_config(config, socks_port):
    if config.startswith("vmess://"): out = vmess_to_outbound(config)
    elif config.startswith("vless://"): out = vless_to_outbound(config)
    elif config.startswith("trojan://"): out = trojan_to_outbound(config)
    elif config.startswith("ss://"): out = ss_to_outbound(config)
    else: return None
    if not out: return None
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": False, "auth": "noauth"}}],
        "outbounds": [out],
    }

async def test_config_real(config, socks_port):
    xray_cfg = build_xray_config(config, socks_port)
    if not xray_cfg: return {"config": config, "active": False, "reason": "parse_failed"}
    cfg_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(xray_cfg, f); cfg_path = f.name
        proc = await asyncio.create_subprocess_exec(str(XRAY_DIR / "xray"), "-c", cfg_path, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.sleep(1.5)
        if proc.returncode is not None: return {"config": config, "active": False, "reason": "xray_crashed"}
        start = time.time()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(TEST_URL, proxy=f"socks5://127.0.0.1:{socks_port}", timeout=aiohttp.ClientTimeout(total=TIMEOUT), allow_redirects=False, ssl=False) as resp:
                    lat = int((time.time() - start) * 1000)
                    if resp.status in TEST_EXPECTED: return {"config": config, "active": True, "latency": lat}
        except: pass
        return {"config": config, "active": False, "reason": "no_response"}
    except Exception as e: return {"config": config, "active": False, "reason": str(e)[:50]}
    finally:
        if proc and proc.returncode is None:
            proc.terminate()
            try: await asyncio.wait_for(proc.wait(), timeout=2)
            except asyncio.TimeoutError: proc.kill()
        if cfg_path:
            try: os.unlink(cfg_path)
            except: pass

async def test_batch_real(configs, base_port=20000):
    results = []
    total = len(configs)
    for i in range(0, total, BATCH_SIZE):
        batch = configs[i:i+BATCH_SIZE]
        bn = i // BATCH_SIZE + 1
        tb = (total + BATCH_SIZE - 1) // BATCH_SIZE
        print(f"  🧪 بچ {bn}/{tb} ({len(batch)} کانفیگ)...")
        tasks = [test_config_real(c, base_port + (i+j) % 5000) for j, c in enumerate(batch)]
        br = await asyncio.gather(*tasks, return_exceptions=True)
        for r in br:
            if isinstance(r, dict): results.append(r)
        await asyncio.sleep(0.5)
    return results

async def fetch_url(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), headers={"User-Agent": "Mozilla/5.0"}) as resp:
            if resp.status == 200: return await resp.text(errors='ignore')
    except: pass
    return ""

async def collect_all(session, sources):
    all_c = set()
    urls = sources.get("github_raw", []) + sources.get("subscriptions", []) + sources.get("custom_urls", [])
    print(f"🌐 دریافت از {len(urls)} منبع...")
    contents = await asyncio.gather(*[fetch_url(session, u) for u in urls], return_exceptions=True)
    for c in contents:
        if isinstance(c, str): all_c.update(extract_configs(c))
    print(f"📦 {len(all_c)} کانفیگ یکتا جمع‌آوری شد")
    return all_c

def load_json(fn, default):
    p = ROOT / fn
    if p.exists():
        try:
            with open(p, 'r', encoding='utf-8') as f: return json.load(f)
        except: pass
    return default

def save_json(fn, data):
    with open(ROOT / fn, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def extract_host_info(config):
    info = {"protocol": "unknown", "host": "", "port": 0}
    try:
        if config.startswith(("vless://", "trojan://")):
            u = urlparse(config)
            info = {"protocol": config.split("://")[0], "host": u.hostname or "", "port": u.port or 0}
        elif config.startswith("vmess://"):
            d = parse_vmess(config)
            if d: info = {"protocol": "vmess", "host": d.get("add", ""), "port": int(d.get("port", 0))}
        elif config.startswith("ss://"):
            rest = config[5:].split("#")[0].split("?")[0]
            if "@" in rest:
                _, hp = rest.rsplit("@", 1)
                if ":" in hp:
                    h2, p2 = hp.rsplit(":", 1)
                    info = {"protocol": "ss", "host": h2, "port": int(p2)}
    except: pass
    return info

async def main():
    print("=" * 60)
    print(f"🚀 شروع اسکن (تست واقعی) - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    if not download_xray():
        print("❌ Xray دانلود نشد"); return
    sources = load_json("sources.json", {})
    tested = load_json("tested.json", {})
    results = load_json("results.json", {"active": [], "stats": {}})
    active_before = {config_hash(c["config"]): c for c in results.get("active", [])}
    print(f"📋 تست‌شده قبلی: {len(tested)}")
    print(f"✅ فعال موجود: {len(active_before)}")
    async with aiohttp.ClientSession() as session:
        all_configs = await collect_all(session, sources)
    new_configs = [c for c in all_configs if config_hash(c) not in tested]
    print(f"🆕 {len(new_configs)} کانفیگ جدید")
    if len(new_configs) > MAX_CONFIGS_TO_TEST:
        print(f"⚠️ محدود به {MAX_CONFIGS_TO_TEST}")
        new_configs = new_configs[:MAX_CONFIGS_TO_TEST]
    new_results = []
    if new_configs:
        print(f"🧪 تست واقعی {len(new_configs)} کانفیگ با Xray...")
        new_results = await test_batch_real(new_configs)
    now = datetime.now().isoformat()
    new_active = 0
    for r in new_results:
        h = config_hash(r["config"]); tested[h] = now
        if r["active"]:
            new_active += 1
            info = extract_host_info(r["config"])
            active_before[h] = {"config": r["config"], "protocol": info["protocol"], "host": info["host"], "port": info["port"], "latency": r.get("latency", 0), "tested_at": now}
    active_list = sorted(active_before.values(), key=lambda x: x.get("latency", 9999))
    save_json("tested.json", tested)
    save_json("results.json", {"active": active_list, "stats": {"last_scan": now, "total_tested": len(tested), "total_active": len(active_list), "new_this_run": new_active, "tested_this_run": len(new_results)}})
    print("=" * 60)
    print(f"✅ کانفیگ‌های فعال واقعی: {len(active_list)}")
    print(f"🧪 تست‌شده این اجرا: {len(new_results)}")
    print(f"🆕 فعال جدید: {new_active}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
