#!/usr/bin/env python3
"""
Config Scanner V2 - تست واقعی کانفیگ‌ها با Xray-core
هر کانفیگ واقعاً از طریق Xray تست می‌شه و اگه HTTP response بده → فعال
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
BATCH_SIZE = 10                # تعداد کانفیگ هر بچ (موازی)
TIMEOUT = 8                    # ثانیه برای هر تست واقعی
MAX_CONFIGS_TO_TEST = 100      # حداکثر کانفیگ در هر اجرا (کمتر = سریع‌تر)
XRAY_VERSION = "1.8.24"
ROOT = Path(__file__).parent
XRAY_DIR = ROOT / "xray-bin"

# URL تست - اگه 204 برگشت یعنی کار می‌کنه
TEST_URL = "https://www.google.com/generate_204"
TEST_EXPECTED_STATUS = [204, 200]

# ========== Regex استخراج ==========
CONFIG_PATTERNS = [
    re.compile(r'vmess://[A-Za-z0-9+/=]+'),
    re.compile(r'vless://[^\s\n\r"\'<>]+'),
    re.compile(r'trojan://[^\s\n\r"\'<>]+'),
    re.compile(r'ss://[^\s\n\r"\'<>]+'),
]

# ========== توابع کمکی ==========
def config_hash(config: str) -> str:
    return hashlib.md5(config.encode('utf-8')).hexdigest()[:16]

def extract_configs(text: str) -> set:
    found = set()
    for pattern in CONFIG_PATTERNS:
        for match in pattern.findall(text):
            found.add(match.strip())
    return found

# ========== دانلود Xray ==========
def download_xray():
    """دانلود Xray-core اگه نباشه"""
    if (XRAY_DIR / "xray").exists():
        print("✅ Xray از قبل موجوده")
        return True
    
    XRAY_DIR.mkdir(exist_ok=True)
    url = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}/Xray-linux-64.zip"
    zip_path = XRAY_DIR / "xray.zip"
    
    print(f"📥 دانلود Xray-core v{XRAY_VERSION}...")
    result = subprocess.run(
        ["curl", "-L", "-s", "-o", str(zip_path), url],
        capture_output=True
    )
    if result.returncode != 0:
        print(f"❌ خطا در دانلود: {result.stderr.decode()}")
        return False
    
    print("📦 استخراج...")
    result = subprocess.run(
        ["unzip", "-o", "-q", str(zip_path), "-d", str(XRAY_DIR)],
        capture_output=True
    )
    if result.returncode != 0:
        print(f"❌ خطا در استخراج: {result.stderr.decode()}")
        return False
    
    os.chmod(XRAY_DIR / "xray", 0o755)
    try:
        zip_path.unlink()
    except Exception:
        pass
    print("✅ Xray آماده شد")
    return True

# ========== پارس کانفیگ‌ها ==========
def parse_vmess(config: str):
    try:
        b64 = config[8:]
        b64 += "=" * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode('utf-8'))
        return data
    except Exception:
        return None

def vless_to_outbound(config: str):
    try:
        url = urlparse(config)
        uuid = url.username or ""
        host = url.hostname or ""
        port = url.port or 443
        params = parse_qs(url.query)
        
        if not uuid or not host:
            return None
        
        security = params.get("security", ["none"])[0]
        network = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or params.get("host", [""])[0]
        fp = params.get("fp", [""])[0]
        path = unquote(params.get("path", ["/"])[0])
        host_header = params.get("host", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        
        stream_settings = {"network": network}
        
        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": path or "/",
                "headers": {"Host": host_header} if host_header else {}
            }
        elif network == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": service_name}
        elif network == "tcp" and params.get("headerType", [""])[0] == "http":
            stream_settings["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [path or "/"],
                        "headers": {"Host": [host_header] if host_header else []}
                    }
                }
            }
        
        if security in ["tls", "xtls"]:
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": sni or host,
                "allowInsecure": True,
                "fingerprint": fp or "chrome",
            }
        elif security == "reality":
            pbk = params.get("pbk", [""])[0]
            if not pbk:
                return None
            stream_settings["security"] = "reality"
            stream_settings["realitySettings"] = {
                "serverName": sni,
                "fingerprint": fp or "chrome",
                "publicKey": pbk,
                "shortId": params.get("sid", [""])[0],
                "spiderX": params.get("spx", ["/"])[0],
            }
        else:
            stream_settings["security"] = "none"
        
        return {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": params.get("flow", [""])[0] or "",
                    }]
                }]
            },
            "streamSettings": stream_settings,
        }
    except Exception:
        return None

def trojan_to_outbound(config: str):
    try:
        url = urlparse(config)
        password = url.username or ""
        host = url.hostname or ""
        port = url.port or 443
        params = parse_qs(url.query)
        
        if not password or not host:
            return None
        
        network = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or params.get("peer", [""])[0] or host
        path = unquote(params.get("path", ["/"])[0])
        host_header = params.get("host", [""])[0]
        
        stream_settings = {"network": network, "security": "tls"}
        
        if network == "ws":
            stream_settings["wsSettings"] = {
                "path": path or "/",
                "headers": {"Host": host_header} if host_header else {}
            }
        elif network == "grpc":
            stream_settings["grpcSettings"] = {
                "serviceName": params.get("serviceName", [""])[0]
            }
        
        stream_settings["tlsSettings"] = {
            "serverName": sni,
            "allowInsecure": True,
        }
        
        return {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "password": password,
                }]
            },
            "streamSettings": stream_settings,
        }
    except Exception:
        return None

def vmess_to_outbound(config: str):
    data = parse_vmess(config)
    if not data:
        return None
    
    try:
        host = data.get("add", "")
        port = int(data.get("port", 443))
        uuid = data.get("id", "")
        aid = int(data.get("aid", 0))
        net = data.get("net", "tcp")
        tls = data.get("tls", "")
        sni = data.get("sni", "") or data.get("host", "")
        path = data.get("path", "/")
        host_header = data.get("host", "")
        
        if not host or not uuid:
            return None
        
        stream_settings = {"network": net}
        
        if net == "ws":
            stream_settings["wsSettings"] = {
                "path": path or "/",
                "headers": {"Host": host_header} if host_header else {}
            }
        elif net == "grpc":
            stream_settings["grpcSettings"] = {"serviceName": path}
        
        if tls == "tls":
            stream_settings["security"] = "tls"
            stream_settings["tlsSettings"] = {
                "serverName": sni or host,
                "allowInsecure": True,
            }
        else:
            stream_settings["security"] = "none"
        
        return {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "alterId": aid,
                        "security": "auto",
                    }]
                }]
            },
            "streamSettings": stream_settings,
        }
    except Exception:
        return None

def ss_to_outbound(config: str):
    try:
        rest = config[5:].split("#")[0]
        rest = rest.split("?")[0]
        
        if "@" not in rest:
            return None
        
        userinfo, host_port = rest.rsplit("@", 1)
        if ":" not in host_port:
            return None
        
        host, port = host_port.rsplit(":", 1)
        port = int(port)
        
        try:
            userinfo_decoded = base64.b64decode(userinfo + "==").decode('utf-8')
        except Exception:
            userinfo_decoded = userinfo
        
        if ":" in userinfo_decoded:
            method, password = userinfo_decoded.split(":", 1)
        else:
            method, password = "aes-256-gcm", userinfo_decoded
        
        return {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address": host,
                    "port": port,
                    "method": method,
                    "password": password,
                }]
            },
            "streamSettings": {"network": "tcp"},
        }
    except Exception:
        return None

def build_xray_config(config: str, socks_port: int):
    if config.startswith("vmess://"):
        outbound = vmess_to_outbound(config)
    elif config.startswith("vless://"):
        outbound = vless_to_outbound(config)
    elif config.startswith("trojan://"):
        outbound = trojan_to_outbound(config)
    elif config.startswith("ss://"):
        outbound = ss_to_outbound(config)
    else:
        return None
    
    if not outbound:
        return None
    
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": socks_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": False, "auth": "noauth"},
        }],
        "outbounds": [outbound],
    }

# ========== تست واقعی ==========
async def test_config_real(config: str, socks_port: int):
    xray_config = build_xray_config(config, socks_port)
    if not xray_config:
        return {"config": config, "active": False, "reason": "parse_failed"}
    
    cfg_path = None
    proc = None
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(xray_config, f)
            cfg_path = f.name
        
        proc = await asyncio.create_subprocess_exec(
            str(XRAY_DIR / "xray"), "-c", cfg_path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        
        # صبر کن Xray بالا بیاد
        await asyncio.sleep(1.5)
        
        if proc.returncode is not None:
            return {"config": config, "active": False, "reason": "xray_crashed"}
        
        # تست HTTP از طریق SOCKS
        start = time.time()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    TEST_URL,
                    proxy=f"socks5://127.0.0.1:{socks_port}",
                    timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                    allow_redirects=False,
                    ssl=False,
                ) as resp:
                    latency = int((time.time() - start) * 1000)
                    if resp.status in TEST_EXPECTED_STATUS:
                        return {
                            "config": config,
                            "active": True,
                            "latency": latency,
                        }
        except Exception:
            pass
        
        return {"config": config, "active": False, "reason": "no_response"}
    
    except Exception as e:
        return {"config": config, "active": False, "reason": str(e)[:50]}
    
    finally:
        try:
            if proc and proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
        except Exception:
            pass
        
        if cfg_path:
            try:
                os.unlink(cfg_path)
            except Exception:
                pass

async def test_batch_real(configs: list, base_port: int = 20000):
    results = []
    total = len(configs)
    
    for i in range(0, total, BATCH_SIZE):
        batch = configs[i:i+BATCH_SIZE]
        batch_num = i // BATCH_SIZE + 1
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        
        print(f"  🧪 بچ {batch_num}/{total_batches} ({len(batch)} کانفیگ)...")
        
        tasks = []
        for j, cfg in enumerate(batch):
            port = base_port + (i + j) % 5000
            tasks.append(test_config_real(cfg, port))
        
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in batch_results:
            if isinstance(r, dict):
                results.append(r)
        
        await asyncio.sleep(0.5)
    
    return results

# ========== جمع‌آوری ==========
async def fetch_url(session, url):
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0"}
        ) as resp:
            if resp.status == 200:
                return await resp.text(errors='ignore')
    except Exception:
        pass
    return ""

async def collect_all(session, sources):
    all_configs = set()
    urls = sources.get("github_raw", []) + sources.get("subscriptions", []) + sources.get("custom_urls", [])
    print(f"🌐 دریافت از {len(urls)} منبع...")
    
    contents = await asyncio.gather(*[fetch_url(session, u) for u in urls], return_exceptions=True)
    for content in contents:
        if isinstance(content, str):
            all_configs.update(extract_configs(content))
    
    print(f"📦 {len(all_configs)} کانفیگ یکتا جمع‌آوری شد")
    return all_configs

# ========== ذخیره‌سازی ==========
def load_json(filename, default):
    path = ROOT / filename
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return default

def save_json(filename, data):
    with open(ROOT / filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def extract_host_info(config: str):
    """استخراج host/port/protocol برای ذخیره‌سازی"""
    info = {"protocol": "unknown", "host": "", "port": 0}
    try:
        if config.startswith(("vless://", "trojan://")):
            u = urlparse(config)
            info = {
                "protocol": config.split("://")[0],
                "host": u.hostname or "",
                "port": u.port or 0,
            }
        elif config.startswith("vmess://"):
            d = parse_vmess(config)
            if d:
                info = {
                    "protocol": "vmess",
                    "host": d.get("add", ""),
                    "port": int(d.get("port", 0)),
                }
        elif config.startswith("ss://"):
            rest = config[5:].split("#")[0].split("?")[0]
            if "@" in rest:
                _, hp = rest.rsplit("@", 1)
                if ":" in hp:
                    h2, p2 = hp.rsplit(":", 1)
                    info = {"protocol": "ss", "host": h2, "port": int(p2)}
    except Exception:
        pass
    return info

# ========== Main ==========
async def main():
    print("=" * 60)
    print(f"🚀 شروع اسکن (تست واقعی با Xray) - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    if not download_xray():
        print("❌ Xray دانلود نشد")
        return
    
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
    new_active_count = 0
    removed_count = 0
    
    # کانفیگ‌های فعال قدیمی که این بار تست نشدن - بازشماری
    old_active_hashes = set(active_before.keys())
    new_active_hashes = set()
    
    for r in new_results:
        h = config_hash(r["config"])
        tested[h] = now
        
        if r["active"]:
            new_active_count += 1
            info = extract_host_info(r["config"])
            active_before[h] = {
                "config": r["config"],
                "protocol": info["protocol"],
                "host": info["host"],
                "port": info["port"],
                "latency": r.get("latency", 0),
                "tested_at": now,
            }
            new_active_hashes.add(h)
    
    # لیست نهایی: همه‌ی active_before (قدیمی + جدید)
    active_list = sorted(
        active_before.values(),
        key=lambda x: x.get("latency", 9999)
    )
    
    save_json("tested.json", tested)
    save_json("results.json", {
        "active": active_list,
        "stats": {
            "last_scan": now,
            "total_tested": len(tested),
            "total_active": len(active_list),
            "new_this_run": new_active_count,
            "tested_this_run": len(new_results),
        }
    })
    
    print("=" * 60)
    print(f"✅ کانفیگ‌های فعال واقعی: {len(active_list)}")
    print(f"🧪 تست‌شده این اجرا: {len(new_results)}")
    print(f"🆕 فعال جدید: {new_active_count}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
