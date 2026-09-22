#!/usr/bin/env python3
"""
Config Scanner - جمع‌آوری، تست و ذخیره کانفیگ‌های V2Ray
اجرا توسط GitHub Actions هر ۱۰ دقیقه
"""

import asyncio
import aiohttp
import json
import re
import os
import hashlib
import base64
import socket
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from pathlib import Path

# ========== تنظیمات ==========
BATCH_SIZE = 10              # هر بچ ۱۰ تا کانفیگ
TIMEOUT = 5                  # ثانیه برای هر تست
MAX_CONFIGS_TO_TEST = 200    # حداکثر کانفیگ در هر اجرا
ROOT = Path(__file__).parent

# ========== Regex استخراج کانفیگ ==========
CONFIG_PATTERNS = [
    re.compile(r'vmess://[A-Za-z0-9+/=]+'),
    re.compile(r'vless://[^\s\n\r"\'<>]+'),
    re.compile(r'trojan://[^\s\n\r"\'<>]+'),
    re.compile(r'ss://[^\s\n\r"\'<>]+'),
]

# ========== توابع کمکی ==========
def config_hash(config: str) -> str:
    """هش یکتا برای هر کانفیگ"""
    return hashlib.md5(config.encode('utf-8')).hexdigest()[:16]

def extract_configs(text: str) -> set:
    """استخراج همه کانفیگ‌ها از یه متن"""
    found = set()
    for pattern in CONFIG_PATTERNS:
        for match in pattern.findall(text):
            found.add(match.strip())
    return found

def parse_config(config: str):
    """پارس host و port از کانفیگ - برگردونه dict یا None"""
    try:
        if config.startswith("vmess://"):
            # vmess: base64 encoded JSON
            b64 = config[8:]
            # padding
            b64 += "=" * (-len(b64) % 4)
            data = json.loads(base64.b64decode(b64).decode('utf-8'))
            return {
                "protocol": "vmess",
                "host": data.get("add", ""),
                "port": int(data.get("port", 0)),
                "network": data.get("net", "tcp"),
                "tls": data.get("tls", ""),
            }
        
        elif config.startswith(("vless://", "trojan://")):
            # vless://uuid@host:port?params#name
            scheme_end = config.index("://") + 3
            rest = config[scheme_end:]
            rest = rest.split("#")[0]  # حذف name
            rest = rest.split("?")[0]  # حذف query
            
            if "@" not in rest:
                return None
            
            host_port = rest.split("@")[-1]
            if ":" not in host_port:
                return None
            
            host, port = host_port.rsplit(":", 1)
            # IPv6 handling
            host = host.strip("[]")
            
            protocol = "vless" if config.startswith("vless") else "trojan"
            query = parse_qs(urlparse(config).query)
            
            return {
                "protocol": protocol,
                "host": host,
                "port": int(port),
                "network": query.get("type", ["tcp"])[0],
                "tls": query.get("security", ["none"])[0],
                "sni": query.get("sni", [""])[0],
            }
        
        elif config.startswith("ss://"):
            # ss://base64@host:port  یا  ss://base64
            rest = config[5:].split("#")[0]
            if "@" in rest:
                _, host_port = rest.rsplit("@", 1)
                if ":" in host_port:
                    host, port = host_port.rsplit(":", 1)
                    return {
                        "protocol": "ss",
                        "host": host,
                        "port": int(port),
                        "network": "tcp",
                        "tls": "none",
                    }
        return None
    except Exception as e:
        return None

async def tcp_ping(host: str, port: int, timeout: float = TIMEOUT):
    """تست TCP ساده - برگردونه latency به میلی‌ثانیه یا None"""
    if not host or not port:
        return None
    
    # حل DNS اگه دامنه هست
    try:
        loop = asyncio.get_event_loop()
        start = loop.time()
        
        # اتصال TCP
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        
        latency = int((loop.time() - start) * 1000)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        
        return latency
    except (asyncio.TimeoutError, socket.gaierror, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

# ========== جمع‌آوری ==========
async def fetch_url(session: aiohttp.ClientSession, url: str):
    """دریافت محتوا از URL"""
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": "Mozilla/5.0 (ConfigScanner/1.0)"}
        ) as resp:
            if resp.status == 200:
                return await resp.text(errors='ignore')
    except Exception as e:
        print(f"  ⚠️  خطا در {url[:60]}... : {type(e).__name__}")
    return ""

async def collect_all(session: aiohttp.ClientSession, sources: dict):
    """جمع‌آوری از همه منابع"""
    all_configs = set()
    
    urls = sources.get("github_raw", []) + sources.get("subscriptions", []) + sources.get("custom_urls", [])
    print(f"🌐 دریافت از {len(urls)} منبع...")
    
    tasks = [fetch_url(session, url) for url in urls]
    contents = await asyncio.gather(*tasks, return_exceptions=True)
    
    for content in contents:
        if isinstance(content, str):
            all_configs.update(extract_configs(content))
    
    print(f"📦 {len(all_configs)} کانفیگ یکتا جمع‌آوری شد")
    return all_configs

# ========== تست ==========
async def test_one(config: str):
    """تست یه کانفیگ"""
    parsed = parse_config(config)
    if not parsed or not parsed["host"] or not parsed["port"]:
        return {"config": config, "active": False, "reason": "parse_failed"}
    
    latency = await tcp_ping(parsed["host"], parsed["port"])
    
    return {
        "config": config,
        "active": latency is not None,
        "latency": latency or 0,
        "protocol": parsed["protocol"],
        "host": parsed["host"],
        "port": parsed["port"],
        "network": parsed.get("network", ""),
        "tls": parsed.get("tls", ""),
    }

async def test_batch(configs: list, batch_size: int = BATCH_SIZE):
    """تست بچ‌بچ - هر ۱۰ تا"""
    results = []
    total = len(configs)
    
    for i in range(0, total, batch_size):
        batch = configs[i:i+batch_size]
        batch_num = i // batch_size + 1
        total_batches = (total + batch_size - 1) // batch_size
        
        print(f"  🧪 بچ {batch_num}/{total_batches} ({len(batch)} کانفیگ)...")
        
        tasks = [test_one(c) for c in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for r in batch_results:
            if isinstance(r, dict):
                results.append(r)
        
        # وقفه کوچک بین بچ‌ها
        await asyncio.sleep(0.5)
    
    return results

# ========== ذخیره‌سازی ==========
def load_json(filename: str, default):
    """خوندن فایل JSON"""
    path = ROOT / filename
    if path.exists():
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return default

def save_json(filename: str, data):
    """ذخیره JSON با فرمت زیبا"""
    path = ROOT / filename
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# ========== Main ==========
async def main():
    print("=" * 60)
    print(f"🚀 شروع اسکن - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # ۱. بارگذاری منابع و لیست تست‌شده‌ها
    sources = load_json("sources.json", {})
    tested = load_json("tested.json", {})   # {hash: timestamp}
    results = load_json("results.json", {"active": [], "stats": {}})
    
    active_before = {config_hash(c["config"]): c for c in results.get("active", [])}
    print(f"📋 کانفیگ‌های تست‌شده قبلی: {len(tested)}")
    print(f"✅ کانفیگ‌های فعال موجود: {len(active_before)}")
    
    # ۲. جمع‌آوری
    async with aiohttp.ClientSession() as session:
        all_configs = await collect_all(session, sources)
    
    # ۳. فیلتر کردن کانفیگ‌های جدید
    new_configs = []
    for c in all_configs:
        h = config_hash(c)
        if h not in tested:
            new_configs.append(c)
    
    print(f"🆕 {len(new_configs)} کانفیگ جدید برای تست")
    
    # ۴. محدود کردن تعداد
    if len(new_configs) > MAX_CONFIGS_TO_TEST:
        print(f"⚠️  محدود به {MAX_CONFIGS_TO_TEST} کانفیگ در این اجرا")
        new_configs = new_configs[:MAX_CONFIGS_TO_TEST]
    
    # ۵. تست بچ‌بچ
    new_results = []
    if new_configs:
        print(f"🧪 شروع تست {len(new_configs)} کانفیگ در بچ‌های {BATCH_SIZE} تایی...")
        new_results = await test_batch(new_configs, BATCH_SIZE)
    
    # ۶. آپدیت tested و results
    now = datetime.now().isoformat()
    for r in new_results:
        h = config_hash(r["config"])
        tested[h] = now
        if r["active"]:
            active_before[h] = {
                "config": r["config"],
                "protocol": r["protocol"],
                "host": r["host"],
                "port": r["port"],
                "network": r.get("network", ""),
                "tls": r.get("tls", ""),
                "latency": r["latency"],
                "tested_at": now,
            }
    
    # ۷. حذف کانفیگ‌های فعالی که دیگه توی منابع نیستن (اختیاری - فعلاً نگه می‌داریم)
    # اگه بخوای فقط کانفیگ‌های تازه رو نگه داری، این بخش رو فعال کن
    # for h in list(active_before.keys()):
    #     if h not in {config_hash(c) for c in all_configs}:
    #         del active_before[h]
    
    # ۸. مرتب‌سازی بر اساس latency
    active_list = sorted(active_before.values(), key=lambda x: x.get("latency", 9999))
    
    # ۹. ذخیره
    save_json("tested.json", tested)
    save_json("results.json", {
        "active": active_list,
        "stats": {
            "last_scan": now,
            "total_tested": len(tested),
            "total_active": len(active_list),
            "new_this_run": len([r for r in new_results if r["active"]]),
            "tested_this_run": len(new_results),
        }
    })
    
    print("=" * 60)
    print(f"✅ کانفیگ‌های فعال: {len(active_list)}")
    print(f"🧪 تست‌شده در این اجرا: {len(new_results)}")
    print(f"🆕 فعال جدید: {len([r for r in new_results if r['active']])}")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(main())
