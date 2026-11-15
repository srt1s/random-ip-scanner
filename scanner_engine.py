import asyncio
import aiohttp
import bisect
import csv
import html
import ipaddress
import os
import random
import re
import time
from collections import deque
from datetime import datetime
from typing import Any, Callable, Dict, Optional

try:
    from .paths import get_resource_path
except ImportError:
    from paths import get_resource_path

# Taninmis User-Agent basliklari (Gercek tarayici gibi gorunmek icin)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
]


class TurkeyIPPool:
    """Turkiye'ye tahsis edilmis (RIPE NCC / ipdeny) IPv4 CIDR bloklarini yonetir ve rastgele TR IP uretir."""

    def __init__(self, ranges_file: Optional[str] = None):
        self.ranges = []
        self.cum_weights = []
        self.total_ips = 0
        self.block_count = 0

        resolved_path = ranges_file if (ranges_file and os.path.exists(ranges_file)) else get_resource_path("tr_ip_ranges.txt")
        if os.path.exists(resolved_path):
            self.load_from_file(resolved_path)

    def load_from_file(self, filepath: str) -> None:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            total = 0
            ranges = []
            cum = []
            for line in lines:
                try:
                    net = ipaddress.IPv4Network(line)
                    start = int(net.network_address)
                    count = net.num_addresses
                    ranges.append((start, count))
                    total += count
                    cum.append(total)
                except Exception:
                    continue
            self.ranges = ranges
            self.cum_weights = cum
            self.total_ips = total
            self.block_count = len(ranges)
        except Exception:
            pass

    def get_random_ip(self) -> str:
        """Turkiye bloklari icinden homojen rastgele bir IPv4 adresi secer."""
        if not self.ranges or self.total_ips == 0:
            return generate_random_public_ip()
        idx = random.randint(0, self.total_ips - 1)
        r_idx = bisect.bisect_right(self.cum_weights, idx)
        base = self.cum_weights[r_idx - 1] if r_idx > 0 else 0
        offset = idx - base
        start_ip, _ = self.ranges[r_idx]
        return str(ipaddress.IPv4Address(start_ip + offset))


def generate_random_public_ip() -> str:
    """Rastgele gecerli, yonlendirilebilir bir genel (public) IPv4 adresi uretir."""
    while True:
        first = random.choice([
            random.randint(1, 9),
            random.randint(11, 99),
            random.randint(101, 126),
            random.randint(128, 168),
            random.randint(170, 171),
            random.randint(173, 191),
            random.randint(193, 197),
            random.randint(199, 202),
            random.randint(204, 223),
        ])
        ip_str = f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        try:
            ip_obj = ipaddress.IPv4Address(ip_str)
            if ip_obj.is_global and not ip_obj.is_multicast and not ip_obj.is_reserved:
                return ip_str
        except Exception:
            continue


def extract_page_title(html_content: str) -> str:
    """HTML iceriginden sayfa basligini (<title>) ceker ve kontrol karakterlerini temizler."""
    if not html_content:
        return ""
    try:
        match = re.search(r"<title(?:\s+[^>]*)?>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        if match:
            raw_title = html.unescape(match.group(1))
            clean_title = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", raw_title)
            clean_title = re.sub(r"\s+", " ", clean_title).strip()
            return clean_title[:100]
    except Exception:
        pass
    return ""


class IPScannerEngine:
    def __init__(
        self,
        txt_log_path: str = "bulunan_ipler.txt",
        csv_log_path: str = "bulunan_ipler.csv",
        on_result: Optional[Callable[[Dict[str, Any], bool], None]] = None,
        on_stat_update: Optional[Callable[[Dict[str, Any]], None]] = None,
        tr_pool: Optional[TurkeyIPPool] = None,
    ):
        self.txt_log_path = txt_log_path
        self.csv_log_path = csv_log_path
        self.on_result = on_result
        self.on_stat_update = on_stat_update

        self.is_running = False
        self.concurrency = 50
        self.timeout_sec = 1.5
        self.scan_mode = "http"      # "http", "https", "both"
        self.target_region = "TR"    # "TR" veya "GLOBAL"
        self.record_200 = True
        self.record_403 = True
        self.record_401 = True

        self.tr_pool = tr_pool if tr_pool is not None else TurkeyIPPool()

        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._tasks = []

        self.stats: Dict[str, Any] = {
            "scanned": 0,
            "hits_200": 0,
            "hits_403": 0,
            "hits_401": 0,
            "hits_other": 0,
            "timeouts": 0,
            "not_found_404": 0,
            "errors": 0,
            "start_time": 0.0,
            "elapsed_sec": 0.0,
            "speed": 0.0,
            "instant_speed": 0.0,
            "region": "TR",
        }

        self._init_csv()

    def _init_csv(self) -> None:
        """CSV dosyasini basliklarla hazirla."""
        if not os.path.exists(self.csv_log_path):
            try:
                parent = os.path.dirname(os.path.abspath(self.csv_log_path))
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(self.csv_log_path, mode="w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Tarih", "Bolge", "IP", "Port", "Protokol",
                        "Durum Kodu", "Durum Aciklama", "Sayfa Basligi", "Web Sunucusu", "URL"
                    ])
            except Exception:
                pass

    def save_hit(self, hit_data: Dict[str, Any]) -> None:
        """Bulunan gecerli IP'yi hem TXT hem de CSV'ye aninda kaydeder."""
        now_str = hit_data.get("full_timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = hit_data.get("ip", "")
        region = hit_data.get("region", self.target_region)
        status = hit_data.get("status", "")
        status_text = hit_data.get("status_text", "")
        title = hit_data.get("title", "")
        server = hit_data.get("server", "")
        url = hit_data.get("url", "")
        proto = hit_data.get("proto", "http")
        port = hit_data.get("port", 80)
        region_tag = "TR" if region == "TR" else "GLOBAL"

        try:
            with open(self.txt_log_path, mode="a", encoding="utf-8") as f:
                f.write(f"[{now_str}] [{status} {status_text}] [{region_tag}] {url}\n")
                if title:
                    f.write(f"   |-- Baslik : {title}\n")
                if server:
                    f.write(f"   |-- Sunucu : {server}\n")
                f.write("-" * 65 + "\n")
        except Exception:
            pass

        try:
            if not os.path.exists(self.csv_log_path):
                self._init_csv()
            with open(self.csv_log_path, mode="a", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([now_str, region_tag, ip, port, proto.upper(), status, status_text, title, server, url])
        except Exception:
            pass

    async def _check_target(self, session: aiohttp.ClientSession, ip: str, proto: str, port: int) -> Dict[str, Any]:
        """Tek bir IP ve port hedefine HTTP/HTTPS GET istegi gonderir."""
        url = (
            f"{proto}://{ip}:{port}/"
            if (proto == "http" and port != 80) or (proto == "https" and port != 443)
            else f"{proto}://{ip}/"
        )
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        region_snapshot = self.target_region
        timeout_val = max(0.3, float(self.timeout_sec))
        start_time = time.perf_counter()
        timeout = aiohttp.ClientTimeout(total=timeout_val, connect=timeout_val * 0.8)
        now_dt = datetime.now()
        ts_short = now_dt.strftime("%H:%M:%S")
        ts_full = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        try:
            async with session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=True) as resp:
                elapsed_ms = int((time.perf_counter() - start_time) * 1000)
                status = resp.status
                server = re.sub(r"[\x00-\x1f\x7f-\x9f]+", "", resp.headers.get("Server", "")).strip()[:80]
                content_type = (resp.content_type or "").lower()

                title = ""
                if not content_type or "html" in content_type or "text" in content_type or "xml" in content_type:
                    try:
                        chunk = await resp.content.read(51200)
                        text = chunk.decode("utf-8", errors="replace")
                        title = extract_page_title(text)
                    except Exception:
                        pass

                return {
                    "ip": ip,
                    "proto": proto,
                    "port": port,
                    "region": region_snapshot,
                    "url": str(resp.url),
                    "status": status,
                    "status_text": resp.reason or "OK",
                    "title": title,
                    "server": server,
                    "elapsed_ms": elapsed_ms,
                    "timestamp": ts_short,
                    "full_timestamp": ts_full,
                    "type": "RESPONSE",
                }

        except asyncio.TimeoutError:
            return {
                "ip": ip, "proto": proto, "port": port, "region": region_snapshot,
                "url": url, "status": "TIMEOUT", "elapsed_ms": int(timeout_val * 1000),
                "timestamp": ts_short, "full_timestamp": ts_full, "type": "TIMEOUT",
            }
        except aiohttp.ClientConnectorError:
            return {
                "ip": ip, "proto": proto, "port": port, "region": region_snapshot,
                "url": url, "status": "CONN_REFUSED",
                "timestamp": ts_short, "full_timestamp": ts_full, "type": "ERROR",
            }
        except aiohttp.ClientSSLError:
            return {
                "ip": ip, "proto": proto, "port": port, "region": region_snapshot,
                "url": url, "status": "SSL_ERROR",
                "timestamp": ts_short, "full_timestamp": ts_full, "type": "ERROR",
            }
        except asyncio.CancelledError:
            raise
        except Exception as e:
            return {
                "ip": ip, "proto": proto, "port": port, "region": region_snapshot,
                "url": url, "status": "ERR", "error_msg": str(e),
                "timestamp": ts_short, "full_timestamp": ts_full, "type": "ERROR",
            }

    async def _worker(self, session: aiohttp.ClientSession, sem: asyncio.Semaphore) -> None:
        """Surekli rastgele IP secip sorgulayan arkaplan calisani."""
        while self.is_running:
            if self.target_region == "TR":
                ip = self.tr_pool.get_random_ip()
            else:
                ip = generate_random_public_ip()

            targets = []
            mode = self.scan_mode
            if mode in ("http", "both"):
                targets.append(("http", 80))
            if mode in ("https", "both"):
                targets.append(("https", 443))

            for proto, port in targets:
                if not self.is_running:
                    break

                async with sem:
                    if not self.is_running:
                        break
                    result = await self._check_target(session, ip, proto, port)

                if not self.is_running:
                    break

                self.stats["scanned"] += 1
                self.stats["region"] = result.get("region", self.target_region)
                status = result.get("status")
                is_hit = False

                if status == 200:
                    self.stats["hits_200"] += 1
                    is_hit = self.record_200
                elif status == 403:
                    self.stats["hits_403"] += 1
                    is_hit = self.record_403
                elif status == 401:
                    self.stats["hits_401"] += 1
                    if self.record_401:
                        self.stats["hits_other"] += 1
                        is_hit = True
                elif status == 404:
                    self.stats["not_found_404"] += 1
                elif status == "TIMEOUT":
                    self.stats["timeouts"] += 1
                else:
                    self.stats["errors"] += 1

                if is_hit:
                    self.save_hit(result)

                if self.on_result:
                    try:
                        self.on_result(result, is_hit)
                    except Exception:
                        pass

            await asyncio.sleep(0.004)

    async def _stat_monitor(self) -> None:
        """Hiz ve istatistikleri periyodik olarak hesaplar."""
        window = deque(maxlen=12)  # ~3 saniyelik kayan pencere (0.25s * 12)
        while self.is_running:
            now = time.perf_counter()
            elapsed = now - self.stats["start_time"]
            scanned = self.stats["scanned"]
            self.stats["elapsed_sec"] = elapsed

            if elapsed > 0:
                self.stats["speed"] = round(scanned / elapsed, 1)

            window.append((now, scanned))
            if len(window) >= 2:
                dt = window[-1][0] - window[0][0]
                ds = window[-1][1] - window[0][1]
                self.stats["instant_speed"] = round(ds / dt, 1) if dt > 0 else 0.0
            else:
                self.stats["instant_speed"] = self.stats["speed"]

            if self.on_stat_update:
                try:
                    self.on_stat_update(dict(self.stats))
                except Exception:
                    pass

            await asyncio.sleep(0.25)

    async def run_async_scan(self) -> None:
        """Async ana tarama dongusunu baslatir."""
        self.is_running = True
        self._loop = asyncio.get_running_loop()
        self.stats["start_time"] = time.perf_counter()

        sem = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)

        async with aiohttp.ClientSession(connector=connector) as session:
            worker_tasks = [asyncio.create_task(self._worker(session, sem)) for _ in range(self.concurrency)]
            stat_task = asyncio.create_task(self._stat_monitor())
            self._tasks = worker_tasks + [stat_task]

            try:
                await asyncio.gather(*self._tasks, return_exceptions=True)
            except asyncio.CancelledError:
                pass
            finally:
                for t in self._tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*self._tasks, return_exceptions=True)
                self._tasks = []
                self._loop = None

    def stop(self) -> None:
        """Taramayi guvenli ve hizli sekilde durdurur."""
        self.is_running = False
        loop = self._loop
        tasks = list(self._tasks)
        if loop and not loop.is_closed():
            def _cancel_all():
                for t in tasks:
                    if not t.done():
                        t.cancel()
            try:
                loop.call_soon_threadsafe(_cancel_all)
            except Exception:
                pass
