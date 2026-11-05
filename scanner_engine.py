import asyncio
import aiohttp
import ipaddress
import random
import re
import html
import time
import os
import csv
from datetime import datetime
from typing import Callable, Optional, Dict, Any

# Tanınmış User-Agent başlıkları (Gerçek tarayıcı gibi görünmek için)
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

def generate_random_public_ip() -> str:
    """Rastgele geçerli, yönlendirilebilir bir genel (public) IPv4 adresi üretir."""
    # Yerel ağ (10.x, 192.168.x, 127.x, 172.16.x) ve ayrılmış blokları eler
    while True:
        # Hızlı üretim için genel IP barındıran ilk oktetleri seçelim
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
    """HTML içeriğinden sayfa başlığını (<title>) çeker."""
    if not html_content:
        return ""
    try:
        match = re.search(r'<title(?:\s+[^>]*)?>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if match:
            clean_title = re.sub(r'\s+', ' ', match.group(1)).strip()
            clean_title = html.unescape(clean_title)
            return clean_title[:80] # İlk 80 karakter yeterli
    except Exception:
        pass
    return ""

class IPScannerEngine:
    def __init__(self,
                 txt_log_path: str = "bulunan_ipler.txt",
                 csv_log_path: str = "bulunan_ipler.csv",
                 on_result: Optional[Callable[[Dict[str, Any]], None]] = None,
                 on_stat_update: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.txt_log_path = txt_log_path
        self.csv_log_path = csv_log_path
        self.on_result = on_result
        self.on_stat_update = on_stat_update

        self.is_running = False
        self.concurrency = 40
        self.timeout_sec = 2.0
        self.scan_mode = "http" # "http", "https", "both"
        self.record_401 = True

        # İstatistik sayaçları
        self.stats = {
            "scanned": 0,
            "hits_200": 0,
            "hits_403": 0,
            "hits_other": 0,
            "timeouts": 0,
            "not_found_404": 0,
            "errors": 0,
            "start_time": 0.0,
            "speed": 0.0,
        }

        self._init_csv()

    def _init_csv(self):
        """CSV dosyasını başlıklarla hazırla."""
        if not os.path.exists(self.csv_log_path):
            try:
                with open(self.csv_log_path, mode="w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.writer(f)
                    writer.writerow(["Tarih", "IP", "Port", "Protokol", "Durum Kodu", "Durum Aciklama", "Sayfa Basligi", "Web Sunucusu", "URL"])
            except Exception as e:
                print(f"CSV başlatma hatası: {e}")

    def save_hit(self, hit_data: Dict[str, Any]):
        """Bulunan geçerli IP'yi (200 veya 403) hem TXT hem de CSV'ye anında kaydeder."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = hit_data.get("ip", "")
        status = hit_data.get("status", "")
        status_text = hit_data.get("status_text", "")
        title = hit_data.get("title", "")
        server = hit_data.get("server", "")
        url = hit_data.get("url", "")
        proto = hit_data.get("proto", "http")
        port = hit_data.get("port", 80)

        # TXT'ye ekle
        try:
            with open(self.txt_log_path, mode="a", encoding="utf-8") as f:
                f.write(f"[{now_str}] [{status} {status_text}] {url}\n")
                if title:
                    f.write(f"   |-- Baslik : {title}\n")
                if server:
                    f.write(f"   |-- Sunucu : {server}\n")
                f.write("-" * 65 + "\n")
        except Exception as e:
            print(f"TXT yazma hatasi: {e}")

        # CSV'ye ekle
        try:
            with open(self.csv_log_path, mode="a", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([now_str, ip, port, proto.upper(), status, status_text, title, server, url])
        except Exception as e:
            print(f"CSV yazma hatası: {e}")

    async def _check_target(self, session: aiohttp.ClientSession, ip: str, proto: str, port: int) -> Dict[str, Any]:
        """Tek bir IP ve port hedefine HTTP/HTTPS GET isteği gönderir."""
        url = f"{proto}://{ip}:{port}/" if (proto == "http" and port != 80) or (proto == "https" and port != 443) else f"{proto}://{ip}/"
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,tr;q=0.8",
        }

        start_time = time.time()
        timeout = aiohttp.ClientTimeout(total=self.timeout_sec, connect=self.timeout_sec * 0.8)

        try:
            async with session.get(url, headers=headers, timeout=timeout, ssl=False, allow_redirects=True) as resp:
                elapsed_ms = int((time.time() - start_time) * 1000)
                status = resp.status
                server = resp.headers.get("Server", "").strip()

                # Sayfa içeriğini alıp başlığı ayrıştır
                title = ""
                try:
                    # En fazla ilk 50 KB oku, büyük dosyaları indirme
                    chunk = await resp.content.read(51200)
                    text = chunk.decode("utf-8", errors="replace")
                    title = extract_page_title(text)
                except Exception:
                    pass

                return {
                    "ip": ip,
                    "proto": proto,
                    "port": port,
                    "url": str(resp.url),
                    "status": status,
                    "status_text": resp.reason or "OK",
                    "title": title,
                    "server": server,
                    "elapsed_ms": elapsed_ms,
                    "type": "RESPONSE"
                }

        except asyncio.TimeoutError:
            return {"ip": ip, "proto": proto, "port": port, "url": url, "status": "TIMEOUT", "type": "TIMEOUT"}
        except aiohttp.ClientConnectorError:
            return {"ip": ip, "proto": proto, "port": port, "url": url, "status": "CONN_REFUSED", "type": "ERROR"}
        except aiohttp.ClientSSLError:
            return {"ip": ip, "proto": proto, "port": port, "url": url, "status": "SSL_ERROR", "type": "ERROR"}
        except Exception as e:
            return {"ip": ip, "proto": proto, "port": port, "url": url, "status": "ERR", "type": "ERROR", "error_msg": str(e)}

    async def _worker(self, session: aiohttp.ClientSession, sem: asyncio.Semaphore):
        """Sürekli rastgele IP seçip sorgulayan arkaplan çalışanı."""
        while self.is_running:
            ip = generate_random_public_ip()

            # Taranacak protokol ve port listesi
            targets = []
            if self.scan_mode in ("http", "both"):
                targets.append(("http", 80))
            if self.scan_mode in ("https", "both"):
                targets.append(("https", 443))

            for proto, port in targets:
                if not self.is_running:
                    break

                async with sem:
                    result = await self._check_target(session, ip, proto, port)

                self.stats["scanned"] += 1

                status = result.get("status")
                is_hit = False

                if status == 200:
                    self.stats["hits_200"] += 1
                    is_hit = True
                elif status == 403:
                    self.stats["hits_403"] += 1
                    is_hit = True
                elif status == 401 and self.record_401:
                    self.stats["hits_other"] += 1
                    is_hit = True
                elif status == 404:
                    self.stats["not_found_404"] += 1
                elif status == "TIMEOUT":
                    self.stats["timeouts"] += 1
                else:
                    self.stats["errors"] += 1

                # Eğer 200 OK veya 403 Forbidden gelirse not et
                if is_hit:
                    self.save_hit(result)

                # UI / Bildirim callback çağır
                if self.on_result:
                    try:
                        self.on_result(result, is_hit)
                    except Exception:
                        pass

            # Kısa döngü rahatlatması
            await asyncio.sleep(0.005)

    async def _stat_monitor(self):
        """Hız ve istatistikleri periyodik olarak hesaplar."""
        while self.is_running:
            elapsed = time.time() - self.stats["start_time"]
            if elapsed > 0:
                self.stats["speed"] = round(self.stats["scanned"] / elapsed, 1)

            if self.on_stat_update:
                try:
                    self.on_stat_update(dict(self.stats))
                except Exception:
                    pass

            await asyncio.sleep(0.5)

    async def run_async_scan(self):
        """Async ana tarama döngüsünü başlatır."""
        self.is_running = True
        self.stats["start_time"] = time.time()

        sem = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(ssl=False, limit=0, ttl_dns_cache=300)

        async with aiohttp.ClientSession(connector=connector) as session:
            # Çalışan işçi görevlerini başlat
            worker_tasks = [asyncio.create_task(self._worker(session, sem)) for _ in range(self.concurrency)]
            stat_task = asyncio.create_task(self._stat_monitor())

            try:
                await asyncio.gather(*worker_tasks, stat_task)
            except asyncio.CancelledError:
                pass
            finally:
                for t in worker_tasks:
                    t.cancel()
                stat_task.cancel()

    def stop(self):
        """Taramayı durdurur."""
        self.is_running = False
