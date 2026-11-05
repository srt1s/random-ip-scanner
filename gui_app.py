import sys
import os
import time
import queue
import threading
import asyncio
import webbrowser
from datetime import datetime

import customtkinter as ctk
from random_ip_scanner.scanner_engine import IPScannerEngine

# Görünüm Teması
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class IPScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Rastgele IP Web Tarayıcı - Random IP Discovery")
        self.geometry("1100x720")
        self.minsize(950, 600)

        # Temel Değişkenler
        self.engine = None
        self.scan_thread = None
        self.loop = None
        self.msg_queue = queue.Queue()
        self.is_scanning = False
        self.auto_open_in_browser = False
        self.last_browser_open_time = 0.0

        # Log dosya yolları
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.txt_path = os.path.join(base_dir, "bulunan_ipler.txt")
        self.csv_path = os.path.join(base_dir, "bulunan_ipler.csv")

        # UI Oluştur
        self._build_ui()

        # Kuyruk kontrol döngüsü
        self.after(50, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        # Üst Başlık & Durum Çubuğu
        header_frame = ctk.CTkFrame(self, corner_radius=10)
        header_frame.pack(fill="x", padx=15, pady=(15, 10))

        title_label = ctk.CTkLabel(
            header_frame,
            text="🌐 İnternet Rastgele IP Web Tarayıcısı",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.pack(side="left", padx=15, pady=12)

        self.status_badge = ctk.CTkLabel(
            header_frame,
            text="● HAZIR (Durduruldu)",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#888888"
        )
        self.status_badge.pack(side="right", padx=15, pady=12)

        # İstatistik Kartları Çerçevesi
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.pack(fill="x", padx=15, pady=5)
        stats_frame.columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.card_scanned = self._create_stat_card(stats_frame, 0, "Taranan IP", "0", "#3a7ebf")
        self.card_200 = self._create_stat_card(stats_frame, 1, "200 OK (Açık Site)", "0", "#2fa572")
        self.card_403 = self._create_stat_card(stats_frame, 2, "403 Forbidden", "0", "#e59400")
        self.card_timeout = self._create_stat_card(stats_frame, 3, "Zaman Aşımı", "0", "#777777")
        self.card_404 = self._create_stat_card(stats_frame, 4, "404 / Hata", "0", "#c73e3e")
        self.card_speed = self._create_stat_card(stats_frame, 5, "Hız (IP/sn)", "0.0", "#9b59b6")

        # Kontrol & Ayar Çerçevesi
        control_frame = ctk.CTkFrame(self, corner_radius=10)
        control_frame.pack(fill="x", padx=15, pady=10)

        # Başlat / Durdur Butonu
        self.btn_toggle = ctk.CTkButton(
            control_frame,
            text="▶ Taramayı Başlat",
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#2fa572",
            hover_color="#26865d",
            height=38,
            width=170,
            command=self._toggle_scan
        )
        self.btn_toggle.pack(side="left", padx=(15, 10), pady=12)

        # Eşzamanlılık Ayarı (Threads)
        ctk.CTkLabel(control_frame, text="Eşzamanlılık:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(5, 3))
        self.slider_concurrency = ctk.CTkSlider(control_frame, from_=10, to=150, number_of_steps=14, width=110)
        self.slider_concurrency.set(40)
        self.slider_concurrency.pack(side="left", padx=(0, 5))
        self.lbl_concurrency = ctk.CTkLabel(control_frame, text="40", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_concurrency.pack(side="left", padx=(0, 15))
        self.slider_concurrency.configure(command=lambda v: self.lbl_concurrency.configure(text=str(int(v))))

        # Timeout Ayarı
        ctk.CTkLabel(control_frame, text="Timeout (sn):", font=ctk.CTkFont(size=12)).pack(side="left", padx=(5, 3))
        self.slider_timeout = ctk.CTkSlider(control_frame, from_=0.5, to=4.0, number_of_steps=7, width=90)
        self.slider_timeout.set(1.5)
        self.slider_timeout.pack(side="left", padx=(0, 5))
        self.lbl_timeout = ctk.CTkLabel(control_frame, text="1.5s", font=ctk.CTkFont(size=12, weight="bold"))
        self.lbl_timeout.pack(side="left", padx=(0, 15))
        self.slider_timeout.configure(command=lambda v: self.lbl_timeout.configure(text=f"{v:.1f}s"))

        # Port / Protokol Seçimi
        ctk.CTkLabel(control_frame, text="Protokol:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(5, 3))
        self.opt_protocol = ctk.CTkOptionMenu(
            control_frame,
            values=["HTTP (Port 80)", "HTTPS (Port 443)", "Her İkisi"],
            width=135,
            height=30
        )
        self.opt_protocol.set("HTTP (Port 80)")
        self.opt_protocol.pack(side="left", padx=(0, 15))

        # Checkbox: Otomatik Chrome'da Aç
        self.chk_auto_open = ctk.CTkCheckBox(
            control_frame,
            text="200 OK'leri Tarayıcıda Aç",
            font=ctk.CTkFont(size=12)
        )
        self.chk_auto_open.pack(side="left", padx=(5, 10))

        # Sağ Butonlar (Dosya Aç & Temizle)
        btn_open_txt = ctk.CTkButton(
            control_frame,
            text="📄 TXT",
            width=65,
            height=32,
            fg_color="#444444",
            hover_color="#555555",
            command=self._open_txt_file
        )
        btn_open_txt.pack(side="right", padx=(5, 15))

        btn_open_csv = ctk.CTkButton(
            control_frame,
            text="📊 CSV",
            width=65,
            height=32,
            fg_color="#444444",
            hover_color="#555555",
            command=self._open_csv_file
        )
        btn_open_csv.pack(side="right", padx=5)

        # Sekmeli Ana Alan (Bulunan IP'ler & Canlı Akış)
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.tab_hits = self.tabview.add("🎯 Bulunan Aktif Siteler (200 OK / 403 Forbidden)")
        self.tab_live = self.tabview.add("⚡ Canlı Tarama Akışı (Realtime Feed)")

        self._build_hits_tab()
        self._build_live_tab()

    def _create_stat_card(self, parent, col, title, initial_val, color):
        frame = ctk.CTkFrame(parent, corner_radius=8, border_width=1, border_color="#333333")
        frame.grid(row=0, column=col, padx=4, sticky="ew")

        lbl_title = ctk.CTkLabel(frame, text=title, font=ctk.CTkFont(size=11), text_color="#aaaaaa")
        lbl_title.pack(pady=(6, 0))

        lbl_val = ctk.CTkLabel(frame, text=initial_val, font=ctk.CTkFont(size=18, weight="bold"), text_color=color)
        lbl_val.pack(pady=(0, 6))

        return lbl_val

    def _build_hits_tab(self):
        # Üst bilgi çubuğu
        info_frame = ctk.CTkFrame(self.tab_hits, fg_color="transparent")
        info_frame.pack(fill="x", padx=10, pady=(5, 5))

        lbl_hint = ctk.CTkLabel(
            info_frame,
            text="💡 İpucu: Herhangi bir satıra çift tıklayarak veya 'Tarayıcıda Aç' butonuna basarak sayfayı Chrome/varsayılan tarayıcınızda açabilirsiniz.",
            font=ctk.CTkFont(size=12),
            text_color="#88c0d0"
        )
        lbl_hint.pack(side="left")

        btn_clear = ctk.CTkButton(
            info_frame,
            text="🗑 Listeyi Temizle",
            width=110,
            height=28,
            fg_color="#553333",
            hover_color="#773333",
            command=self._clear_hits_view
        )
        btn_clear.pack(side="right")

        # Scrollable Frame - Bulunan IP Kartları
        self.hits_container = ctk.CTkScrollableFrame(self.tab_hits, corner_radius=8)
        self.hits_container.pack(fill="both", expand=True, padx=5, pady=5)

        self.hits_count = 0

    def _build_live_tab(self):
        top_bar = ctk.CTkFrame(self.tab_live, fg_color="transparent")
        top_bar.pack(fill="x", padx=10, pady=(5, 5))

        self.chk_autoscroll = ctk.CTkCheckBox(top_bar, text="Otomatik Aşağı Kaydır", font=ctk.CTkFont(size=12))
        self.chk_autoscroll.select()
        self.chk_autoscroll.pack(side="left")

        btn_clear_log = ctk.CTkButton(
            top_bar,
            text="Konsolu Temizle",
            width=110,
            height=28,
            fg_color="#333333",
            hover_color="#444444",
            command=self._clear_live_log
        )
        btn_clear_log.pack(side="right")

        self.live_textbox = ctk.CTkTextbox(self.tab_live, font=ctk.CTkFont(family="Consolas", size=12), wrap="none")
        self.live_textbox.pack(fill="both", expand=True, padx=5, pady=5)
        self.live_textbox.configure(state="disabled")

    def _toggle_scan(self):
        if not self.is_scanning:
            self._start_scan()
        else:
            self._stop_scan()

    def _start_scan(self):
        self.is_scanning = True
        self.btn_toggle.configure(text="⏹ Taramayı Durdur", fg_color="#c73e3e", hover_color="#9e3232")
        self.status_badge.configure(text="● AKTİF TARANIYOR...", text_color="#2fa572")

        # Parametreleri al
        concurrency = int(self.slider_concurrency.get())
        timeout_val = float(self.slider_timeout.get())
        proto_choice = self.opt_protocol.get()

        scan_mode = "http"
        if "HTTPS" in proto_choice:
            scan_mode = "https"
        elif "Her İkisi" in proto_choice:
            scan_mode = "both"

        # Engine oluştur
        self.engine = IPScannerEngine(
            txt_log_path=self.txt_path,
            csv_log_path=self.csv_path,
            on_result=lambda res, is_hit: self.msg_queue.put(("RESULT", res, is_hit)),
            on_stat_update=lambda st: self.msg_queue.put(("STATS", st))
        )
        self.engine.concurrency = concurrency
        self.engine.timeout_sec = timeout_val
        self.engine.scan_mode = scan_mode

        # Arkaplan thread başlat
        def run_thread():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            try:
                self.loop.run_until_complete(self.engine.run_async_scan())
            except Exception as e:
                print(f"Tarama hatasi: {e}")
            finally:
                self.loop.close()

        self.scan_thread = threading.Thread(target=run_thread, daemon=True)
        self.scan_thread.start()

    def _stop_scan(self):
        self.is_scanning = False
        self.btn_toggle.configure(text="▶ Taramayı Başlat", fg_color="#2fa572", hover_color="#26865d")
        self.status_badge.configure(text="● DURDURULDU", text_color="#888888")

        if self.engine:
            self.engine.stop()

    def _process_queue(self):
        """Kuyruktaki mesajları GUI'ye aktarır (Donmayı önlemek için toplu işler)."""
        batch_limit = 50
        count = 0

        while count < batch_limit:
            try:
                msg = self.msg_queue.get_nowait()
            except queue.Empty:
                break

            msg_type = msg[0]
            if msg_type == "STATS":
                self._update_stats_ui(msg[1])
            elif msg_type == "RESULT":
                result, is_hit = msg[1], msg[2]
                self._append_live_log(result)
                if is_hit:
                    self._add_hit_card(result)

            count += 1

        self.after(50, self._process_queue)

    def _update_stats_ui(self, stats):
        self.card_scanned.configure(text=f"{stats.get('scanned', 0):,}")
        self.card_200.configure(text=f"{stats.get('hits_200', 0):,}")
        self.card_403.configure(text=f"{stats.get('hits_403', 0):,}")
        self.card_timeout.configure(text=f"{stats.get('timeouts', 0):,}")
        err_total = stats.get('not_found_404', 0) + stats.get('errors', 0)
        self.card_404.configure(text=f"{err_total:,}")
        self.card_speed.configure(text=f"{stats.get('speed', 0.0)}/s")

    def _append_live_log(self, result):
        now_str = datetime.now().strftime("%H:%M:%S")
        status = result.get("status")
        ip = result.get("ip")
        proto = result.get("proto")

        line = ""
        if status == 200:
            line = f"[{now_str}] [200 OK]      {proto}://{ip}  --> BULDUM! ({result.get('title') or 'Baslik yok'})\n"
        elif status == 403:
            line = f"[{now_str}] [403 FORBID]  {proto}://{ip}  --> ERİŞİM ENGELİ (Sunucu: {result.get('server') or 'Bilinmiyor'})\n"
        elif status == 404:
            line = f"[{now_str}] [404 NOT FND] {proto}://{ip}  --> Atlandı\n"
        elif status == "TIMEOUT":
            line = f"[{now_str}] [TIMEOUT]     {proto}://{ip}  --> Zaman aşımı\n"
        else:
            line = f"[{now_str}] [{status}]        {proto}://{ip}\n"

        self.live_textbox.configure(state="normal")
        self.live_textbox.insert("end", line)

        # 500 satırdan fazlasını kırp (bellek şişmesin)
        lines = int(self.live_textbox.index('end-1c').split('.')[0])
        if lines > 500:
            self.live_textbox.delete("1.0", "50.0")

        if self.chk_autoscroll.get():
            self.live_textbox.see("end")

        self.live_textbox.configure(state="disabled")

    def _add_hit_card(self, result):
        self.hits_count += 1
        url = result.get("url", f"http://{result.get('ip')}/")
        ip = result.get("ip")
        status = result.get("status")
        status_text = result.get("status_text", "")
        title = result.get("title") or "(Başlık Bulunamadı)"
        server = result.get("server") or "(Bilinmiyor)"
        now_str = datetime.now().strftime("%H:%M:%S")

        is_200 = (status == 200)
        bg_color = "#1f3b2e" if is_200 else "#3b2b1f"
        badge_color = "#2fa572" if is_200 else "#e59400"

        card = ctk.CTkFrame(self.hits_container, fg_color=bg_color, corner_radius=8, border_width=1, border_color=badge_color)
        card.pack(fill="x", padx=5, pady=4)

        # Kart Üst Satır
        top_row = ctk.CTkFrame(card, fg_color="transparent")
        top_row.pack(fill="x", padx=10, pady=(6, 2))

        lbl_badge = ctk.CTkLabel(
            top_row,
            text=f" {status} {status_text} ",
            fg_color=badge_color,
            corner_radius=4,
            text_color="#ffffff",
            font=ctk.CTkFont(size=12, weight="bold")
        )
        lbl_badge.pack(side="left")

        lbl_url = ctk.CTkLabel(
            top_row,
            text=f"  {url}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#64b5f6"
        )
        lbl_url.pack(side="left", padx=5)

        lbl_time = ctk.CTkLabel(
            top_row,
            text=now_str,
            font=ctk.CTkFont(size=11),
            text_color="#aaaaaa"
        )
        lbl_time.pack(side="right")

        # Kart Alt Satır (Detaylar & Buton)
        bottom_row = ctk.CTkFrame(card, fg_color="transparent")
        bottom_row.pack(fill="x", padx=10, pady=(2, 6))

        details_text = f"📄 Sayfa: {title}  |  🖥️ Sunucu: {server}"
        lbl_details = ctk.CTkLabel(
            bottom_row,
            text=details_text,
            font=ctk.CTkFont(size=12),
            text_color="#cccccc"
        )
        lbl_details.pack(side="left")

        btn_open = ctk.CTkButton(
            bottom_row,
            text="🌐 Tarayıcıda Aç",
            width=110,
            height=26,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#3a7ebf",
            hover_color="#2b6196",
            command=lambda u=url: webbrowser.open(u)
        )
        btn_open.pack(side="right")

        # Çift tıklayınca aç
        card.bind("<Double-Button-1>", lambda e, u=url: webbrowser.open(u))
        lbl_url.bind("<Double-Button-1>", lambda e, u=url: webbrowser.open(u))

        # Kullanıcı "Otomatik Tarayıcıda Aç"ı seçtiyse ve 200 OK ise
        if is_200 and self.chk_auto_open.get():
            curr_time = time.time()
            # Bilgisayarı sekmelerle boğmamak için en fazla 4 saniyede 1 yeni sekme aç
            if curr_time - self.last_browser_open_time > 4.0:
                self.last_browser_open_time = curr_time
                webbrowser.open(url)

    def _clear_hits_view(self):
        for widget in self.hits_container.winfo_children():
            widget.destroy()
        self.hits_count = 0

    def _clear_live_log(self):
        self.live_textbox.configure(state="normal")
        self.live_textbox.delete("1.0", "end")
        self.live_textbox.configure(state="disabled")

    def _open_txt_file(self):
        if not os.path.exists(self.txt_path):
            with open(self.txt_path, "w", encoding="utf-8") as f:
                f.write("=== BULUNAN AKTIF IP LISTESI ===\n\n")
        os.startfile(self.txt_path)

    def _open_csv_file(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", encoding="utf-8-sig") as f:
                f.write("Tarih,IP,Port,Protokol,Durum Kodu,Durum Aciklama,Sayfa Basligi,Web Sunucusu,URL\n")
        os.startfile(self.csv_path)

    def _on_close(self):
        if self.is_scanning:
            self._stop_scan()
        self.destroy()

if __name__ == "__main__":
    app = IPScannerApp()
    app.mainloop()
