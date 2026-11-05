# Rastgele IP Web Tarayicisi (Random IP Discovery Tool)

Internet uzerindeki rastgele kamuya acik (public) IPv4 adreslerini yuksek hiz ve eszamanlilik ile tarayarak acik web sunucularini, yonetim panellerini ve siteleri tespit eden Python tabanli kesif araci.

---

## Ozellikler

- Akilli IP Uretimi: Yerel ag (10.x.x.x, 192.168.x.x, 127.x.x.x), multicast ve ozel ayrilmis IP bloklarini otomatik olarak filtreler. Yalnizca genel (public) IP adreslerini sorgular.
- Durum Kodu Filtreleme:
  - 404 Not Found ve Timeout (Zaman Asimi): Hedef otomatik olarak atlanir ve siradaki IP adresine gecilir.
  - 200 OK (Aktif Web Sitesi): Adres aninda tespit edilir, sayfa basligi (`<title>`) ve sunucu banner bilgisi (`Server: Apache, Nginx, IIS vb.`) ayristirilir.
  - 403 Forbidden (Erisim Kisitli / Yonetim Paneli): Olasilikla admin panelleri veya yetkilendirme isteyen servisler listeye ve kayitlara dahil edilir.
- Coklu Calisma Modu:
  - Modern Grafiksel Kullanici Arayuzu (GUI - CustomTkinter destegiyle).
  - Terminal / Konsol Modu (CLI - Rich tablo gorunumu destegiyle).
- Kayit ve Disa Aktarim:
  - `bulunan_ipler.txt`: Okunabilir detayli metin gunlugu.
  - `bulunan_ipler.csv`: Excel ve diger veri analizi araclariyla tam uyumlu, UTF-8 BOM kodlamali CSV tablosu.
- Dogrudan Tarayicida Acma:
  - Bulunan herhangi bir hedefe cift tiklayarak varsayilan tarayicida acabilme.
  - Arayuz uzerinden "200 OK'leri Tarayicida Ac" secenegi acildiginda bulunan her aktif siteyi otomatik yeni sekmede acma destegi.

---

## Gereksinimler

- Python 3.9 veya daha yuksek bir surum
- Gerekli Python paketleri (`requirements.txt` icerisinde listelenmistir)

---

## Kurulum

1. Repoyu bilgisayariniza klonlayin:
```bash
git clone https://github.com/srt1s/random-ip-scanner.git
cd random-ip-scanner
```

2. Bagimliliklari yukleyin:
```bash
pip install -r requirements.txt
```

---

## Kullanim

### Yontem 1: Tek Tikla Baslatma (Windows)
Klasordeki `start.bat` dosyasina cift tiklayarak grafik arayuzu baslatabilirsiniz.

### Yontem 2: Grafik Arayuzu (GUI)
```bash
python main.py
```

### Yontem 3: Komut Satiri Arayuzu (CLI)
```bash
python main.py --cli
```

---

## Arayuz Ayarlari ve Parametreler

- Eszamanlilik (Concurrency): Ayni anda paralel taranacak IP sayisi (Onerilen: 30 - 100).
- Zaman Asimi (Timeout): Yanit vermeyen sunuculardan ne kadar sure sonra vazgecilecegi (Onerilen: 1.5 - 2.0 saniye).
- Protokol: HTTP (Port 80), HTTPS (Port 443) veya her ikisi.
- User-Agent Rotasyonu: Isteklerin engellenmemesi icin yaygin tarayici basliklari otomatik uygulanir.

---

## Yasal Uyari

Bu arac sadece egitim, ag arastirmasi ve guvenlik analizleri amaciyla gelistirilmistir. Kamuya acik IP adresleri uzerinde yapilan taramalarin dogurabilecegi yasal sorumluluk kullaniciya aittir.
