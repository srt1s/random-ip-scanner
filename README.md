# Rastgele IP Web Tarayicisi (Random IP Discovery Studio)

Internet uzerindeki rastgele kamuya acik (public) IPv4 adreslerini yuksek hiz ve eszamanlilik ile tarayarak acik web sunucularini, yonetim panellerini ve siteleri tespit eden Python / PyQt6 tabanli kesif araci.

---

## Ozellikler

- **Modern PyQt6 Masaustu Arayuzu (Konsolsuz .exe Destekli)**:
  - Karanlik tema (Obsidian Slate), canli radar animasyonu ve gercek zamanli `IP/sn` hiz grafigi.
  - Sanallastirilmis yuksek performansli sonuc tablosu (on binlerce kayitta sifir takilma), siralama, anlik arama ve durum/bolge filtreleme.
  - Dahili **Kayit Arsivi (CSV)** sekmesi ile daha once bulunan siteleri goruntuleme, arama ve tarayicida acma.
  - Canli renkli telemetri akisi (`Canli Akis`), duraklatma ve filtreleme.
- **Akilli IP & Bolge Yonetimi**:
  - **Turkiye Odakli Tarama**: Turkiye'ye tahsis edilmis (RIPE NCC) **16.8 Milyon+** genel IPv4 adresi uzerinden secim yapar (`tr_ip_ranges.txt`).
  - **Global Mod**: Tek tikla tum dunya genel IP uzayina gecebilir.
  - Yerel ag (`10.x`, `192.168.x`, `127.x`, `172.16.x`) ve ayrilmis bloklar otomatik olarak elenir.
- **Durum Kodu Filtreleme & Kayit**:
  - `200 OK`: Acik web siteleri sayfa basligi (`<title>`) ve sunucu (`Server`) bilgisiyle kaydedilir.
  - `403 Forbidden` ve `401 Unauthorized`: Yonetim panelleri veya yetki isteyen servisler istege bagli olarak kaydedilir.
  - `404 Not Found` ve `Timeout`: Otomatik atlanir.
- **Disa Aktarim**:
  - `bulunan_ipler.txt`: Okunabilir metin gunlugu.
  - `bulunan_ipler.csv`: Excel uyumlu UTF-8 BOM CSV kaydi.

---

## Kullanim

### Yontem 1: Derlenmis Konsolsuz Uygulama (Onerilen)
Klasordeki `RandomIPScanner.exe` dosyasina cift tiklayarak siyah konsol penceresi acilmadan dogrudan masaustu uygulamasini baslatabilirsiniz. Bulunan sonuclar `.exe` dosyasinin bulundugu klasordeki `bulunan_ipler.txt` ve `bulunan_ipler.csv` dosyalarina yazilir.

### Yontem 2: Python ile Calistirma
```bash
pip install -r requirements.txt
python main.py
```

### Yontem 3: Komut Satiri Arayuzu (CLI)
```bash
python main.py --cli
```

---

## Derleme (PyInstaller ile Konsolsuz .exe)

```powershell
pyinstaller --noconfirm --clean --onefile --windowed --name "RandomIPScanner" --icon "assets/app_icon.ico" --add-data "tr_ip_ranges.txt;." --add-data "assets;assets" gui_app.py
```

---

## Yasal Uyari

Bu arac sadece egitim, ag arastirmasi ve guvenlik analizleri amaciyla gelistirilmistir. Kamuya acik IP adresleri uzerinde yapilan taramalarin dogurabilecegi yasal sorumluluk kullaniciya aittir.
