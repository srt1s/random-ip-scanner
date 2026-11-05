import sys
import os
import time
import asyncio
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from random_ip_scanner.scanner_engine import IPScannerEngine

console = Console()

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    txt_path = os.path.join(base_dir, "bulunan_ipler.txt")
    csv_path = os.path.join(base_dir, "bulunan_ipler.csv")

    console.print(Panel.fit(
        "[bold cyan]🌐 Rastgele IP Web Tarayıcısı (CLI Modu)[/bold cyan]\n"
        "[dim]404 ve Timeout'lar atlanır, 200 OK ve 403 Forbidden kaydedilir.[/dim]\n"
        f"[yellow]Kayıt Dosyaları:[/yellow] {txt_path} | {csv_path}",
        border_style="cyan"
    ))

    def on_result(res, is_hit):
        if is_hit:
            status = res.get("status")
            url = res.get("url")
            title = res.get("title") or "Başlık yok"
            server = res.get("server") or "Bilinmiyor"

            if status == 200:
                console.print(f"[bold green]✔ [200 OK][/bold green] [bold underline white]{url}[/bold underline white] | [cyan]{title}[/cyan] | [dim]{server}[/dim]")
            elif status == 403:
                console.print(f"[bold yellow]⛔ [403 FORBIDDEN][/bold yellow] [bold underline white]{url}[/bold underline white] | [dim]Sunucu: {server}[/dim]")
            else:
                console.print(f"[bold magenta]⚡ [{status}][/bold magenta] [white]{url}[/white]")

    engine = IPScannerEngine(
        txt_log_path=txt_path,
        csv_log_path=csv_path,
        on_result=on_result
    )
    engine.concurrency = 50
    engine.timeout_sec = 1.5
    engine.scan_mode = "http"

    console.print("[green]Tarama başlatılıyor... Durdurmak için Ctrl + C tuşlarına basın.[/green]\n")

    try:
        asyncio.run(engine.run_async_scan())
    except KeyboardInterrupt:
        console.print("\n[red]Tarama kullanıcı tarafından durduruldu.[/red]")
        engine.stop()

if __name__ == "__main__":
    main()
