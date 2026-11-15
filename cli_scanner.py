import asyncio
import os
import sys

from rich.console import Console
from rich.panel import Panel

try:
    from random_ip_scanner.paths import get_app_dir
    from random_ip_scanner.scanner_engine import IPScannerEngine
except ImportError:
    from paths import get_app_dir
    from scanner_engine import IPScannerEngine

console = Console()


def main():
    base_dir = get_app_dir()
    txt_path = os.path.join(base_dir, "bulunan_ipler.txt")
    csv_path = os.path.join(base_dir, "bulunan_ipler.csv")

    is_global = "--global" in sys.argv
    target_region = "GLOBAL" if is_global else "TR"
    region_label = "Tum Dunya (Global)" if is_global else "Sadece Turkiye (16.8M IP)"

    console.print(Panel.fit(
        f"[bold cyan]Rastgele IP Web Tarayicisi (CLI Modu)[/bold cyan]\n"
        f"[bold yellow]Hedef Bolge:[/bold yellow] [bold green]{region_label}[/bold green]\n"
        "[dim]404 ve Timeout'lar atlanir, 200 OK ve 403 Forbidden kaydedilir.[/dim]\n"
        f"[yellow]Kayit Dosyalari:[/yellow] {txt_path} | {csv_path}",
        border_style="cyan",
    ))

    def on_result(res, is_hit):
        if is_hit:
            status = res.get("status")
            url = res.get("url")
            title = res.get("title") or "Baslik yok"
            server = res.get("server") or "Bilinmiyor"
            flag = "[TR]" if res.get("region") == "TR" else "[GLOBAL]"

            if status == 200:
                console.print(f"[bold green][200 OK][/bold green] {flag} [bold underline white]{url}[/bold underline white] | [cyan]{title}[/cyan] | [dim]{server}[/dim]")
            elif status == 403:
                console.print(f"[bold yellow][403 FORBIDDEN][/bold yellow] {flag} [bold underline white]{url}[/bold underline white] | [dim]Sunucu: {server}[/dim]")
            else:
                console.print(f"[bold magenta][{status}][/bold magenta] {flag} [white]{url}[/white]")

    engine = IPScannerEngine(
        txt_log_path=txt_path,
        csv_log_path=csv_path,
        on_result=on_result,
    )
    engine.concurrency = 50
    engine.timeout_sec = 1.5
    engine.scan_mode = "http"
    engine.target_region = target_region

    console.print("[green]Tarama baslatiliyor... Durdurmak icin Ctrl + C tuslarina basin.[/green]\n")

    try:
        asyncio.run(engine.run_async_scan())
    except KeyboardInterrupt:
        console.print("\n[red]Tarama kullanici tarafindan durduruldu.[/red]")
        engine.stop()


if __name__ == "__main__":
    main()
