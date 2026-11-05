import sys
import os

# Paket yolunu ayarla
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

def main():
    if "--cli" in sys.argv:
        from random_ip_scanner.cli_scanner import main as cli_main
        cli_main()
    else:
        from random_ip_scanner.gui_app import IPScannerApp
        app = IPScannerApp()
        app.mainloop()

if __name__ == "__main__":
    main()
