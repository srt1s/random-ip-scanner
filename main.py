import multiprocessing
import os
import sys

# Paket yolunu ayarla
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if not getattr(sys, "frozen", False):
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)


def main() -> None:
    if "--cli" in sys.argv:
        try:
            from random_ip_scanner.cli_scanner import main as cli_main
        except ImportError:
            from cli_scanner import main as cli_main
        cli_main()
    else:
        try:
            from random_ip_scanner.gui_app import launch_gui
        except ImportError:
            from gui_app import launch_gui
        sys.exit(launch_gui())


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
