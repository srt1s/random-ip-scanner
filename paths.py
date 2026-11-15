import os
import sys


def get_app_dir() -> str:
    """Calisma dizinini dondurur (derlenmisse .exe klasoru, degilse kaynak klasoru)."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def get_resource_path(relative_path: str) -> str:
    """Paket icindeki veya exe yanindaki salt-okunur kaynak dosyasinin yolunu cozer."""
    app_dir_candidate = os.path.join(get_app_dir(), relative_path)
    if os.path.exists(app_dir_candidate):
        return app_dir_candidate

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        bundled_candidate = os.path.join(meipass, relative_path)
        if os.path.exists(bundled_candidate):
            return bundled_candidate

    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)


def ensure_safe_stdio() -> None:
    """Konsolsuz (windowed) calismada None olan stdout/stderr akislarini guvenli hale getirir."""
    if sys.stdout is None:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
