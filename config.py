"""
Specter — Network Pentesting Toolkit
Configuracion global del proyecto.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno desde .env (si existe)
load_dotenv()

# ─── Rutas base ────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
DATA_DIR    = BASE_DIR / "engagements"

# ─── API Keys opcionales ───────────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# ─── Herramientas externas (paths por defecto) ────────────────────────────────
NMAP_PATH       = os.getenv("NMAP_PATH", "nmap")
AIRMON_PATH     = os.getenv("AIRMON_PATH", "airmon-ng")
AIRCRACK_PATH   = os.getenv("AIRCRACK_PATH", "aircrack-ng")
BETTERCAP_PATH  = os.getenv("BETTERCAP_PATH", "bettercap")
HASHCAT_PATH    = os.getenv("HASHCAT_PATH", "hashcat")
JOHN_PATH       = os.getenv("JOHN_PATH", "john")
TCPDUMP_PATH    = os.getenv("TCPDUMP_PATH", "tcpdump")

# ─── Configuracion de red ─────────────────────────────────────────────────────
DEFAULT_INTERFACE   = os.getenv("DEFAULT_INTERFACE", "eth0")
MONITOR_INTERFACE   = os.getenv("MONITOR_INTERFACE", "wlan0")
DEFAULT_TIMEOUT     = int(os.getenv("DEFAULT_TIMEOUT", "30"))

# ─── Configuracion de reportes ────────────────────────────────────────────────
REPORT_FORMAT   = os.getenv("REPORT_FORMAT", "markdown")   # markdown | html
OPERATOR_NAME   = os.getenv("OPERATOR_NAME", "Specter Operator")
COMPANY_NAME    = os.getenv("COMPANY_NAME", "")

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")   # DEBUG | INFO | WARNING | ERROR
