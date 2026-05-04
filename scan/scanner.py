"""
Specter — Modulo: Escaneo y Enumeracion
Wrapper de Nmap con perfiles predefinidos para pentesting profesional.
"""

import nmap
from typing import Optional
from pathlib import Path

from utils.helpers import banner, success, info, warning, error, print_table, timestamp, human_timestamp, ensure_dir, check_tool
from utils.logger import get_logger
from config import REPORTS_DIR

log = get_logger("scan")


# ─── Perfiles de escaneo ──────────────────────────────────────────────────────

PROFILES = {
    "quick":      "-T4 -F",                                          # Top 100 puertos, rapido
    "default":    "-T4 -sV -sC -O",                                  # Version + scripts + OS
    "full":       "-T4 -p- -sV -sC -O",                              # Todos los puertos
    "stealth":    "-sS -T2 -f",                                       # SYN scan sigiloso
    "udp":        "-sU -T4 --top-ports 100",                          # Top 100 UDP
    "vuln":       "-sV --script=vuln",                                # Scripts de vulnerabilidades NSE
    "smb":        "-p 445 --script=smb-vuln*,smb-enum*",             # Especifico SMB
    "http":       "-p 80,443,8080,8443 --script=http-*",             # Especifico HTTP
}


# ─── Escaneo principal ────────────────────────────────────────────────────────

def scan(target: str, profile: str = "default", extra_args: str = "") -> dict:
    """
    Ejecuta un escaneo Nmap y retorna los resultados parseados.
    Requiere python-nmap y nmap instalado en el sistema.
    """
    if not check_tool("nmap"):
        return {}

    nm = nmap.PortScanner()
    args = PROFILES.get(profile, PROFILES["default"])
    if extra_args:
        args += f" {extra_args}"

    info(f"Iniciando escaneo [{profile}]: {target}")
    info(f"Argumentos nmap: {args}")

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        error(f"Error de Nmap (requiere root para algunos escaneos): {e}")
        return {}
    except Exception as e:
        error(f"Error inesperado: {e}")
        return {}

    return nm


# ─── Parseo de resultados ─────────────────────────────────────────────────────

def parse_results(nm: nmap.PortScanner) -> list[dict]:
    """Convierte los resultados de Nmap en una lista de hosts con sus detalles."""
    hosts = []
    for host in nm.all_hosts():
        host_data = {
            "ip":       host,
            "hostname": nm[host].hostname(),
            "state":    nm[host].state(),
            "os":       _get_os(nm, host),
            "ports":    [],
        }
        for proto in nm[host].all_protocols():
            for port, pdata in nm[host][proto].items():
                host_data["ports"].append({
                    "port":    port,
                    "proto":   proto,
                    "state":   pdata.get("state"),
                    "service": pdata.get("name"),
                    "version": f"{pdata.get('product', '')} {pdata.get('version', '')}".strip(),
                    "scripts": pdata.get("script", {}),
                })
        hosts.append(host_data)
    return hosts


def _get_os(nm: nmap.PortScanner, host: str) -> str:
    """Extrae la mejor estimacion de OS del resultado Nmap."""
    try:
        matches = nm[host]["osmatch"]
        if matches:
            best = matches[0]
            return f"{best['name']} ({best['accuracy']}%)"
    except (KeyError, IndexError):
        pass
    return "Desconocido"


# ─── Mostrar resultados en consola ────────────────────────────────────────────

def display_results(hosts: list[dict]) -> None:
    for host in hosts:
        success(f"Host: {host['ip']} ({host['hostname']}) — Estado: {host['state']}")
        info(f"OS detectado: {host['os']}")
        if host["ports"]:
            rows = [
                [p["port"], p["proto"].upper(), p["state"], p["service"], p["version"]]
                for p in host["ports"]
                if p["state"] == "open"
            ]
            if rows:
                print_table(
                    f"Puertos abiertos — {host['ip']}",
                    ["Puerto", "Proto", "Estado", "Servicio", "Version"],
                    rows,
                )
            # Mostrar scripts NSE si hay output
            for p in host["ports"]:
                for script_name, script_out in p.get("scripts", {}).items():
                    info(f"[NSE] {p['port']}/{script_name}:\n{script_out[:500]}")
        else:
            warning("No se encontraron puertos abiertos.")


# ─── Reporte ──────────────────────────────────────────────────────────────────

def save_report(target: str, hosts: list[dict], output: Optional[str]) -> Path:
    ensure_dir(REPORTS_DIR)
    filename = output or str(REPORTS_DIR / f"scan_{target.replace('/', '_')}_{timestamp()}.md")
    path = Path(filename)

    lines = [
        f"# Reporte de Escaneo — {target}",
        f"**Fecha:** {human_timestamp()}",
        "",
    ]
    for host in hosts:
        lines += [
            f"## Host: {host['ip']}",
            f"- **Hostname:** {host['hostname']}",
            f"- **Estado:** {host['state']}",
            f"- **OS:** {host['os']}",
            "",
            "### Puertos abiertos",
            "| Puerto | Proto | Servicio | Version |",
            "|--------|-------|----------|---------|",
        ]
        for p in host["ports"]:
            if p["state"] == "open":
                lines.append(f"| {p['port']} | {p['proto']} | {p['service']} | {p['version']} |")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ─── Punto de entrada ─────────────────────────────────────────────────────────

def run(
    target: Optional[str],
    iface: Optional[str] = None,
    profile: str = "default",
    verbose: bool = False,
    output: Optional[str] = None,
) -> None:
    if not target:
        error("Debes especificar un objetivo con --target (IP, rango CIDR o hostname)")
        return

    banner("SCAN — Escaneo y Enumeracion", f"Objetivo: {target} | Perfil: {profile}")

    nm = scan(target, profile=profile)
    if not nm:
        return

    hosts = parse_results(nm)
    if not hosts:
        warning("No se encontraron hosts activos.")
        return

    success(f"Hosts activos encontrados: {len(hosts)}")
    display_results(hosts)

    report_path = save_report(target, hosts, output)
    success(f"Reporte guardado en: {report_path}")
