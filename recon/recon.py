"""
Specter — Modulo: Reconocimiento / OSINT
Tecnicas: WHOIS, DNS, subdominios, Shodan, headers HTTP.
"""

import socket
import json
from typing import Optional
from datetime import datetime
from pathlib import Path

import requests
import dns.resolver

from utils.helpers import banner, success, info, warning, error, print_table, timestamp, human_timestamp, ensure_dir
from utils.logger import get_logger
from config import SHODAN_API_KEY, REPORTS_DIR

log = get_logger("recon")


# ─── WHOIS basico via socket ───────────────────────────────────────────────────

def whois_lookup(domain: str) -> str:
    """Consulta WHOIS contra el servidor whois.iana.org."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("whois.iana.org", 43))
        s.send((domain + "\r\n").encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        return response.decode(errors="ignore")
    except Exception as e:
        return f"Error WHOIS: {e}"


# ─── DNS ──────────────────────────────────────────────────────────────────────

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

def dns_lookup(domain: str) -> dict:
    """Resuelve multiples tipos de registros DNS para un dominio."""
    results = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []
    return results


# ─── Subdominios (fuerza bruta con wordlist minima integrada) ─────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "vpn", "api", "dev", "staging",
    "test", "portal", "app", "m", "remote", "webmail", "ns1", "ns2",
    "smtp", "pop", "imap", "blog", "shop", "secure", "login", "auth",
]

def enumerate_subdomains(domain: str) -> list[dict]:
    """Intenta resolver subdominios comunes del dominio objetivo."""
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
            success(f"Encontrado: {fqdn} → {ip}")
        except socket.gaierror:
            pass
    return found


# ─── Headers HTTP ─────────────────────────────────────────────────────────────

def http_headers(target: str) -> dict:
    """Obtiene headers HTTP del objetivo para identificar tecnologias."""
    url = target if target.startswith("http") else f"https://{target}"
    try:
        resp = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        return dict(resp.headers)
    except Exception as e:
        error(f"No se pudo conectar a {url}: {e}")
        return {}


# ─── Shodan ───────────────────────────────────────────────────────────────────

def shodan_lookup(ip: str) -> dict:
    """Consulta Shodan para obtener info publica de una IP."""
    if not SHODAN_API_KEY:
        warning("SHODAN_API_KEY no configurado. Saltando consulta Shodan.")
        return {}
    try:
        import shodan
        api = shodan.Shodan(SHODAN_API_KEY)
        result = api.host(ip)
        return {
            "ip":        result.get("ip_str"),
            "org":       result.get("org"),
            "country":   result.get("country_name"),
            "ports":     result.get("ports", []),
            "vulns":     list(result.get("vulns", {}).keys()),
            "hostnames": result.get("hostnames", []),
        }
    except Exception as e:
        error(f"Shodan error: {e}")
        return {}


# ─── Resolver IP del target ───────────────────────────────────────────────────

def resolve_ip(target: str) -> Optional[str]:
    try:
        return socket.gethostbyname(target)
    except Exception:
        return None


# ─── Reporte ──────────────────────────────────────────────────────────────────

def save_report(target: str, data: dict, output: Optional[str]) -> Path:
    ensure_dir(REPORTS_DIR)
    filename = output or str(REPORTS_DIR / f"recon_{target.replace('/', '_')}_{timestamp()}.md")
    path = Path(filename)

    lines = [
        f"# Reporte de Reconocimiento — {target}",
        f"**Fecha:** {human_timestamp()}",
        "",
        "## IP Resuelta",
        f"`{data.get('ip', 'N/A')}`",
        "",
        "## WHOIS",
        "```",
        data.get("whois", "Sin datos")[:2000],
        "```",
        "",
        "## Registros DNS",
    ]
    for rtype, records in data.get("dns", {}).items():
        if records:
            lines.append(f"**{rtype}:** {', '.join(records)}")
    lines += [
        "",
        "## Subdominios encontrados",
    ]
    for s in data.get("subdomains", []):
        lines.append(f"- `{s['subdomain']}` → {s['ip']}")

    lines += [
        "",
        "## Headers HTTP",
        "```",
    ]
    for k, v in data.get("headers", {}).items():
        lines.append(f"{k}: {v}")
    lines += ["```", ""]

    if data.get("shodan"):
        sh = data["shodan"]
        lines += [
            "## Shodan",
            f"- **Org:** {sh.get('org')}",
            f"- **Pais:** {sh.get('country')}",
            f"- **Puertos:** {sh.get('ports')}",
            f"- **Vulnerabilidades:** {sh.get('vulns')}",
        ]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ─── Punto de entrada ─────────────────────────────────────────────────────────

def run(target: Optional[str], verbose: bool = False, output: Optional[str] = None) -> None:
    if not target:
        error("Debes especificar un objetivo con --target")
        return

    banner("RECON — Reconocimiento OSINT", f"Objetivo: {target}")

    data: dict = {"target": target}

    # Resolver IP
    info("Resolviendo IP...")
    ip = resolve_ip(target)
    data["ip"] = ip
    if ip:
        success(f"IP: {ip}")
    else:
        warning("No se pudo resolver la IP del objetivo.")

    # WHOIS
    info("Consultando WHOIS...")
    data["whois"] = whois_lookup(target)

    # DNS
    info("Enumerando registros DNS...")
    data["dns"] = dns_lookup(target)
    rows = [(k, ", ".join(v)) for k, v in data["dns"].items() if v]
    if rows:
        print_table("Registros DNS", ["Tipo", "Registros"], rows)

    # Subdominios
    info("Enumerando subdominios comunes...")
    data["subdomains"] = enumerate_subdomains(target)
    if not data["subdomains"]:
        warning("No se encontraron subdominios comunes.")

    # HTTP Headers
    info("Obteniendo headers HTTP...")
    data["headers"] = http_headers(target)
    if data["headers"]:
        rows = list(data["headers"].items())[:10]
        print_table("Headers HTTP", ["Header", "Valor"], rows)

    # Shodan
    if ip:
        info("Consultando Shodan...")
        data["shodan"] = shodan_lookup(ip)

    # Reporte
    report_path = save_report(target, data, output)
    success(f"Reporte guardado en: {report_path}")
