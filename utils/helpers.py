"""
Specter — Helpers compartidos entre modulos.
"""

import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


# ─── Verificacion de herramientas ─────────────────────────────────────────────

def check_tool(name: str) -> bool:
    """Verifica si una herramienta externa esta disponible en el PATH."""
    available = shutil.which(name) is not None
    if not available:
        console.print(f"[bold red][!][/] Herramienta no encontrada: [yellow]{name}[/]")
    return available


def require_tools(*tools: str) -> bool:
    """Verifica multiples herramientas. Retorna False si alguna falta."""
    return all(check_tool(t) for t in tools)


# ─── Ejecucion de comandos ────────────────────────────────────────────────────

def run_command(
    cmd: list[str],
    capture: bool = True,
    timeout: Optional[int] = None,
) -> tuple[int, str, str]:
    """
    Ejecuta un comando externo.
    Retorna (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        console.print(f"[bold red][!][/] Timeout ejecutando: {' '.join(cmd)}")
        return -1, "", "Timeout"
    except FileNotFoundError:
        console.print(f"[bold red][!][/] Comando no encontrado: {cmd[0]}")
        return -1, "", "FileNotFoundError"


# ─── Timestamps ───────────────────────────────────────────────────────────────

def timestamp() -> str:
    """Retorna timestamp actual en formato YYYY-MM-DD_HH-MM-SS."""
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def human_timestamp() -> str:
    """Retorna timestamp legible para reportes."""
    return datetime.now().strftime("%d/%m/%Y %H:%M:%S")


# ─── Output CLI ───────────────────────────────────────────────────────────────

def banner(title: str, subtitle: str = "") -> None:
    """Imprime un banner de seccion."""
    content = f"[bold white]{title}[/]"
    if subtitle:
        content += f"\n[dim]{subtitle}[/]"
    console.print(Panel(content, border_style="cyan", expand=False))


def success(msg: str) -> None:
    console.print(f"[bold green][+][/] {msg}")


def info(msg: str) -> None:
    console.print(f"[bold cyan][*][/] {msg}")


def warning(msg: str) -> None:
    console.print(f"[bold yellow][!][/] {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red][x][/] {msg}")


def print_table(title: str, columns: list[str], rows: list[list]) -> None:
    """Imprime una tabla con Rich."""
    table = Table(title=title, border_style="cyan", header_style="bold magenta")
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)


# ─── Validacion de red ────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    """Valida formato basico de una IP."""
    import re
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def ensure_dir(path: Path) -> Path:
    """Crea el directorio si no existe y lo retorna."""
    path.mkdir(parents=True, exist_ok=True)
    return path
