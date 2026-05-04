#!/usr/bin/env python3
"""
Specter — Network Pentesting Toolkit
CLI principal. Ejecutar con: python main.py [modulo] [opciones]

USO:
    python main.py recon   --target ejemplo.com
    python main.py scan    --target 192.168.1.0/24
    python main.py wifi    --iface wlan0
    python main.py mitm    --target 192.168.1.5 --gateway 192.168.1.1
    python main.py exploit --target 192.168.1.5
    python main.py post    --target 192.168.1.5
"""

import argparse
import sys
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = """
  ███████╗██████╗ ███████╗ ██████╗████████╗███████╗██████╗ 
  ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
  ███████╗██████╔╝█████╗  ██║        ██║   █████╗  ██████╔╝
  ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══╝  ██╔══██╗
  ███████║██║     ███████╗╚██████╗   ██║   ███████╗██║  ██║
  ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""

MODULES = {
    "recon":   "Reconocimiento OSINT (DNS, WHOIS, Shodan, subdominios)",
    "scan":    "Escaneo y enumeracion de red (Nmap wrapper)",
    "wifi":    "Ataques WiFi (monitor mode, handshake, deauth)",
    "mitm":    "Man-in-the-Middle (ARP spoofing, sniffing)",
    "exploit": "Explotacion de vulnerabilidades (Metasploit bridge)",
    "post":    "Post-explotacion y pivoting",
}


def print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/]")
    console.print(
        Panel(
            "[bold white]Network Pentesting Toolkit[/]\n"
            "[dim]Solo para uso autorizado — pentesting etico y legal[/]",
            border_style="cyan",
            expand=False,
        )
    )


def print_modules() -> None:
    from rich.table import Table
    table = Table(title="Modulos disponibles", border_style="cyan", header_style="bold magenta")
    table.add_column("Modulo", style="bold yellow")
    table.add_column("Descripcion")
    for name, desc in MODULES.items():
        table.add_row(name, desc)
    console.print(table)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specter",
        description="Specter — Network Pentesting Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "module",
        nargs="?",
        choices=list(MODULES.keys()),
        help="Modulo a ejecutar",
    )
    parser.add_argument("--target",   "-t", help="IP, rango CIDR o dominio objetivo")
    parser.add_argument("--iface",    "-i", help="Interfaz de red a usar")
    parser.add_argument("--gateway",  "-g", help="Gateway (para MITM)")
    parser.add_argument("--output",   "-o", help="Archivo de salida del reporte")
    parser.add_argument("--verbose",  "-v", action="store_true", help="Modo verbose")
    parser.add_argument("--list",     "-l", action="store_true", help="Listar modulos disponibles")
    return parser


def dispatch(args: argparse.Namespace) -> None:
    """Despacha la ejecucion al modulo correspondiente."""

    if args.module == "recon":
        from recon.recon import run
        run(target=args.target, verbose=args.verbose, output=args.output)

    elif args.module == "scan":
        from scan.scanner import run
        run(target=args.target, iface=args.iface, verbose=args.verbose, output=args.output)

    elif args.module == "wifi":
        from wifi.wifi_attack import run
        run(iface=args.iface, verbose=args.verbose, output=args.output)

    elif args.module == "mitm":
        from mitm.arp_spoof import run
        run(target=args.target, gateway=args.gateway, iface=args.iface, verbose=args.verbose)

    elif args.module == "exploit":
        from exploit.exploit import run
        run(target=args.target, verbose=args.verbose, output=args.output)

    elif args.module == "post":
        from post.post import run
        run(target=args.target, verbose=args.verbose, output=args.output)


def main() -> None:
    print_banner()
    parser = build_parser()
    args = parser.parse_args()

    if args.list or args.module is None:
        print_modules()
        console.print("\n[dim]Uso: python main.py [modulo] --target [objetivo][/]\n")
        sys.exit(0)

    dispatch(args)


if __name__ == "__main__":
    main()
