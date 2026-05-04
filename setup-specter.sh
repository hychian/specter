#!/bin/bash
# =============================================================================
# setup-specter.sh — Instalador automatico de Specter en Kali Linux
# =============================================================================
# Uso:
#   curl -sL https://github.com/hychian/specter/raw/main/setup-specter.sh | bash
#
# O descargar y ejecutar:
#   wget https://github.com/hychian/specter/raw/main/setup-specter.sh
#   chmod +x setup-specter.sh && ./setup-specter.sh
# =============================================================================

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

REPO_URL="https://github.com/hychian/specter.git"
INSTALL_DIR="$HOME/specter"

echo -e "${CYAN}"
echo "  ╔═══════════════════════════════════════════════╗"
echo "  ║        Specter — Network Pentesting           ║"
echo "  ║              Instalador Automatico             ║"
echo "  ╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# ─── Verificar que estamos en Linux ──────────────────────────────────────────
if [[ "$(uname)" != "Linux" ]]; then
    echo -e "${RED}[!] Este script es para Linux. Estás en: $(uname)${NC}"
    echo -e "${YELLOW}[!] Se recomienda Kali Linux.${NC}"
    exit 1
fi

# ─── Verificar si es Kali ────────────────────────────────────────────────────
IS_KALI=false
if grep -qi kali /etc/os-release 2>/dev/null; then
    IS_KALI=true
    echo -e "${GREEN}[✓] Kali Linux detectado${NC}"
else
    echo -e "${YELLOW}[!] No es Kali Linux. Algunas herramientas pueden necesitar instalacion manual.${NC}"
fi

# ─── Actualizar repos e instalar dependencias del sistema ────────────────────
echo ""
echo -e "${CYAN}[*] Actualizando paquetes del sistema...${NC}"
sudo apt update

echo ""
echo -e "${CYAN}[*] Instalando herramientas de pentesting...${NC}"

if [[ "$IS_KALI" == true ]]; then
    # Kali ya trae casi todo, solo aseguramos
    sudo apt install -y \
        python3 python3-pip python3-venv \
        nmap \
        aircrack-ng \
        metasploit-framework \
        git
else
    # Otras distros Linux (Ubuntu/Debian)
    sudo apt install -y \
        python3 python3-pip python3-venv \
        nmap \
        aircrack-ng \
        metasploit-framework \
        git \
        build-essential \
        libpcap-dev
fi

# ─── Clonar repositorio ──────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[*] Clonando Specter desde GitHub...${NC}"
if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "${YELLOW}[!] El directorio $INSTALL_DIR ya existe. Actualizando...${NC}"
    cd "$INSTALL_DIR" && git pull
else
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# ─── Crear entorno virtual e instalar dependencias Python ────────────────────
echo ""
echo -e "${CYAN}[*] Creando entorno virtual Python...${NC}"
python3 -m venv venv
source venv/bin/activate

echo ""
echo -e "${CYAN}[*] Instalando dependencias Python...${NC}"
pip install --upgrade pip
pip install -r requirements.txt

# ─── Desactivar venv ─────────────────────────────────────────────────────────
deactivate

# ─── Configurar .env ─────────────────────────────────────────────────────────
echo ""
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
    echo -e "${CYAN}[*] Creando .env desde template...${NC}"
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
    echo -e "${YELLOW}[!] Edita $INSTALL_DIR/.env para configurar:${NC}"
    echo -e "${YELLOW}    - SHODAN_API_KEY (opcional)${NC}"
    echo -e "${YELLOW}    - OPERATOR_NAME${NC}"
    echo -e "${YELLOW}    - COMPANY_NAME${NC}"
else
    echo -e "${GREEN}[✓] .env ya existe${NC}"
fi

# ─── Verificar instalacion ───────────────────────────────────────────────────
echo ""
echo -e "${CYAN}[*] Verificando instalacion...${NC}"

echo ""
echo "────────────────────────────────────────────"
echo " Herramientas externas:"
echo "────────────────────────────────────────────"
TOOLS=("nmap" "airmon-ng" "airodump-ng" "aireplay-ng" "aircrack-ng" "msfconsole")
ALL_OK=true
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool  (no encontrada)"
        ALL_OK=false
    fi
done

echo ""
echo "────────────────────────────────────────────"
echo " Dependencias Python:"
echo "────────────────────────────────────────────"
source "$INSTALL_DIR/venv/bin/activate"
python3 -c "
import sys
pkgs = ['scapy', 'rich', 'paramiko', 'shodan', 'jinja2', 'dnspython', 'requests', 'python_nmap']
missing = []
for p in pkgs:
    try:
        __import__(p.replace('_', '').replace('python', ''))
        print(f'  ✓ {p}')
    except ImportError:
        missing.append(p)
if missing:
    print(f'  ✗ Faltan: {missing}')
" 2>/dev/null || echo -e "  ${YELLOW}[!] Verificacion rapida de Python fallo, pero pip ya instalo todo${NC}"
deactivate

# ─── Crear alias en .bashrc ──────────────────────────────────────────────────
echo ""
if ! grep -q "alias specter=" ~/.bashrc 2>/dev/null; then
    echo -e "${CYAN}[*] Agregando alias 'specter' a ~/.bashrc...${NC}"
    cat >> ~/.bashrc << 'EOF'

# Specter — Network Pentesting Toolkit
alias specter="cd $HOME/specter && source venv/bin/activate && python3 main.py"
alias specter-root="cd $HOME/specter && source venv/bin/activate && sudo python3 main.py"
EOF
    echo -e "${GREEN}[✓] Alias agregado. Reinicia tu terminal o corre: source ~/.bashrc${NC}"
else
    echo -e "${GREEN}[✓] Alias 'specter' ya existe en ~/.bashrc${NC}"
fi

# ─── Mensaje final ───────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║        Instalacion completada exitosamente!         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Directorio:${NC}  $INSTALL_DIR"
echo -e "  ${CYAN}Alias:${NC}       specter, specter-root"
echo ""
echo "  Ejemplos de uso:"
echo ""
echo "    # Listar modulos"
echo "    specter --list"
echo ""
echo "    # Reconocimiento OSINT (no requiere root)"
echo "    specter recon -t ejemplo.com"
echo ""
echo "    # Escaneo de red (requiere root para SYN scan)"
echo "    specter-root scan -t 192.168.1.0/24 -p full"
echo ""
echo "    # Escaneo de vulnerabilidades"
echo "    specter-root scan -t 192.168.1.5 -p vuln"
echo ""
echo "    # WiFi (requiere adapter externo)"
echo "    specter-root wifi -i wlan0"
echo ""
echo "    # MITM"
echo "    specter-root mitm -t 192.168.1.100 -g 192.168.1.1"
echo ""
echo "    # Explotacion (requiere msfrpcd)"
echo "    sudo msfrpcd -P specter123 -S -f &"
echo "    specter exploit -t 192.168.1.5"
echo ""
echo "    # Post-explotacion"
echo "    specter post -t 192.168.1.5"
echo ""
echo -e "${YELLOW}  Importante: Edita $INSTALL_DIR/.env con tus datos${NC}"
echo -e "${YELLOW}  y asegurate de tener autorizacion escrita antes de pentestear.${NC}"
echo ""
