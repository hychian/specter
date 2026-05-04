"""
Specter — Logger centralizado con Rich.
Todos los modulos deben importar el logger desde aqui.
"""

import logging
from rich.logging import RichHandler
from rich.console import Console
from config import LOG_LEVEL

console = Console()

def get_logger(name: str) -> logging.Logger:
    """Retorna un logger con formato Rich para el modulo dado."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(message)s",
        datefmt="[%H:%M:%S]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)],
    )
    return logging.getLogger(name)
