"""Product naming constants for the GuToChat transition."""
from __future__ import annotations

PRODUCT_NAME = "GuToChat"
FORMER_PRODUCT_NAME = "LoRa Chat"
TECHNICAL_APP_ID = "lorachat-v2"
PRODUCT_DISPLAY_NAME = PRODUCT_NAME
PRODUCT_LEGACY_DISPLAY_NAME = f"{PRODUCT_NAME} / {FORMER_PRODUCT_NAME}"
TECHNICAL_CONFIG_DIR = ".config/lorachat-v2"
TECHNICAL_BACKUP_DIR = "lorachat-v2-backups"


def transition_name() -> str:
    """Return the user-facing transition label."""
    return f"{PRODUCT_NAME}, formerly {FORMER_PRODUCT_NAME}"
