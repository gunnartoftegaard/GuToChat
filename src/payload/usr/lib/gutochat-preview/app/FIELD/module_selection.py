"""Explicit optional private-radio selection; no hardware or service I/O."""
from typing import Any, Mapping

def private_radio_enabled(config: Mapping[str, Any]) -> bool:
    # Preserve existing installations unless an operator explicitly opts out.
    value = config.get("private_radio_enabled", True)
    if not isinstance(value, bool):
        raise ValueError("private_radio_enabled must be true or false")
    return value
