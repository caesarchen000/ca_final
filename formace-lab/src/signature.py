"""Generate and verify signatures for stats.txt files."""

import hashlib
import getpass
import platform
import socket
from datetime import datetime
from pathlib import Path
from typing import Tuple, Optional


def generate_signature() -> Tuple[str, str, str, str]:
    """Generate signature components for stats.txt.

    Returns:
        Tuple of (username, os_info, timestamp, signature_hash)
    """
    username = getpass.getuser()
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()}"
    timestamp = datetime.now().isoformat()

    # Create signature: hash(username + hostname + os_info + timestamp)
    sig_input = f"{username}:{hostname}:{os_info}:{timestamp}"
    signature_hash = hashlib.sha256(sig_input.encode()).hexdigest()[:16]

    return username, os_info, timestamp, signature_hash


def append_signature_to_stats(stats_file: Path) -> None:
    """Append signature to stats.txt file.

    Args:
        stats_file: Path to stats.txt file
    """
    if not stats_file.exists():
        return

    username, os_info, timestamp, signature_hash = generate_signature()

    signature_block = f"""

---------- Begin Signature ----------
# Username: {username}
# OS: {os_info}
# Timestamp: {timestamp}
# Signature: {signature_hash}
---------- End Signature ----------
"""

    with open(stats_file, 'a') as f:
        f.write(signature_block)


def extract_signature(stats_file: Path) -> Optional[dict]:
    """Extract signature from stats.txt file.

    Args:
        stats_file: Path to stats.txt file

    Returns:
        Dictionary with signature components or None if not found
    """
    if not stats_file.exists():
        return None

    with open(stats_file, 'r') as f:
        content = f.read()

    # Find signature block
    if '---------- Begin Signature ----------' not in content:
        return None

    sig_section = content.split('---------- Begin Signature ----------')[1]
    sig_section = sig_section.split('---------- End Signature ----------')[0]

    result = {}
    for line in sig_section.strip().split('\n'):
        line = line.strip()
        if line.startswith('# Username:'):
            result['username'] = line.split(':', 1)[1].strip()
        elif line.startswith('# OS:'):
            result['os'] = line.split(':', 1)[1].strip()
        elif line.startswith('# Timestamp:'):
            result['timestamp'] = line.split(':', 1)[1].strip()
        elif line.startswith('# Signature:'):
            result['signature'] = line.split(':', 1)[1].strip()

    return result if result else None


def verify_timestamp_range(timestamp_str: str, start_date: str, end_date: str) -> bool:
    """Verify timestamp is within allowed range.

    Args:
        timestamp_str: ISO format timestamp string
        start_date: Start date in YYYY-MM-DD format
        end_date: End date in YYYY-MM-DD format

    Returns:
        True if timestamp is within range, False otherwise
    """
    try:
        timestamp = datetime.fromisoformat(timestamp_str)
        start = datetime.fromisoformat(f"{start_date}T00:00:00")
        end = datetime.fromisoformat(f"{end_date}T23:59:59")
        return start <= timestamp <= end
    except (ValueError, TypeError):
        return False
