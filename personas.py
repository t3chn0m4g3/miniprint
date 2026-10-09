"""Device personalities. Responses approximate an EWS, not a complete firmware image.

Banner references: https://github.com/nmap/nmap/blob/master/nmap-service-probes
(Brother Debut; HP ChaiServer). Lexmark banner and /cgi-bin routes:
https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-26067.yaml
Brother routes and BRFIRMWARE fields:
https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/admin/misc/brother_default_admin_auth_bypass_cve_2024_51978.rb
PJL response framing and variable syntax:
https://www.hp.com/ctg/Manual/bpl13208.pdf (PJL Technical Reference Manual).
Serial formats and firmware lists are plausible synthetic identities.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import string
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Persona:
    name: str
    vendor: str
    model: str
    pjl_id: str
    banner: str
    title: str
    status_path: str
    login_path: str
    admin_prefix: str
    firmware_versions: tuple[str, ...]
    cve_hints: dict[str, str]

    @property
    def seed_dir(self) -> Path:
        return Path(__file__).parent / "fake-files" / self.name

    def info(self, family: str, identity: Identity) -> str:
        values = {
            "CONFIG": f'MODEL="{self.model}"\r\nLANGUAGES=3\r\nPCL\r\nPOSTSCRIPT\r\nPDF',
            "FILESYS": "VOLUME TOTALSIZE FREESIZE LOCATION LABEL\r\n0: 16777216 12582912 RAM ",
            "MEMORY": "TOTAL=67108864\r\nLARGEST=33554432",
            "PAGECOUNT": "12457",
            "PRODINFO": f'MODEL="{self.model}"\r\nSERIALNUMBER="{identity.serial}"\r\nFIRMWARE="{identity.firmware}"',
            "BRFIRMWARE": f'SERIAL="{identity.serial}"\r\nMAIN="{identity.firmware}"',
        }
        return values.get(family, "")


PERSONAS = {
    "brother": Persona(
        "brother",
        "Brother",
        "MFC-L9570CDW",
        "Brother MFC-L9570CDW",
        "Debut/1.30",
        "Brother MFC-L9570CDW",
        "/general/status.html",
        "/general/status.html",
        "/admin",
        ("ZL", "ZK", "ZJ"),
        {
            "serial_leak_probe": "CVE-2024-51977",
            "default_password_probe": "CVE-2024-51978",
            "default_password_success": "CVE-2024-51978",
            "pjl_crash_probe": "CVE-2024-51982",
            "passback_attempt": "CVE-2024-51984",
        },
    ),
    "hp": Persona(
        "hp",
        "HP",
        "LaserJet 4200",
        "hp LaserJet 4200",
        "HP-ChaiServer/3.0",
        "HP LaserJet 4200   ",
        "/hp/device/this.LCDispatcher",
        "/hp/device/DevicePassword/Index",
        "/hp/device",
        ("20051202 08.015.0", "20050819 08.014.0"),
        {},
    ),
    "lexmark": Persona(
        "lexmark",
        "Lexmark",
        "MX521ade",
        "Lexmark MX521ade",
        "Lexmark_Web_Server",
        "Lexmark MX521ade",
        "/webglue/content?c=Status",
        "/webglue/login",
        "/cgi-bin",
        ("MXTGM.240.201", "MXTGM.230.041"),
        {"path_traversal_probe": "CVE-2025-1127", "ssrf_probe": "CVE-2025-9269"},
    ),
}


@dataclass(frozen=True)
class Identity:
    persona: str
    serial: str
    hostname: str
    mac_suffix: str
    firmware: str

    def profile(self) -> dict[str, str]:
        persona = PERSONAS[self.persona]
        return {
            "manufacturer": persona.vendor,
            "model": persona.model,
            "serial": self.serial,
            "hostname": self.hostname,
            "firmware": self.firmware,
            "location": "Office",
        }


def new_identity(name: str) -> Identity:
    persona = PERSONAS[name]
    digits = "".join(secrets.choice(string.digits) for _ in range(6))
    suffix = secrets.token_hex(3).upper()
    serial = {
        "brother": f"E78321M4N{digits}",
        "hp": "CN" + secrets.token_hex(4).upper(),
        "lexmark": "72" + secrets.token_hex(3).upper(),
    }[name]
    prefix = {"brother": "BRN", "hp": "NPI", "lexmark": "ET"}[name]
    return Identity(name, serial, prefix + suffix, suffix, secrets.choice(persona.firmware_versions))


def load_identity(selection: str, state_dir: str | Path, logger: logging.Logger, *, reroll: bool = False) -> Identity:
    if selection not in (*PERSONAS, "random"):
        raise ValueError("Unknown persona")
    directory = Path(state_dir)
    path = directory / "identity.json"
    if not reroll:
        try:
            identity = Identity(**json.loads(path.read_text()))
            if (
                identity.persona in PERSONAS
                and all(isinstance(value, str) and value for value in asdict(identity).values())
                and selection in ("random", identity.persona)
            ):
                return identity
        except OSError, ValueError, TypeError:
            pass
    name = secrets.choice(tuple(PERSONAS)) if selection == "random" else selection
    identity = new_identity(name)
    temporary = directory / f".identity-{secrets.token_hex(8)}.tmp"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with temporary.open("x") as handle:
            os.chmod(temporary, 0o600)
            json.dump(asdict(identity), handle)
        os.replace(temporary, path)
    except OSError:
        logger.warning(
            "Identity kept in memory; state directory is not writable",
            extra={"event": "identity_ephemeral", "persona": name},
        )
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
    return identity
