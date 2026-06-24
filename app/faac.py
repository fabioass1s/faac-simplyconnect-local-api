"""
Núcleo FAAC SimplyConnect — portado do notebook abre_portao_autonomo.ipynb.

Tudo aqui é função pura ou recebe um requests.Session já logado.
A criptografia foi validada contra capturas reais:
  shared = SHA-256( ECDH_p256(privateKey, device.publicKey).x )
  cryptedPyl = AES-256-ECB / ZeroPadding sobre o JSON do pyl
"""
from __future__ import annotations

import hashlib
import json
import secrets
import string
import time
from typing import Any, Optional

import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

API_BASE = "https://us-api-prod.faacsimplyconnect.com/v2"

BASE_HEADERS = {
    "accept": "application/json, text/plain, */*",
    "app-name": "simplyconnect_enduser",
    "app-version": "3.11.0",
    "content-type": "application/json",
    "origin": "https://am-user.faacsimplyconnect.com",
    "referer": "https://am-user.faacsimplyconnect.com/",
}

# rótulos amigáveis por ícone (apenas exibição; o que vale é o "code")
ICON_LABELS = {
    "GATE_OPEN": "Abrir (total)",
    "GATE_CLOSE": "Fechar",
    "GATE_PARTIAL_OPEN": "Abrir parcial / pedestre",
    "STOP": "Parar",
    "PARTIAL_BIDIRECTIONAL": "Parcial bidirecional",
}

# Estado físico do portão, lido do campo inteiro `logicalStatus` da automação.
# Mapa validado observando o portão real (notebook dev_status.ipynb):
#   abrir : 0 -> 1 -> 2     fechar: 2 -> 5 -> 0
# Tupla: (code técnico, rótulo PT, moving?). 3/4/6/7 não observados ainda.
LOGICAL_STATUS = {
    0: ("CLOSED",  "Fechado",  False),
    1: ("OPENING", "Abrindo",  True),
    2: ("OPEN",    "Aberto",   False),
    5: ("CLOSING", "Fechando", True),
}


def decode_logical_status(value) -> dict:
    """Traduz o inteiro `logicalStatus` em {raw, code, label, moving}.

    Para valores ainda não mapeados devolve code UNKNOWN e moving=None
    (não sabemos se está parado), sem quebrar."""
    if value is None:
        return {"raw": None, "code": "UNKNOWN", "label": "Desconhecido", "moving": None}
    code, label, moving = LOGICAL_STATUS.get(
        value, ("UNKNOWN", f"Estado {value} (desconhecido)", None))
    return {"raw": value, "code": code, "label": label, "moving": moving}


def predict_state(before_code: str, command_code: int) -> dict:
    """Estima o estado resultante a partir do estado ATUAL + comando, SEM consultar
    a nuvem de novo (modo ultrarrápido).

    O portão é toggle: acionar quando fechado abre, quando aberto fecha. É só um
    palpite — o resultado real depende da configuração do portão — por isso o
    estado devolvido vem com `predicted: True`.
    """
    def _s(code, label, moving):
        return {"raw": None, "code": code, "label": label,
                "moving": moving, "predicted": True}

    if command_code == 3:                       # parar
        return _s("STOPPED", "Parado", False)
    if before_code in ("CLOSED", "CLOSING"):    # mais fechado -> vai abrir
        return _s("OPENING", "Abrindo", True)
    if before_code in ("OPEN", "OPENING"):      # mais aberto -> vai fechar
        return _s("CLOSING", "Fechando", True)
    return _s("UNKNOWN", "Desconhecido", None)


# --------------------------------------------------------------------------- #
#  Helpers de parsing
# --------------------------------------------------------------------------- #
def to_signed_int8(data) -> list[int]:
    return [x - 256 if x > 127 else x for x in data]


def ints_to_hex(v) -> str:
    """publicKey vem como lista de ints (com ou sem sinal) ou já como hex."""
    if isinstance(v, list):
        return bytes((x % 256) for x in v).hex()
    return v or ""


def pick(d: Any, *keys):
    for k in keys:
        if isinstance(d, dict) and d.get(k) not in (None, ""):
            return d[k]
    return None


def extract_items(payload: Any) -> list:
    """Acha a lista de itens dentro de formatos variados (inclui page.items)."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("items", "item", "data", "accessPoints", "content", "results", "page"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
            if isinstance(v, dict):
                inner = extract_items(v)
                if inner:
                    return inner
    return []


# --------------------------------------------------------------------------- #
#  Criptografia
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[str, str]:
    """Gera par p256. Retorna (private_hex 64 chars, public_hex comprimida 66 chars)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_hex = format(priv.private_numbers().private_value, "064x")
    pub_bytes = priv.public_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return priv_hex, pub_bytes.hex()


def public_from_private(priv_hex: str) -> str:
    """Deriva a public key comprimida (hex) a partir da private key hex."""
    po = ec.derive_private_key(int(priv_hex, 16), ec.SECP256R1()).public_key()
    return po.public_bytes(Encoding.X962, PublicFormat.CompressedPoint).hex()


def make_browser_id(user_id: str, browser_name: str) -> str:
    rnd_hex = secrets.token_hex(12)
    rnd_suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    return f"{user_id}{rnd_hex}={browser_name}?{rnd_suffix}"


def compute_uuidm(serial: str, email: str, browser_id: str) -> str:
    s = "deviceUUID" + serial + "email" + email.lower() + "mobileId" + browser_id
    return hashlib.sha256(s.encode()).hexdigest()[:12]


def calculate_checksum(idx: int, val: Optional[int] = None) -> int:
    s = format(idx + val if val is not None else idx, "x")
    if len(s) % 2 == 1:
        s = "0" + s
    b = bytes.fromhex(s)
    tot = b[0]
    for x in b[1:]:
        tot += x
    tot += 1
    inv = (~tot) & 0xFFFFFFFF
    binr = bin(inv)[2:]
    if len(binr) > 8:
        binr = binr[-8:]
    return int(binr, 2)


def derive_session_key(priv_hex: str, dev_pub_hex: str) -> str:
    priv = ec.derive_private_key(int(priv_hex, 16), ec.SECP256R1())
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(dev_pub_hex))
    x32 = priv.exchange(ec.ECDH(), peer)
    return hashlib.sha256(x32).hexdigest()


def _zero_pad(d: bytes, b: int = 16) -> bytes:
    return d if len(d) % b == 0 else d + b"\x00" * (b - len(d) % b)


def _aes_ecb_encrypt(key_hex: str, pt: bytes) -> bytes:
    enc = Cipher(algorithms.AES(bytes.fromhex(key_hex)), modes.ECB()).encryptor()
    return enc.update(_zero_pad(pt)) + enc.finalize()


def build_command_body(uuidm: str, priv_hex: str, dev_pub_hex: str, com: int,
                       cmd_basic: int = 20) -> dict:
    session_key = derive_session_key(priv_hex, dev_pub_hex)
    token = int(time.time() * 1000)
    pyl = {"com": com, "cks": calculate_checksum(com), "token": token}
    plain = json.dumps(pyl, separators=(",", ":")).encode("utf-8")
    crypted = to_signed_int8(_aes_ecb_encrypt(session_key, plain))
    return {"cmd": cmd_basic, "pyl": pyl, "uuidm": uuidm, "cryptedPyl": crypted}


# --------------------------------------------------------------------------- #
#  Chamadas à API (recebem um requests.Session)
# --------------------------------------------------------------------------- #
class FaacError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(f"HTTP {status}: {detail}")


def new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(BASE_HEADERS)
    return s


def login(session: requests.Session, identifier: str, password: str) -> dict:
    body = {"identifier": identifier, "password": password, "scope": "smartaccess"}
    r = session.post(f"{API_BASE}/login", data=json.dumps(body))
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    item = r.json().get("item", {})
    user = item.get("user", {})
    return {
        "user_id": user.get("userId") or user.get("id"),
        "email": user.get("email"),
        "name": " ".join(filter(None, [user.get("firstName"), user.get("lastName")])) or None,
    }


def list_access_points(session: requests.Session) -> list[dict]:
    r = session.get(
        f"{API_BASE}/simply-connect/access-points/archived",
        params={"page": 1, "pageSize": 50,
                "sortOnlineOfflineDateCreation": "true", "excludeArchived": "true"},
    )
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    aps = []
    for i, it in enumerate(extract_items(r.json())):
        if not isinstance(it, dict):
            continue
        dev = it.get("device") if isinstance(it.get("device"), dict) else {}
        aps.append({
            "index": i,
            "id": pick(it, "id", "_id", "accessPointId"),
            "name": pick(it, "name", "alias", "label", "description") or "(sem nome)",
            "online": it.get("online"),
            "brand": it.get("brand"),
            "serial": pick(dev, "serialNumber", "serial"),
            "public_key": ints_to_hex(pick(dev, "publicKey")),
        })
    return aps


def get_gate_status(session: requests.Session, ap_id: str) -> dict:
    """Estado físico atual do portão (abrindo/fechando/aberto/fechado/...).

    Fonte: o mesmo /access-points/archived que list_access_points já usa — cada
    item traz `logicalStatus` (int) + flags. Não custa chamada extra de rede
    além deste GET. Devolve {logicalStatus, state, online, inError, inAlarm,
    modfun, lastConnectionOn, found}."""
    r = session.get(
        f"{API_BASE}/simply-connect/access-points/archived",
        params={"page": 1, "pageSize": 50,
                "sortOnlineOfflineDateCreation": "true", "excludeArchived": "true"},
    )
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    item = next((it for it in extract_items(r.json())
                 if isinstance(it, dict) and pick(it, "id", "_id", "accessPointId") == ap_id),
                None)
    if item is None:
        return {"found": False, "logicalStatus": None,
                "state": decode_logical_status(None), "online": None,
                "inError": None, "inAlarm": None, "modfun": None,
                "lastConnectionOn": None}
    ls = item.get("logicalStatus")
    return {
        "found": True,
        "logicalStatus": ls,
        "state": decode_logical_status(ls),
        "online": item.get("online"),
        "inError": item.get("inError"),
        "inAlarm": item.get("inAlarm"),
        "modfun": item.get("modfun"),
        "lastConnectionOn": item.get("lastConnectionOn"),
    }


def get_ap_devices(session: requests.Session, ap_id: str) -> list[dict]:
    r = session.get(f"{API_BASE}/smartaccess/access-point/{ap_id}")
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    d = r.json()
    if isinstance(d, dict) and isinstance(d.get("item"), dict):
        d = d["item"]
    if isinstance(d.get("devices"), list) and d["devices"]:
        raw = d["devices"]
    elif isinstance(d.get("device"), dict):
        raw = [d["device"]]
    else:
        raw = []
    return [{
        "id": pick(dev, "id", "_id", "deviceId"),
        "serial": pick(dev, "serialNumber", "serial"),
        "public_key": ints_to_hex(pick(dev, "publicKey")),
    } for dev in raw]


def list_commands(session: requests.Session, ap_id: str) -> list[dict]:
    r = session.get(
        f"{API_BASE}/smartaccess/access-point/{ap_id}/commands",
        params={"page": 1, "pageSize": 0, "accessPointId": ap_id},
    )
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    data = r.json()
    page = data.get("page") if isinstance(data, dict) else None
    items = (page.get("items") if isinstance(page, dict) else None) or data.get("items", [])
    cmds = []
    for it in items:
        cmds.append({
            "code": it.get("code"),
            "icon": it.get("icon"),
            "label": ICON_LABELS.get(it.get("icon"), it.get("icon") or "?"),
            "description": it.get("userDescription") or it.get("description") or "",
            "password_required": bool(it.get("passwordRequired")),
            "position": it.get("userPosition") if it.get("userPosition") is not None else 999,
        })
    cmds.sort(key=lambda c: c["position"])
    for i, c in enumerate(cmds):
        c["index"] = i
    return cmds


def register_browser(session: requests.Session, ap_id: str, browser_id: str,
                     browser_name: str, public_key_hex: str, user_id: str) -> dict:
    # publicKey TEM que ser string hex comprimida (array de ints faz o app crashar ao autorizar)
    body = {
        "browserId": browser_id,
        "browserName": browser_name,
        "publicKey": public_key_hex,
        "userId": user_id,
    }
    url = f"{API_BASE}/smartaccess/access-point/{ap_id}/whitelist/browser"
    r = session.post(url, data=json.dumps(body))
    if r.status_code not in (200, 201):
        raise FaacError(r.status_code, r.text[:300])
    return r.json() if r.text else {"status": "ok"}


def is_authorized(session: requests.Session, ap_id: str, browser_id: str) -> bool:
    """Checa a whitelist do portão; True se o browser_id já está confiável."""
    r = session.get(
        f"{API_BASE}/simply-connect/automations/{ap_id}/whitelist",
        params={"browserId": browser_id, "filterByClientId": "true"},
    )
    if r.status_code != 200:
        return False
    for entry in extract_items(r.json()):
        if not isinstance(entry, dict):
            continue
        for bp in entry.get("uuidmAndPublicKeys", []) or []:
            if bp.get("browserId") == browser_id:
                return True
    return False


def send_command(session: requests.Session, ap_id: str, uuidm: str, priv_hex: str,
                 dev_pub_hex: str, com: int) -> dict:
    body = build_command_body(uuidm, priv_hex, dev_pub_hex, com)
    url = f"{API_BASE}/smartaccess/access-point/{ap_id}/mqtt-message"
    r = session.post(url, data=json.dumps(body))
    if r.status_code != 200:
        raise FaacError(r.status_code, r.text[:300])
    return {"http": r.status_code, "response": r.json() if r.text else None,
            "command_code": com, "pyl": body["pyl"]}
