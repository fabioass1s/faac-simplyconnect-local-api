"""
FAAC Gate API — simples e local.

- 1 conta FAAC (.env) -> vários portões.
- 1 chave de API (X-API-Key) dá acesso a tudo.
- A private_key de cada portão fica guardada em data/keys.json.
- O portão é o único conceito: você endereça tudo por /gates/{id}/...

Fluxo:
  GET /gates                       -> lista os portões
  POST /gates/{id}/register        -> gera a chave + registra (uma vez por portão)
  (autoriza no app)
  GET /gates/{id}                  -> confere se já foi autorizado
  POST /gates/{id}/open            -> abre (sempre)
"""
from __future__ import annotations

import hmac
import time
from typing import Callable, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException

from . import config, faac, store
from .models import ImportIn, RegisterIn

API_DESCRIPTION = """
Controle local do(s) seu(s) portão(ões) **FAAC SimplyConnect**.

- 1 conta FAAC (no `.env` do servidor) → vários portões.
- 1 chave de API (header `X-API-Key`) dá acesso a tudo.
- O servidor faz **login sozinho** na FAAC com as credenciais do `.env` — você nunca manda a senha.
- A `private_key` de cada portão é gerada no back-end e guardada em `data/keys.json`.
- Tudo é endereçado pelo **`access_point_id`** (o `id` único do portão).

---

## 🔑 Autenticação

Todas as rotas (menos `GET /` e `GET /health`) exigem o header:

```
X-API-Key: <a chave do .env>
```

---

## 📋 Passo a passo (faça uma vez por portão)

**1. Confira que o login do `.env` está OK**
> `GET /account` — mostra a conta FAAC logada (loga sozinho se preciso).
> Se der erro, ajuste `IDENTIFIER` / `PASSWORD` no `.env`.

**2. Liste seus portões e pegue o `access_point_id`**
> `GET /gates` — devolve cada portão com `id`, `name`, `online` e `status`.
> Copie o `id` do portão que você quer controlar.

**3. Registre o portão** (gera a chave no back-end e pede aprovação na FAAC)
> `POST /gates/{access_point_id}/register` com corpo `{}`.
> Isso cria um "dispositivo web" e dispara uma **notificação de aprovação** no app.
> Para refazer um registro: `POST /gates/{access_point_id}/register?force=true`.

**4. Aprove o dispositivo no app FAAC SimplyConnect (no celular)**
> Abra o app e **aprove a notificação** do novo dispositivo. Se não aparecer:
> `Home > Usuários > (sua conta) > Gerenciar > Outros dispositivos` e aprove ali.

**5. Confira se ficou pronto**
> `GET /gates/{access_point_id}` — o `status` deve virar **`ready`**.
> `status`: `not_registered` (registre) → `pending` (aprove no app) → `ready` (pode abrir).

**6. Veja os comandos disponíveis do portão** (opcional)
> `GET /gates/{access_point_id}/commands` — lista os comandos com seus `code`.

**7. Acione o portão**
> `POST /gates/{access_point_id}` — **abre** (padrão).
> `POST /gates/{access_point_id}?command=stop` ou `?command=pedestrian`.
> `POST /gates/{access_point_id}?code=N` — envia um `code` específico (veja o passo 6).
> A resposta traz `state_before`/`state_after` (ex.: `Fechado` → `Abrindo`),
> aguardando alguns segundos para confirmar a transição. Para respostas rápidas
> use `?status_mode=predict` (deduz o resultado sem esperar) ou `?status_mode=off`
> (só envia). Veja os modos no detalhe do endpoint.

**8. Veja o estado físico do portão** (abrindo / fechando / aberto / fechado)
> `GET /gates/{access_point_id}/status` — `state.code` = CLOSED | OPENING | OPEN |
> CLOSING | UNKNOWN, `state.label` em português e `state.moving` (em movimento?).
> Não confunda com o `status` de cadastro (not_registered/pending/ready).

---

## 🔁 Já tenho uma chave autorizada (avançado)

Se você já extraiu uma `private_key` **já aprovada** (ex.: do notebook), pule o
registro/aprovação: `POST /gates/{access_point_id}/import` — funciona na hora.

## ⚠️ Limite de dispositivos

A FAAC limita quantos "dispositivos web" cada conta pode ter. Se o registro
retornar `max_device_in_wl_reached`, apague um dispositivo antigo no app
(`Home > Usuários > (conta) > Gerenciar > Outros dispositivos`) e tente de novo.
"""

app = FastAPI(
    title="FAAC Gate API",
    version="3.0.0",
    description=API_DESCRIPTION,
)


# --------------------------------------------------------------------------- #
#  Auth da API
# --------------------------------------------------------------------------- #
def require_api_key(x_api_key: Optional[str] = Header(None, alias="X-API-Key")) -> None:
    if not config.API_KEY:
        raise HTTPException(500, "API_KEY não configurada no .env do servidor.")
    if not x_api_key or not hmac.compare_digest(x_api_key, config.API_KEY):
        raise HTTPException(401, "X-API-Key ausente ou inválida.")


# --------------------------------------------------------------------------- #
#  Sessão FAAC (auto-login server-side, com cache e re-login)
# --------------------------------------------------------------------------- #
class Faac:
    def __init__(self):
        self.http = faac.new_session()
        self.logged_in = False
        self.user_id: Optional[str] = None
        self.email: Optional[str] = None

    def login(self) -> None:
        if not config.IDENTIFIER or not config.PASSWORD:
            raise HTTPException(500, "IDENTIFIER/PASSWORD não configurados no .env.")
        self.http = faac.new_session()
        try:
            u = faac.login(self.http, config.IDENTIFIER, config.PASSWORD)
        except faac.FaacError as e:
            raise HTTPException(502, f"Login FAAC falhou: {e.status} {e.detail}")
        self.user_id, self.email, self.logged_in = u["user_id"], u["email"], True

    def ensure(self) -> None:
        if not self.logged_in:
            self.login()

    def call(self, fn: Callable, *args, **kwargs):
        self.ensure()
        try:
            return fn(self.http, *args, **kwargs)
        except faac.FaacError as e:
            if e.status in (401, 403):   # cookie expirou -> relog e tenta 1x
                self.login()
                try:
                    return fn(self.http, *args, **kwargs)
                except faac.FaacError as e2:
                    raise HTTPException(502, f"FAAC API {e2.status}: {e2.detail}")
            raise HTTPException(502, f"FAAC API {e.status}: {e.detail}")


FAAC = Faac()


def _find_gate(access_point_id: str) -> dict:
    ap = next((a for a in FAAC.call(faac.list_access_points) if a["id"] == access_point_id), None)
    if not ap:
        raise HTTPException(404, f"Portão '{access_point_id}' não encontrado na sua conta.")
    return ap


def _register_one(ap: dict, browser_name: Optional[str],
                  private_key: Optional[str] = None) -> dict:
    """Cadastra UM portão: resolve serial/publicKey, gera (ou reusa) o par de chaves,
    registra o browser na whitelist da FAAC e salva tudo em data/keys.json.

    A private_key é gerada no back-end por padrão; só é reaproveitada se vier em
    `private_key` (uso avançado). Não trata idempotência — quem chama decide.
    Retorna o registro salvo (inclui private_key e uuidm gerados)."""
    access_point_id = ap["id"]
    serial, device_pub = ap["serial"], ap["public_key"]
    if not serial or not device_pub:   # fallback no detalhe do portão
        devs = FAAC.call(faac.get_ap_devices, access_point_id)
        if devs:
            serial = serial or devs[0]["serial"]
            device_pub = device_pub or devs[0]["public_key"]
    if not serial or not device_pub:
        raise HTTPException(409, f"Portão '{ap['name']}' sem serial/publicKey — "
                                 "não dá para cadastrar.")

    FAAC.ensure()  # garante user_id/email
    browser_name = (browser_name or config.BROWSER_NAME).strip() or "python-auto"
    if private_key:
        priv = private_key.strip()
        try:
            pub = faac.public_from_private(priv)
        except ValueError:
            raise HTTPException(422, "private_key inválida (esperado hex de 64 chars).")
    else:
        priv, pub = faac.generate_keypair()   # <- chave gerada no back-end

    browser_id = faac.make_browser_id(FAAC.user_id, browser_name)
    uuidm = faac.compute_uuidm(serial, FAAC.email, browser_id)
    try:
        FAAC.call(faac.register_browser, access_point_id, browser_id, browser_name, pub, FAAC.user_id)
    except HTTPException as e:
        if "max_device_in_wl_reached" in str(e.detail):
            raise HTTPException(
                409,
                f"Limite de dispositivos web da FAAC atingido nesta conta — não dá para "
                f"registrar '{ap['name']}' agora. Abra o app FAAC SimplyConnect, vá em "
                "Home > Usuários / (Selecione a conta X) / Gerenciar / Outros dispositivos / "
                "(Apague algum) dispositivo web antigo que você não usa mais, e rode o "
                "registro de novo. "
                "(Se você já tem uma chave autorizada para este portão, use "
                f"POST /gates/{access_point_id}/import em vez de registrar.)",
            )
        raise

    rec = {
        "name": ap["name"], "serial": serial, "device_public_key": device_pub,
        "browser_name": browser_name, "browser_id": browser_id,
        "uuidm": uuidm, "private_key": priv,
    }
    store.save_key(access_point_id, rec)
    return rec


def _send(access_point_id: str, code: int) -> dict:
    rec = store.get_key(access_point_id)
    if not rec:
        raise HTTPException(409, f"Portão sem chave. Rode POST /gates/{access_point_id}/register.")
    res = FAAC.call(faac.send_command, access_point_id, rec["uuidm"],
                    rec["private_key"], rec["device_public_key"], code)
    res["gate"] = rec.get("name") or access_point_id
    return res


def _poll_state(access_point_id: str, before_ls, timeout: float = 6.0,
                interval: float = 1.0) -> dict:
    """Lê o estado por alguns segundos até o logicalStatus mudar em relação a
    `before_ls` (o portão leva ~3-4s para começar a se mover) e devolve esse
    primeiro estado já diferente. Se nada mudar até o timeout, devolve a última
    leitura."""
    deadline = time.monotonic() + timeout
    last = FAAC.call(faac.get_gate_status, access_point_id)
    while time.monotonic() < deadline:
        if last.get("logicalStatus") != before_ls:
            return last
        time.sleep(interval)
        last = FAAC.call(faac.get_gate_status, access_point_id)
    return last


def _status(access_point_id: str, rec: Optional[dict]) -> str:
    """Estado do cadastro: not_registered | pending | ready."""
    if not rec:
        return "not_registered"
    bid = rec.get("browser_id")
    if not bid:
        return "ready"   # chave importada já vem autorizada
    return "ready" if FAAC.call(faac.is_authorized, access_point_id, bid) else "pending"


def _auth_steps(name: str, browser_name: str, access_point_id: str) -> list:
    return [
        "1. Abra o app FAAC SimplyConnect no celular, ou mantenha aberto",
        "2. Espere a notificação do portão aparecer",
        f"3. Clique em APROVAR",
        "4. Caso contrario, vá em Home > Usuários > Selecione a conta > Gerenciar > Outros dispositivos > Procure o dispositivo chamado '{browser_name}' e aprove",
        "5. Caso não apareça, refaça o procedimento de registro (POST /gates/{access_point_id}/register) e aguarde a notificação no app",
        f"5. Volte e rode GET /gates/{access_point_id} — o status deve virar 'ready'",
    ]


def _instruction(status: str, access_point_id: str, name: str, browser_name: str) -> str:
    if status == "not_registered":
        return f"Para usar '{name}', cadastre uma vez: POST /gates/{access_point_id}/register"
    if status == "pending":
        return (f"Quase lá! Autorize '{browser_name}' no app FAAC (portão '{name}'), "
                f"depois confira em GET /gates/{access_point_id}.")
    return f"Pronto! Para abrir '{name}': POST /gates/{access_point_id}"


# --------------------------------------------------------------------------- #
#  Health (sem API key)
# --------------------------------------------------------------------------- #
@app.get("/", tags=["health"])
def root():
    return {
        "name": "FAAC Gate API",
        "auth": "header X-API-Key em tudo (exceto /health e esta)",
        "docs": "/docs",
        "login_faac": "automático (credenciais do .env). Veja: GET /account ou POST /login",
        "fluxo": ["GET /account (testa o .env)", "GET /gates",
                  "POST /gates/{id}/register", "(autoriza no app)",
                  "GET /gates/{id}", "POST /gates/{id}  (abre)"],
    }


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "logged_in": FAAC.logged_in, "api_key_set": bool(config.API_KEY)}


# --------------------------------------------------------------------------- #
#  Rotas protegidas
# --------------------------------------------------------------------------- #
api = APIRouter(dependencies=[Depends(require_api_key)])


@api.post("/login", tags=["account"])
def account_login():
    """Faz login na FAAC com as credenciais do .env (e confirma que estão certas).

    Normalmente você NÃO precisa chamar isto — o servidor loga sozinho antes de
    qualquer chamada. Serve para testar o .env.
    """
    FAAC.login()
    return {"logged_in": True, "configured_identifier": config.IDENTIFIER,
            "email": FAAC.email, "user_id": FAAC.user_id,
            "message": "Login na FAAC OK — credenciais do .env válidas."}


@api.get("/account", tags=["account"])
def account():
    """Mostra a conta FAAC do .env (loga automaticamente se ainda não tiver logado)."""
    FAAC.ensure()
    return {"logged_in": FAAC.logged_in, "configured_identifier": config.IDENTIFIER,
            "email": FAAC.email, "user_id": FAAC.user_id}


@api.get("/gates", tags=["gates"])
def gates():
    """Lista os portões da conta com status e o que fazer em seguida.

    status: not_registered (cadastre) | pending (autorize no app) | ready (pode abrir)
    """
    out = []
    for a in FAAC.call(faac.list_access_points):
        rec = store.get_key(a["id"])
        status = _status(a["id"], rec)
        bn = (rec or {}).get("browser_name") or config.BROWSER_NAME
        out.append({
            "id": a["id"], "name": a["name"], "online": a["online"],
            "status": status,
            "instruction": _instruction(status, a["id"], a["name"], bn),
        })
    return {"gates": out}


@api.get("/gates/{access_point_id}", tags=["gates"])
def gate_detail(access_point_id: str):
    """Status do portão + instrução do próximo passo (em texto simples)."""
    ap = _find_gate(access_point_id)
    rec = store.get_key(access_point_id)
    status = _status(access_point_id, rec)
    bn = (rec or {}).get("browser_name") or config.BROWSER_NAME
    res = {"id": access_point_id, "name": ap["name"], "online": ap["online"],
           "status": status,
           "instruction": _instruction(status, access_point_id, ap["name"], bn)}
    if status == "pending":
        res["steps"] = _auth_steps(ap["name"], bn, access_point_id)
    return res


@api.post("/gates/{access_point_id}/register", tags=["gates"])
def gate_register(access_point_id: str, body: RegisterIn, force: bool = False):
    """Cadastra o portão: gera uma chave, registra na FAAC e te guia a autorizar
    no app.

    Por padrão é idempotente: se já tem chave salva, não registra de novo — só
    informa o status. Use `?force=true` para **registrar de novo mesmo assim**
    (gera uma chave nova e substitui a salva; exige autorizar de novo no app).
    """
    ap = _find_gate(access_point_id)

    # idempotente: se já tem chave, não registra de novo; só informa onde você está
    # (a menos que force=true, aí refaz o registro do zero)
    rec = store.get_key(access_point_id)
    if rec and not force:
        status = _status(access_point_id, rec)
        if status == "ready":
            return {"status": "ready", "gate": ap["name"],
                    "message": f"'{ap['name']}' já está cadastrado e autorizado. "
                               f"Para abrir: POST /gates/{access_point_id}. "
                               f"Para refazer mesmo assim: ?force=true",
                    "force_hint": f"POST /gates/{access_point_id}/register?force=true"}
        return {"status": "pending", "gate": ap["name"],
                "message": f"'{ap['name']}' já foi cadastrado; falta só autorizar no app. "
                           f"Para refazer o registro: ?force=true",
                "steps": _auth_steps(ap["name"], rec.get("browser_name", "?"), access_point_id),
                "force_hint": f"POST /gates/{access_point_id}/register?force=true"}

    rec = _register_one(ap, body.browser_id, body.private_key)
    verbo = "Registro refeito" if force else "Cadastro iniciado"
    return {
        "status": "pending", "gate": ap["name"], "forced": force,
        "message": f"{verbo} para '{ap['name']}'. Agora autorize no app:",
        "steps": _auth_steps(ap["name"], rec["browser_name"], access_point_id),
        "private_key": rec["private_key"], "uuidm": rec["uuidm"],
        "BACKUP": "A private_key foi salva em data/keys.json (+ backup). Copie-a para um "
                  "gerenciador de senhas — é a única cópia que sobrevive à perda do disco.",
    }


@api.post("/gates/{access_point_id}/import", tags=["gates"])
def gate_import(access_point_id: str, body: ImportIn):
    """Importa uma chave JÁ autorizada (ex.: extraída do navegador/notebook).
    Não registra nada na FAAC nem exige aprovação no app — funciona na hora."""
    ap = _find_gate(access_point_id)
    serial, device_pub = ap["serial"], ap["public_key"]
    if not serial or not device_pub:
        devs = FAAC.call(faac.get_ap_devices, access_point_id)
        if devs:
            serial = serial or devs[0]["serial"]
            device_pub = device_pub or devs[0]["public_key"]
    if not device_pub:
        raise HTTPException(409, "Portão sem publicKey — não dá para importar.")

    priv = (body.private_key or "").strip()
    if not priv:
        raise HTTPException(422, "private_key obrigatória para importar (cole a chave já "
                                 "autorizada — hex de 64 chars).")
    try:
        faac.public_from_private(priv)
    except ValueError:
        raise HTTPException(422, "private_key inválida (esperado hex de 64 chars).")

    if body.uuidm:
        uuidm = body.uuidm.strip()
    elif body.browser_id:
        FAAC.ensure()
        uuidm = faac.compute_uuidm(serial, FAAC.email, body.browser_id.strip())
    else:
        raise HTTPException(422, "Informe uuidm, ou browser_id para calcular o uuidm.")

    store.save_key(access_point_id, {
        "name": ap["name"], "serial": serial, "device_public_key": device_pub,
        "browser_name": "imported", "browser_id": (body.browser_id or "").strip(),
        "uuidm": uuidm, "private_key": priv,
    })
    return {"imported": True, "gate": ap["name"], "uuidm": uuidm,
            "next": f"POST /gates/{access_point_id}  (abre)"}


@api.delete("/gates/{access_point_id}/key", tags=["gates"])
def gate_forget(access_point_id: str):
    """Esquece a chave salva localmente (não mexe na whitelist do FAAC)."""
    if not store.delete_key(access_point_id):
        raise HTTPException(404, "Nenhuma chave salva para esse portão.")
    return {"forgotten": access_point_id}


@api.get("/gates/{access_point_id}/key", tags=["gates"])
def gate_key(access_point_id: str):
    """Exporta a chave salva (inclui private_key) para backup."""
    rec = store.get_key(access_point_id)
    if not rec:
        raise HTTPException(404, "Nenhuma chave salva para esse portão.")
    return {"access_point_id": access_point_id, **rec,
            "aviso": "contém a private_key — guarde num gerenciador de senhas."}


@api.get("/gates/{access_point_id}/commands", tags=["gates"])
def gate_commands(access_point_id: str):
    return {"commands": FAAC.call(faac.list_commands, access_point_id)}


@api.get("/gates/{access_point_id}/status", tags=["gates"])
def gate_status(access_point_id: str):
    """Estado FÍSICO atual do portão: abrindo / fechando / aberto / fechado.

    Lê o `logicalStatus` do portão e traduz:
    - `state.code`  : CLOSED | OPENING | OPEN | CLOSING | UNKNOWN
    - `state.label` : rótulo em português
    - `state.moving`: True se está em movimento (abrindo/fechando)

    (Não confunda com o `status` de cadastro de GET /gates/{id}, que é
    not_registered/pending/ready.)
    """
    ap = _find_gate(access_point_id)
    st = FAAC.call(faac.get_gate_status, access_point_id)
    return {"id": access_point_id, "name": ap["name"], **st}


_COMMAND_CODES = {"open": 1, "pedestrian": 2, "stop": 3}


_STATUS_MODES = ("confirm", "predict", "now", "off")


@api.post("/gates/{access_point_id}", tags=["gates"])
def gate_action(access_point_id: str, command: str = "open",
                code: Optional[int] = None, status_mode: str = "confirm"):
    """Aciona o portão. Por padrão ABRE.

    - POST /gates/{id}                  -> abre
    - POST /gates/{id}?command=stop     -> para   (ou pedestrian)
    - POST /gates/{id}?code=13          -> envia um code específico

    `status_mode` controla como o `state_after` é obtido:

    - **`confirm`** (padrão): espera alguns segundos e lê o estado REAL da nuvem
      (mais lento, ~6s, mas confirma a transição: Fechado → Abrindo).
    - **`predict`**: *ultrarrápido*. Lê só o estado ATUAL e **deduz** o resultado
      do comando (fechado+abrir → Abrindo; aberto+abrir → Fechando). Não confirma
      na nuvem — `state_after.predicted = true`.
    - **`now`**: lê o estado imediatamente após enviar (snapshot; como o portão
      leva ~3-4s para se mexer, costuma ainda mostrar o estado anterior).
    - **`off`**: não lê nada — só envia o comando (resposta mínima, sem `state_*`).

    `state_before` vem em todos os modos, menos `off`.
    """
    if code is None:
        code = _COMMAND_CODES.get(command.lower())
        if code is None:
            raise HTTPException(422, f"command inválido: '{command}'. "
                                     "Use open/pedestrian/stop, ou ?code=N.")
    if status_mode not in _STATUS_MODES:
        raise HTTPException(422, f"status_mode inválido: '{status_mode}'. "
                                 f"Use um de: {', '.join(_STATUS_MODES)}.")

    if status_mode == "off":
        return _send(access_point_id, code)

    before = FAAC.call(faac.get_gate_status, access_point_id)
    res = _send(access_point_id, code)

    if status_mode == "predict":
        after_state = faac.predict_state(before["state"]["code"], code)
        online = before.get("online")
    else:  # confirm | now
        after = (_poll_state(access_point_id, before.get("logicalStatus"))
                 if status_mode == "confirm"
                 else FAAC.call(faac.get_gate_status, access_point_id))
        after_state = after["state"]
        online = after.get("online")

    res["state_before"] = before["state"]
    res["state_after"] = after_state
    res["label"] = after_state["label"]
    res["online"] = online
    return res


app.include_router(api)
