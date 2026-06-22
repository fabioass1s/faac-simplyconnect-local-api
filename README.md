# FAAC Gate LOCAL API

API REST (FastAPI) **local e simples** que controla o(s) seu(s) portão(ões) FAAC
SimplyConnect.

- 1 conta FAAC (no `.env`) → vários portões.
- 1 chave de API (`X-API-Key`) dá acesso a tudo.
- A `private_key` de cada portão fica guardada em `data/keys.json`.
- **O portão é o único conceito**: você endereça tudo por `/gates/{id}/...`.

> ⚠️ `.env` e `data/` contêm credenciais e chaves privadas (texto puro). Já estão
> no `.gitignore`. Não compartilhe.

## Configurar

```bash
cd faac-gate-api
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r requirements.txt

copy .env.example .env          # edite o .env
python -c "import secrets; print(secrets.token_urlsafe(32))"   # gera a API_KEY
```

`.env`:
```
IDENTIFIER=voce@email.com
PASSWORD=sua-senha-faac
BROWSER_NAME=python-auto
API_KEY=<a chave gerada>
HOST=127.0.0.1
PORT=8000
```

## Rodar

```bash
python run.py        # http://127.0.0.1:8000/docs
```

## Autenticação

Tudo (menos `GET /` e `GET /health`) exige o header `X-API-Key: <API_KEY>`.
O cliente **nunca** manda a senha do FAAC — ela fica só no servidor, que faz o
login sozinho.

### Login na FAAC (automático)

Não existe "fazer login" a cada requisição: o servidor loga sozinho com o `.env`
(`IDENTIFIER`/`PASSWORD`) antes da primeira chamada e renova quando expira. Para
**ver/testar** isso:

```bash
curl -s $B/account $H     # mostra a conta logada (loga se preciso)
curl -s -X POST $B/login $H   # força o login e confirma que o .env está certo
```

## Fluxo (a API te guia em cada passo)

Cada portão tem um **status**: `not_registered` → `pending` → `ready`. As respostas
trazem `instruction`/`steps` em texto simples dizendo o que fazer.

```bash
KEY="sua-api-key"; B="http://127.0.0.1:8000"
H="-H X-API-Key:$KEY"

# 1. lista os portões (cada um vem com status + instrução)
curl -s $B/gates $H
#  -> {"id":"...","name":"Casa avó","status":"not_registered",
#      "instruction":"Para usar 'Casa avó', cadastre uma vez: POST /gates/.../register"}

# 2. cadastra (a chave é GERADA no back-end, registra, e devolve o passo-a-passo
#    p/ autorizar no app)
curl -s -X POST $B/gates/<ID>/register $H -H 'content-type: application/json' -d '{}'
#  -> {"status":"pending","steps":["1. Abra o app...","4. Autorize 'browser-aut'",...]}
#  (rodar de novo é seguro — não duplica, só mostra o status)

# 3. autorize no app (passos acima). Depois confira:
curl -s $B/gates/<ID> $H        # -> "status":"ready"

# 4. abre: POST no id do portão + API key.
curl -s -X POST $B/gates/<ID> $H
```

Tem vários portões? Repita o passo 2 pra cada um. Depois, **abrir = POST no id do
portão** (cada um é independente):

```bash
curl -s -X POST $B/gates/<ID_CASA>    $H     # abre Casa
curl -s -X POST $B/gates/<ID_GARAGEM> $H     # abre Garagem
curl -s -X POST "$B/gates/<ID_CASA>?command=stop" $H   # para
```

## Endpoints

| Método + rota | O que faz |
|---|---|
| `GET /` · `GET /health` | Info / liveness (sem API key) |
| `GET /account` | Conta FAAC logada (loga sozinho com o `.env`) |
| `POST /login` | Força o login FAAC — testa se o `.env` está certo |
| `GET /gates` | Lista os portões com `status` + `instruction` |
| `GET /gates/{id}` | Status do portão + próximo passo (com `steps` se pendente) |
| **`POST /gates/{id}`** | **Abre o portão** (padrão). `?command=stop\|pedestrian` ou `?code=N` |
| `POST /gates/{id}/register` | Cadastra um portão (gera chave no back-end + registra + guia a autorizar). Idempotente — use `?force=true` para refazer o registro |
| `POST /gates/{id}/import` | Avançado: importa uma chave já autorizada (ex.: do notebook) |
| `GET /gates/{id}/commands` | Lista os comandos do portão |
| `GET /gates/{id}/key` | Exporta a chave salva (backup) |
| `DELETE /gates/{id}/key` | Esquece a chave salva localmente |

## ⚠️ Segurança, riscos e responsabilidade

> **Leia antes de usar.** Este é um projeto **simples, local e de uso pessoal**.
> Ele controla um portão físico — usado sem cautela, **pode ser explorado** e
> resultar em acesso indevido ao seu imóvel. Use por sua conta e risco.

**Pontos de atenção (e como eles podem ser explorados):**

- **Segredos em texto puro.** `.env` (login/senha FAAC) e `data/keys.json`
  (`private_key` de cada portão) ficam **sem criptografia** no disco. Quem ler
  esses arquivos **abre seu portão**. Mantenha-os fora de repositórios, backups
  públicos e máquinas compartilhadas (já estão no `.gitignore`).
- **A `API_KEY` é a única tranca da API.** Qualquer um com ela aciona todos os
  portões. Gere uma forte (`secrets.token_urlsafe(32)`), **nunca** versione, e
  troque se vazar. Uma chave fraca/curta é passível de **força bruta**.
- **Sem HTTPS, sem rate-limit, sem expiração.** O servidor é HTTP puro. Se você
  expor a porta na internet, a `API_KEY` trafega **em claro** (sniffável) e não há
  proteção contra tentativas repetidas. **Não exponha direto na internet.**
- **Rode só em `127.0.0.1`.** O padrão já é localhost. Para acesso remoto, use uma
  **rede privada (ex.: Tailscale/WireGuard)** ou um **proxy reverso com HTTPS** —
  nunca um `port-forward` cru no roteador.
- **A whitelist da FAAC é a real linha de defesa.** Mesmo com a chave, um portão
  só abre se o dispositivo foi **aprovado no app**. Revogue dispositivos antigos
  em `Home > Usuários > (conta) > Gerenciar > Outros dispositivos`.
- **Sem auditoria/garantia.** Este código **não passou** por auditoria de
  segurança. Pode conter falhas. Trate-o como um utilitário pessoal, não como um
  produto pronto para produção.

**Boas práticas mínimas:** máquina confiável só sua · `API_KEY` forte e secreta ·
acesso remoto só por VPN/HTTPS · backup das `private_key` num gerenciador de
senhas · revogar no app o que não usa mais.

> ⚖️ Controle **apenas portões que são seus** ou que você tem autorização
> explícita para operar. Você é o único responsável pelo uso.

## Notas técnicas

- `publicKey` é enviada como **string hex comprimida** no registro (array de ints
  faz o app crashar ao autorizar).
- `uuidm = SHA256("deviceUUID"+serial+"email"+email+"mobileId"+browserId)[:12]`.
- Comando: `cryptedPyl = AES-256-ECB/ZeroPadding` da chave
  `SHA-256(ECDH_p256(priv, device.publicKey).x)`.
- O registro é **por portão** e exige aprovação manual no app (segurança).
- Chaves em `data/keys.json` (+ `data/keys-backup.jsonl` append-only de segurança).
- Uso local: bind em `127.0.0.1`. Pra acesso remoto seguro sem mexer no código,
  use **Tailscale** (rede privada).
