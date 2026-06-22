"""Configuração via .env (carregado automaticamente)."""
from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

# ---- Credenciais FAAC (ficam só no servidor) ----
IDENTIFIER = os.getenv("IDENTIFIER", "")
PASSWORD = os.getenv("PASSWORD", "")
BROWSER_NAME = os.getenv("BROWSER_NAME", "python-auto")

# ---- Chave de acesso da SUA API (o cliente manda no header X-API-Key) ----
API_KEY = os.getenv("API_KEY", "")

# ---- Bind (local por padrão) ----
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
