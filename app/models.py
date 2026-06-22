"""Modelos Pydantic dos corpos de requisição."""
from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    # opcionais: nome do browser e/ou reutilizar uma private_key existente.
    # No fluxo normal você NÃO manda private_key — o back-end gera o par de chaves.
    browser_id: Optional[str] = Field("navg", examples=["navg"])  # padrão: "navg"
    private_key: Optional[str] = Field("", examples=[""])       # cole a chave já autorizada



class ImportIn(BaseModel):
    # importa uma chave JÁ autorizada (ex.: extraída do navegador). Não registra
    # nada na FAAC nem precisa aprovar no app.
    # examples=[...] força o valor exibido no /docs (sem isso o Swagger mostra "string")
    private_key: Optional[str] = Field("", examples=[""])       # cole a chave já autorizada
    uuidm: Optional[str] = Field(None, examples=[""])           # se ausente, calcula do browser_id
    browser_id: Optional[str] = Field("navg", examples=["navg"])  # padrão: "navg"
