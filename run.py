"""Sobe o servidor local: python run.py"""
import uvicorn

from app import config

if __name__ == "__main__":
    if not config.API_KEY:
        print("[aviso] API_KEY vazia no .env — as rotas vão responder 500. "
              "Gere uma: python -c \"import secrets; print(secrets.token_urlsafe(32))\"")
    if not config.IDENTIFIER or not config.PASSWORD:
        print("[aviso] IDENTIFIER/PASSWORD vazios no .env — o login FAAC vai falhar.")
    print(f"FAAC Gate API em http://{config.HOST}:{config.PORT}/docs")
    uvicorn.run("app.main:app", host=config.HOST, port=config.PORT, reload=True)
