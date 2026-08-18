"""Integração com Google Calendar (Fase 2) — OAuth 2.0 + Calendar API.

Degradação graciosa: se faltar lib ou env, `is_enabled()` retorna False e o app
continua subindo normalmente (o CRM cai no link/.ics da Fase 1). Nada de 500 por
falta de config — mesmo princípio do _NoopLimiter usado para o slowapi.

Refresh tokens são SEMPRE criptografados (Fernet/GOOGLE_TOKEN_KEY) antes de ir ao banco.
"""
import os
import json
import base64
import logging
from datetime import datetime, timedelta

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

logger = logging.getLogger("google_sync")

# Evita "Scope has changed" quando o Google adiciona openid/email aos escopos concedidos.
os.environ.setdefault("OAUTHLIB_RELAX_TOKEN_SCOPE", "1")

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")  # opcional; senão deriva da request
GOOGLE_TOKEN_KEY = os.getenv("GOOGLE_TOKEN_KEY")

# calendar.events é o escopo funcional; openid+email só para exibir o e-mail conectado.
SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/calendar.events",
]
AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
REVOKE_URI = "https://oauth2.googleapis.com/revoke"
TZ = "America/Sao_Paulo"

try:
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import Flow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    from google.auth.transport.requests import Request as GoogleRequest
    from cryptography.fernet import Fernet
    _LIBS_OK = True
except Exception as e:  # pragma: no cover - caminho de degradação
    logger.warning("Libs do Google indisponíveis (%s); integração Google DESATIVADA", e)
    _LIBS_OK = False

_fernet = None
if _LIBS_OK and GOOGLE_TOKEN_KEY:
    try:
        _fernet = Fernet(GOOGLE_TOKEN_KEY.encode() if isinstance(GOOGLE_TOKEN_KEY, str) else GOOGLE_TOKEN_KEY)
    except Exception as e:  # pragma: no cover
        logger.warning("GOOGLE_TOKEN_KEY inválida (%s); integração Google DESATIVADA", e)
        _fernet = None


class ReconnectRequired(Exception):
    """Refresh token revogado/expirado — o corretor precisa reconectar."""


def is_enabled() -> bool:
    return bool(_LIBS_OK and GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and _fernet)


# ── Criptografia do refresh token ─────────────────────────────────────────────
def encrypt_token(plain: str) -> str:
    return _fernet.encrypt(plain.encode()).decode()


def decrypt_token(cipher: str) -> str:
    return _fernet.decrypt(cipher.encode()).decode()


# ── OAuth ─────────────────────────────────────────────────────────────────────
def _client_config(redirect_uri):
    return {"web": {
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "auth_uri": AUTH_URI,
        "token_uri": TOKEN_URI,
        "redirect_uris": [redirect_uri],
    }}


def build_auth_url(state: str, redirect_uri: str) -> str:
    flow = Flow.from_client_config(_client_config(redirect_uri), scopes=SCOPES, redirect_uri=redirect_uri)
    url, _ = flow.authorization_url(
        access_type="offline", prompt="consent",
        include_granted_scopes="true", state=state,
    )
    return url


def _email_from_creds(creds):
    idt = getattr(creds, "id_token", None)
    if not idt:
        return None
    try:
        payload = idt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return data.get("email")
    except Exception:
        return None


def exchange_code(code: str, redirect_uri: str):
    """Troca o code por tokens. Retorna (refresh_token, google_email, escopo)."""
    flow = Flow.from_client_config(_client_config(redirect_uri), scopes=SCOPES, redirect_uri=redirect_uri)
    flow.fetch_token(code=code)
    creds = flow.credentials
    email = _email_from_creds(creds)
    scope = " ".join(creds.scopes) if getattr(creds, "scopes", None) else " ".join(SCOPES)
    return creds.refresh_token, email, scope


def revoke(refresh_token: str):
    import urllib.parse
    import urllib.request
    data = urllib.parse.urlencode({"token": refresh_token}).encode()
    req = urllib.request.Request(
        REVOKE_URI, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:  # pragma: no cover
        logger.warning("Falha ao revogar token Google: %s", e)


# ── Calendar API ──────────────────────────────────────────────────────────────
def service_from_refresh(refresh_token: str):
    """Renova o access token e devolve o client do Calendar. Em falha de refresh
    (token revogado/expirado) levanta ReconnectRequired."""
    creds = Credentials(
        token=None,
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )
    try:
        creds.refresh(GoogleRequest())
    except Exception as e:
        raise ReconnectRequired(str(e))
    return build("calendar", "v3", credentials=creds, cache_discovery=False)


def _event_body(titulo, descricao, inicio, duracao_min, recurrence=None):
    # inicio: 'YYYY-MM-DD HH:MM' em horário BR (sem conversão para UTC)
    start = inicio.replace(" ", "T") + ":00"
    dt = datetime.strptime(inicio, "%Y-%m-%d %H:%M")
    end = (dt + timedelta(minutes=duracao_min or 30)).strftime("%Y-%m-%dT%H:%M:%S")
    body = {
        "summary": titulo or "Tarefa",
        "description": descricao or "",
        "start": {"dateTime": start, "timeZone": TZ},
        "end": {"dateTime": end, "timeZone": TZ},
        "reminders": {"useDefault": False, "overrides": [{"method": "popup", "minutes": 30}]},
    }
    # recurrence: lista de RRULEs (ex.: ["RRULE:FREQ=YEARLY"]) p/ eventos recorrentes
    if recurrence:
        body["recurrence"] = recurrence
    return body


def create_event(service, titulo, descricao, inicio, duracao_min, recurrence=None) -> str:
    ev = service.events().insert(
        calendarId="primary", body=_event_body(titulo, descricao, inicio, duracao_min, recurrence)
    ).execute()
    return ev.get("id")


def patch_event(service, event_id, titulo, descricao, inicio, duracao_min, recurrence=None):
    service.events().patch(
        calendarId="primary", eventId=event_id,
        body=_event_body(titulo, descricao, inicio, duracao_min, recurrence),
    ).execute()


def delete_event(service, event_id):
    try:
        service.events().delete(calendarId="primary", eventId=event_id).execute()
    except HttpError as e:
        # 404/410: evento já não existe no Google — trata como sucesso (idempotente)
        if getattr(e, "resp", None) is not None and e.resp.status in (404, 410):
            return
        raise
