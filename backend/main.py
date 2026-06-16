import json
import logging
import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from auth import verify_password, hash_password, create_access_token, decode_token
from database import get_connection, init_db, insert_returning

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
logger = logging.getLogger("audit")

app = FastAPI(title="Saúde Prime API", docs_url=None, redoc_url=None)

_origins_env = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [o.strip() for o in _origins_env.split(",") if o.strip()] or [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

security = HTTPBearer()

MAX_TENTATIVAS = 5
BLOQUEIO_MINUTOS = 15


# ── Rate limiting (slowapi) ─────────────────────────────────────────────────────
# slowapi é dependência fixa (requirements.txt), mas degradamos com aviso em log
# caso o import falhe, para que o app sempre suba. Quando indisponível, os
# decorators viram no-op (não limitam, mas não quebram as rotas).
try:
    from slowapi import Limiter
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded
    _SLOWAPI_OK = True
except Exception as _slowapi_err:  # pragma: no cover - caminho de degradação
    logger.warning("slowapi indisponível (%s); rate limiting DESATIVADO", _slowapi_err)
    _SLOWAPI_OK = False


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "anon"


def _user_key(request: Request) -> str:
    """key_func de rate limit por usuário autenticado.

    Lê sub/id do JWT no header Authorization; se ausente/ inválido, cai para o
    IP de origem. Pronto para reutilização futura em POST /api/ai/chat e writes
    sensíveis via o helper limit_por_usuario(). O endpoint decorado precisa ter
    `request: Request` na assinatura.
    """
    try:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            payload = decode_token(auth[7:].strip())
            if payload:
                return f"user:{payload.get('sub') or payload.get('id')}"
    except Exception:
        pass
    return _client_ip(request)


if _SLOWAPI_OK:
    limiter = Limiter(key_func=get_remote_address)
    app.state.limiter = limiter

    def _rate_limit_handler(request: Request, exc):
        return JSONResponse(
            status_code=429,
            content={"detail": "Muitas requisições. Tente novamente em instantes."},
        )

    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
else:
    class _NoopLimiter:
        """Substituto no-op quando slowapi não está disponível."""
        def limit(self, *args, **kwargs):
            def _deco(fn):
                return fn
            return _deco

    limiter = _NoopLimiter()
    app.state.limiter = limiter


def limit_por_usuario(limite: str):
    """Helper reutilizável: rate limit por usuário autenticado (sub/id do JWT).

    Uso futuro previsto: POST /api/ai/chat e writes sensíveis. Exemplo:

        @app.post("/api/ai/chat")
        @limit_por_usuario("20/minute")
        def ai_chat(req: ..., request: Request, user=Depends(require_corretor)):
            ...

    O endpoint PRECISA declarar `request: Request`. Hoje apenas o login usa
    rate limit (por IP, via @limiter.limit). Mantido aqui pronto para o futuro.
    """
    return limiter.limit(limite, key_func=_user_key)


# ── Helpers ───────────────────────────────────────────────────────────────────

_SENHAS_PROIBIDAS = {
    "saude@2026", "admin@2026", "saude2026", "admin2026",
    "Saude123", "Admin123", "Senha123", "123456789", "senha@123",
    "Abc12345!", "Password1!", "Mudar@123",
}

def validate_password(password: str):
    if len(password) < 10:
        raise HTTPException(400, "Senha deve ter ao menos 10 caracteres")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(400, "Senha deve ter ao menos uma letra maiúscula")
    if not re.search(r"[a-z]", password):
        raise HTTPException(400, "Senha deve ter ao menos uma letra minúscula")
    if not re.search(r"[0-9]", password):
        raise HTTPException(400, "Senha deve ter ao menos um número")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:',.<>?/\\|`~]", password):
        raise HTTPException(400, "Senha deve ter ao menos um caractere especial (!@#$%...)")
    if password in _SENHAS_PROIBIDAS:
        raise HTTPException(400, "Senha muito comum ou previsível. Escolha outra.")


def log_action(usuario: str, acao: str, detalhes: str, ip: str = "", usuario_id: Optional[int] = None):
    try:
        conn = get_connection()
        conn.execute(
            "INSERT INTO audit_log (usuario, usuario_id, acao, detalhes, ip) VALUES (?, ?, ?, ?, ?)",
            (usuario, usuario_id, acao, detalhes, ip),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"AUDIT LOG FALHOU — usuario={usuario} acao={acao} erro={e}")


def check_corretora_ativa(corretora_id):
    if not corretora_id:
        return
    conn = get_connection()
    row = conn.execute(
        "SELECT ativo, data_expiracao FROM corretoras WHERE id = ?", (corretora_id,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(403, "Corretora não encontrada")
    if not row["ativo"]:
        raise HTTPException(403, "Assinatura inativa. Entre em contato com o suporte.")
    if str(row["data_expiracao"]) < date.today().isoformat():
        raise HTTPException(403, "Assinatura expirada. Entre em contato com o suporte para renovar.")


# ── Dependências de autenticação ──────────────────────────────────────────────

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = decode_token(creds.credentials)
    if not payload:
        raise HTTPException(401, "Token inválido ou expirado")
    # Sessão única: verifica se o session_token ainda é o ativo no banco
    session_tok = payload.get("session_token")
    if session_tok:
        conn = get_connection()
        row = conn.execute(
            "SELECT session_token FROM users WHERE username = ?", (payload["sub"],)
        ).fetchone()
        conn.close()
        if not row or row["session_token"] != session_tok:
            raise HTTPException(401, "Sessão encerrada. Outro dispositivo fez login com esta conta.")
    return payload


def require_superadmin(user=Depends(get_current_user)):
    if user.get("role") != "superadmin":
        raise HTTPException(403, "Acesso restrito ao super administrador")
    return user


def require_admin(user=Depends(get_current_user)):
    if user.get("role") not in ("admin", "superadmin"):
        raise HTTPException(403, "Acesso restrito ao administrador")
    if user.get("role") == "admin":
        check_corretora_ativa(user.get("corretora_id"))
    return user


def require_corretor(user=Depends(get_current_user)):
    check_corretora_ativa(user.get("corretora_id"))
    conn = get_connection()
    row = conn.execute(
        "SELECT id, ativo FROM users WHERE username = ?", (user["sub"],)
    ).fetchone()
    conn.close()
    if not row or not row["ativo"]:
        raise HTTPException(403, "Usuário inativo")
    user["id"] = row["id"]
    return user


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    conn = get_connection()
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM users WHERE role = 'superadmin'"
    ).fetchone()
    if row["cnt"] == 0:
        old = conn.execute(
            "SELECT id FROM users WHERE username = 'admin'"
        ).fetchone()
        if old:
            conn.execute("UPDATE users SET role='superadmin' WHERE username='admin'")
        else:
            import string
            alphabet = string.ascii_letters + string.digits + "!@#$%"
            senha_temp = "".join(secrets.choice(alphabet) for _ in range(16))
            conn.execute(
                "INSERT INTO users (username, hashed_password, nome, role) VALUES (?, ?, ?, ?)",
                ("admin", hash_password(senha_temp), "Administrador", "superadmin"),
            )
            print("\n" + "=" * 60)
            print("  SUPERADMIN CRIADO — TROQUE A SENHA IMEDIATAMENTE")
            print(f"  Usuário: admin")
            print(f"  Senha temporária: {senha_temp}")
            print("=" * 60 + "\n")
        conn.commit()
    conn.close()
    seed_catalogo()


def seed_catalogo():
    conn = get_connection()
    cnt = conn.execute("SELECT COUNT(*) as cnt FROM operadoras").fetchone()
    if cnt["cnt"] > 0:
        conn.close()
        return

    _OPS = [
        ("unity",        "Unity Saúde",       "Adm. Esplendor · Mai/2026 · Taxa assoc. R$ 5,00 · Assoc: UEB, UVA, UNIPRO, ANC, UNSP · Telemedicina gratuita", 1),
        ("evo",          "Evo Saúde",          "Adm. Easyplan · Reajuste set/2026 · Odonto ODONTOGROUP incluso · Telemedicina 24h · Taxa assoc. R$ 5,00", 2),
        ("plenum",       "Plenum Saúde",       "Adm. Easyplan · Reajuste mar/2027 · Seguro Viagem AIG + UTI Móvel 24h · Sírio-Libanês (Sigma) · Taxa assoc. R$ 5,00", 3),
        ("amil",         "Amil",               "Vigência mai/2026 · Amil Dental incluso 12 meses grátis (R$ 14,99/mês após) · Rede nacional · Reembolso disponível nos planos Platinum", 4),
        ("medsenior",    "MedSênior",          "Vigência mai/2026 · Pessoa Física · Sem coparticipação · Rede Brasília · Coleta domiciliar Lab. MedSênior · Oficinas do Bem inclusas", 5),
        ("segurosunimed","Seguros Unimed",      "PME · Compulsório e Facultativo · 2–99 vidas · Rede DF + UE nacional · Essencial I/II/III/IV disponíveis", 6),
        ("portosaude",   "Porto Saúde",        "PME · Planos Bronze / Prata / Ouro · Com e sem coparticipação parcial · Rede credenciada DF · Porto Seguro Saúde", 7),
        ("bradesco",     "Bradesco Saúde",     "PME · Planos Nacionais · Tabela jan/2026 · Rede credenciada DF · Bradesco Seguros", 8),
        ("bestsenior",   "Best Sênior",        "PF e PME · Exclusivo 44+ · Tabela Mar-Abr/2026 · Rede credenciada DF · Best Sênior Saúde", 9),
        ("sulamerica",   "SulAmérica Saúde",   "PME Compulsório · Vigência 12m ou 24m · 3–99 vidas · Com e sem copart 30% · Rede credenciada DF · SulAmérica Seguro Saúde", 10),
        ("hapvida",      "Hapvida",            "PME 2–29 vidas · Tabela Brasília · Nosso Médico e Nosso Plano · Com coparticipação parcial ou completa · Rede credenciada DF", 11),
    ]
    # Cor base (HEX) — fonte única no banco. Em DBs já existentes o seed vem das
    # migrations (UPDATE ... WHERE cor IS NULL); aqui cobre o primeiro boot.
    _CORES = {
        "unity": "#0f2340", "evo": "#5c1a40", "plenum": "#0a4028", "amil": "#461BFF",
        "medsenior": "#95C13D", "segurosunimed": "#0074BE", "portosaude": "#005CB9",
        "bradesco": "#CC0000", "bestsenior": "#1B3A8A", "sulamerica": "#D5531C",
        "hapvida": "#007B40",
    }
    for chave, nome, info, ordem in _OPS:
        conn.execute(
            "INSERT INTO operadoras (chave, nome, info, ordem, cor) VALUES (?, ?, ?, ?, ?)",
            (chave, nome, info, ordem, _CORES.get(chave)),
        )
    conn.commit()

    ops_map = {r["chave"]: r["id"] for r in conn.execute("SELECT id, chave FROM operadoras").fetchall()}

    # (codigo, op_chave, nome, aco, tipo, fvidas, mod, vig, precos, ordem)
    _PLANOS = [
        # UNITY (u3-u6 batem com dados.js; u1/u2 removidos pois não existem mais)
        ("u3","unity","Sem copart — Unity Vida","enf",None,None,None,None,[348.34,369.25,424.63,475.59,570.69,656.31,826.94,1017.15,1322.28,1917.30],1),
        ("u4","unity","Com copart — Unity Vida","enf",None,None,None,None,[248.94,263.88,303.46,339.87,407.85,469.02,590.97,726.90,944.97,1370.20],2),
        ("u5","unity","Sem copart — Unity Star","apt",None,None,None,None,[433.42,459.42,528.34,591.74,710.08,816.60,1028.91,1265.56,1645.23,2385.58],3),
        ("u6","unity","Com copart — Unity Star","apt",None,None,None,None,[371.26,393.54,452.57,506.88,608.25,699.46,881.36,1084.07,1409.30,2043.48],4),
        # EVO
        ("e1","evo","Sem copart — NOW Enfermaria","enf",None,None,None,None,[329.69,352.17,383.37,450.31,541.95,612.67,747.64,917.58,1233.41,1637.60],1),
        ("e2","evo","Com copart — ONE Enfermaria","enf",None,None,None,None,[249.30,266.30,289.90,340.52,409.81,463.29,565.35,693.86,932.68,1238.32],2),
        ("e3","evo","Com copart — NOW Enfermaria","enf",None,None,None,None,[286.68,306.24,333.37,391.58,471.26,532.76,650.13,797.90,1072.54,1424.01],3),
        ("e4","evo","Sem copart — NOW Apartamento","apt",None,None,None,None,[394.15,421.03,458.33,538.36,647.91,732.47,893.83,1097.00,1474.58,1957.80],4),
        ("e5","evo","Com copart — ONE Apartamento","apt",None,None,None,None,[292.74,312.71,340.41,399.85,481.22,544.02,663.86,814.76,1095.20,1454.10],5),
        ("e6","evo","Com copart — NOW Apartamento","apt",None,None,None,None,[348.80,372.59,405.60,476.42,573.37,648.20,790.99,970.79,1304.93,1732.56],6),
        # PLENUM
        ("p1","plenum","Copart parcial — Delta (Enf)","enf",None,None,None,None,[349.90,437.38,507.36,577.34,629.82,664.81,804.77,874.75,1084.69,1679.52],1),
        ("p2","plenum","Copart parcial — Ômega (Enf)","enf",None,None,None,None,[389.90,487.38,565.36,643.34,701.82,740.81,896.77,974.75,1208.69,1871.52],2),
        ("p3","plenum","Copart total — Delta (Enf)","enf",None,None,None,None,[269.90,337.38,391.36,445.34,485.82,512.81,620.77,674.75,836.69,1295.52],3),
        ("p4","plenum","Copart total — Ômega (Enf)","enf",None,None,None,None,[299.90,374.88,434.86,494.84,539.82,569.81,689.77,749.75,929.69,1439.52],4),
        ("p5","plenum","Copart parcial — Beta (Apt)","apt",None,None,None,None,[399.90,499.88,579.86,659.84,719.82,759.81,919.77,999.75,1239.69,1919.52],5),
        ("p6","plenum","Copart parcial — Sigma (Apt)","apt",None,None,None,None,[499.90,624.88,724.86,824.84,899.82,949.81,1149.77,1249.75,1549.69,2399.52],6),
        ("p7","plenum","Copart total — Beta (Apt)","apt",None,None,None,None,[309.90,387.38,449.36,511.34,557.82,588.81,712.77,774.75,960.69,1487.52],7),
        ("p8","plenum","Copart total — Sigma (Apt)","apt",None,None,None,None,[389.90,487.38,565.36,643.34,701.82,740.81,896.77,974.75,1208.69,1871.52],8),
        # AMIL — Adesão Copart. Completa (IDs batem com dados.js am_ad_ct_*)
        ("am_ad_ct_1", "amil","Copart. Completa — Bronze DF (Enf)","enf","adesao",None,None,None,[ 320.90, 435.79, 511.57, 511.57, 511.57,  571.43,  789.14,  942.24, 1354.94, 1921.31], 1),
        ("am_ad_ct_2", "amil","Copart. Completa — Bronze DF (Apt)","apt","adesao",None,None,None,[ 356.22, 483.74, 567.86, 567.86, 567.86,  634.31,  875.98, 1045.92, 1504.03, 2132.71], 2),
        ("am_ad_ct_3", "amil","Copart. Completa — Prata DF (Enf)", "enf","adesao",None,None,None,[ 448.22, 524.41, 639.79, 767.74, 806.12,  886.74, 1108.44, 1219.28, 1524.11, 2667.19], 3),
        ("am_ad_ct_4", "amil","Copart. Completa — Prata DF (Apt)", "apt","adesao",None,None,None,[ 497.52, 582.10, 710.15, 852.18, 894.80,  984.28, 1230.36, 1353.40, 1691.75, 2960.58], 4),
        ("am_ad_ct_5", "amil","Copart. Completa — Ouro (Enf)",     "enf","adesao",None,None,None,[ 500.09, 585.11, 713.83, 856.60, 899.42,  989.38, 1236.72, 1360.39, 1700.48, 2975.86], 5),
        ("am_ad_ct_6", "amil","Copart. Completa — Ouro (Apt)",     "apt","adesao",None,None,None,[ 555.10, 649.48, 792.35, 950.82, 998.36, 1098.19, 1372.74, 1510.02, 1887.53, 3303.18], 6),
        ("am_ad_ct_7", "amil","Copart. Completa — Platinum Mais R1 (Apt)","apt","adesao",None,None,None,[ 732.24, 856.72,1045.19,1254.24,1316.95, 1448.65, 1810.81, 1991.90, 2489.88, 4357.28], 7),
        ("am_ad_ct_8", "amil","Copart. Completa — Platinum Mais R2 (Apt)","apt","adesao",None,None,None,[ 739.48, 865.19,1055.54,1266.65,1330.00, 1462.99, 1828.75, 2011.62, 2514.52, 4400.42], 8),
        ("am_ad_ct_9", "amil","Copart. Completa — Platinum R1 (Apt)",     "apt","adesao",None,None,None,[ 589.22, 689.38, 841.04,1009.26,1059.73, 1165.70, 1457.12, 1602.84, 2003.56, 3506.22], 9),
        ("am_ad_ct_10","amil","Copart. Completa — Platinum R2 (Apt)",     "apt","adesao",None,None,None,[ 595.08, 696.24, 849.42,1019.30,1070.26, 1177.28, 1471.61, 1618.78, 2023.46, 3541.07],10),
        # AMIL — Adesão Copart. Parcial (IDs batem com dados.js am_ad_cp_*)
        ("am_ad_cp_1", "amil","Copart. Parcial — Bronze DF (Enf)","enf","adesao",None,None,None,[ 427.87, 581.05, 682.09, 682.09, 682.09,  761.89, 1052.17, 1256.29, 1806.55, 2561.69],11),
        ("am_ad_cp_2", "amil","Copart. Parcial — Bronze DF (Apt)","apt","adesao",None,None,None,[ 474.95, 644.98, 757.14, 757.14, 757.14,  845.72, 1167.95, 1394.53, 2005.33, 2843.56],12),
        ("am_ad_cp_3", "amil","Copart. Parcial — Prata DF (Enf)", "enf","adesao",None,None,None,[ 597.62, 699.22, 853.04,1023.65,1074.84, 1182.31, 1477.91, 1625.71, 2032.14, 3556.26],13),
        ("am_ad_cp_4", "amil","Copart. Parcial — Prata DF (Apt)", "apt","adesao",None,None,None,[ 663.36, 776.14, 946.87,1136.26,1193.06, 1312.38, 1640.48, 1804.54, 2255.68, 3947.45],14),
        ("am_ad_cp_5", "amil","Copart. Parcial — Ouro (Enf)",     "enf","adesao",None,None,None,[ 666.78, 780.12, 951.76,1142.10,1199.21, 1319.12, 1648.91, 1813.80, 2267.26, 3967.69],15),
        ("am_ad_cp_6", "amil","Copart. Parcial — Ouro (Apt)",     "apt","adesao",None,None,None,[ 740.11, 865.93,1056.43,1267.72,1331.10, 1464.20, 1830.26, 2013.29, 2516.62, 4404.08],16),
        ("am_ad_cp_7", "amil","Copart. Parcial — Platinum Mais R1 (Apt)","apt","adesao",None,None,None,[ 976.32,1142.28,1393.60,1672.32,1755.95, 1931.53, 2414.44, 2655.86, 3319.84, 5809.72],17),
        ("am_ad_cp_8", "amil","Copart. Parcial — Platinum Mais R2 (Apt)","apt","adesao",None,None,None,[ 985.99,1153.60,1407.40,1688.87,1773.34, 1950.66, 2438.34, 2682.17, 3352.69, 5867.23],18),
        ("am_ad_cp_9", "amil","Copart. Parcial — Platinum R1 (Apt)",     "apt","adesao",None,None,None,[ 785.62, 919.16,1121.39,1345.67,1412.94, 1554.24, 1942.81, 2137.09, 2671.37, 4674.90],19),
        ("am_ad_cp_10","amil","Copart. Parcial — Platinum R2 (Apt)",     "apt","adesao",None,None,None,[ 793.43, 928.31,1132.54,1359.04,1426.99, 1569.70, 1962.12, 2158.33, 2697.91, 4721.35],20),
        # HAPVIDA
        ("hap_nm_cp_enf","hapvida","Copart Parcial — Nosso Médico (Enf)","enf","pme","02-29",None,None,[147.09,164.74,184.51,212.19,244.02,290.38,362.98,453.73,771.34,863.90],1),
        ("hap_nm_cp_apt","hapvida","Copart Parcial — Nosso Médico (Apt)","apt","pme","02-29",None,None,[220.58,247.05,276.70,318.21,365.94,435.47,544.34,680.43,1156.73,1295.54],2),
        ("hap_nm_cc_enf","hapvida","Copart Completa — Nosso Médico (Enf)","enf","pme","02-29",None,None,[129.46,145.00,162.40,186.76,214.77,255.58,319.48,399.35,678.90,760.37],3),
        ("hap_nm_cc_apt","hapvida","Copart Completa — Nosso Médico (Apt)","apt","pme","02-29",None,None,[194.12,217.41,243.50,280.03,322.03,383.22,479.03,598.79,1017.94,1140.09],4),
        ("hap_np_cp_amb","hapvida","Copart Parcial — Nosso Plano (Amb)","amb","pme","02-29",None,None,[148.42,166.23,186.18,214.11,246.23,293.01,366.26,457.83,778.31,871.71],5),
        ("hap_np_cp_enf","hapvida","Copart Parcial — Nosso Plano (Enf)","enf","pme","02-29",None,None,[163.26,182.85,204.79,235.51,270.84,322.30,402.88,503.60,856.12,958.85],6),
        ("hap_np_cp_apt","hapvida","Copart Parcial — Nosso Plano (Apt)","apt","pme","02-29",None,None,[244.93,274.32,307.24,353.33,406.33,483.53,604.41,755.51,1284.37,1438.40],7),
        ("hap_np_cc_amb","hapvida","Copart Completa — Nosso Plano (Amb)","amb","pme","02-29",None,None,[120.72,135.21,151.44,174.16,200.28,238.33,297.91,372.39,633.06,709.03],8),
        ("hap_np_cc_enf","hapvida","Copart Completa — Nosso Plano (Enf)","enf","pme","02-29",None,None,[143.68,160.92,180.23,207.26,232.35,282.64,354.55,443.19,753.48,843.83],9),
        ("hap_np_cc_apt","hapvida","Copart Completa — Nosso Plano (Apt)","apt","pme","02-29",None,None,[215.54,241.40,270.37,310.93,357.57,425.51,531.89,664.86,1130.26,1265.89],10),
        # MEDSENIOR (ms1–ms8) — preços só a partir de 59 anos (índices 0–6 = 0)
        ("ms1","medsenior","Sem copart — DF3 Enfermaria","enf","pf",None,None,None,[0,0,0,0,0,0,0,803.50,964.20,1263.10],1),
        ("ms2","medsenior","Sem copart — DF4 Apartamento","apt","pf",None,None,None,[0,0,0,0,0,0,0,964.19,1157.03,1515.71],2),
        ("ms3","medsenior","Sem copart — Black Apartamento","apt","pf",None,None,None,[0,0,0,0,0,0,0,1205.92,1447.10,1895.70],3),
        ("ms4","medsenior","Sem copart — Infinite Apartamento","apt","pf",None,None,None,[0,0,0,0,0,0,0,1818.30,2181.96,2858.37],4),
        ("ms5","medsenior","PME — DF Enfermaria","enf","pme",None,None,None,[0,0,0,0,0,0,0,723.14,867.77,1136.78],5),
        ("ms6","medsenior","PME — DF Apartamento","apt","pme",None,None,None,[0,0,0,0,0,0,0,867.78,1041.34,1364.16],6),
        ("ms7","medsenior","PME — Black Apartamento","apt","pme",None,None,None,[0,0,0,0,0,0,0,1085.34,1302.41,1706.16],7),
        ("ms8","medsenior","PME — Infinite Apartamento","apt","pme",None,None,None,[0,0,0,0,0,0,0,1487.70,1785.24,2338.66],8),
        # PORTO SAÚDE (ps_1–ps_8)
        ("ps_1","portosaude","Sem copart — Bronze Brasília Pro","enf","pme",None,None,None,[243.53,295.33,356.27,407.87,441.93,456.40,545.18,586.91,725.17,1218.96],1),
        ("ps_2","portosaude","Com copart — Bronze Brasília Pro","enf","pme",None,None,None,[187.52,227.41,274.33,314.06,340.29,351.43,419.79,451.92,558.38,938.60],2),
        ("ps_3","portosaude","Sem copart — Prata Brasília Pro","enf","pme",None,None,None,[287.92,349.16,421.20,482.21,522.48,539.58,644.54,693.88,857.34,1441.12],3),
        ("ps_4","portosaude","Com copart — Prata Brasília Pro","enf","pme",None,None,None,[221.70,268.85,324.33,371.30,402.31,415.48,496.30,534.29,660.15,1109.66],4),
        ("ps_5","portosaude","Sem copart — P420","apt","pme",None,None,None,[414.59,502.78,606.52,694.36,752.35,776.98,928.12,999.16,1234.54,2075.16],5),
        ("ps_6","portosaude","Com copart — P420","apt","pme",None,None,None,[339.96,412.28,497.35,569.38,616.92,637.12,761.06,819.31,1012.32,1701.53],6),
        ("ps_7","portosaude","Sem copart — Ouro Brasília Pro","apt","pme",None,None,None,[381.88,463.11,558.66,639.57,692.98,715.67,854.89,920.32,1137.13,1911.42],7),
        ("ps_8","portosaude","Com copart — Ouro Brasília Pro","apt","pme",None,None,None,[313.14,379.75,458.10,524.45,568.25,586.85,701.01,754.66,932.44,1567.36],8),
        # BEST SÊNIOR (bse_pf1–bse_pme4) — preços só a partir de 44 anos (índices 0–5 = 0)
        ("bse_pf1","bestsenior","Sem copart — Classic (Enf)","enf","pf",None,None,None,[0,0,0,0,0,0,676.09,851.88,1090.40,1504.75],1),
        ("bse_pf2","bestsenior","Sem copart — Classic (Apt)","apt","pf",None,None,None,[0,0,0,0,0,0,829.65,1045.37,1338.07,1846.54],2),
        ("bse_pf3","bestsenior","Sem copart — Prime (Apt)","apt","pf",None,None,None,[0,0,0,0,0,0,982.49,1237.94,1584.56,2186.69],3),
        ("bse_pf4","bestsenior","Sem copart — Platinum (Apt)","apt","pf",None,None,None,[0,0,0,0,0,0,1189.90,1499.28,1919.08,2648.33],4),
        ("bse_pme1","bestsenior","Sem copart — Classic PJ (Enf)","enf","pme",None,None,None,[0,0,0,0,0,0,608.48,766.69,981.36,1353.64],5),
        ("bse_pme2","bestsenior","Sem copart — Classic PJ (Apt)","apt","pme",None,None,None,[0,0,0,0,0,0,746.69,940.84,1204.26,1661.89],6),
        ("bse_pme3","bestsenior","Sem copart — Prime PJ (Apt)","apt","pme",None,None,None,[0,0,0,0,0,0,884.24,1114.15,1426.10,1968.02],7),
        ("bse_pme4","bestsenior","Sem copart — Platinum PJ (Apt)","apt","pme",None,None,None,[0,0,0,0,0,0,1070.91,1349.36,1727.17,2383.50],8),
        # BRADESCO (bd_1–bd_7)
        ("bd_1","bradesco","Sem copart — Nacional Plus 4 (Apt)","apt","pme",None,None,None,[1111.89,1312.03,1587.55,1905.08,2171.76,2236.91,2723.58,3203.48,3812.14,6670.86],1),
        ("bd_2","bradesco","Sem copart — Premium 6 (Apt)","apt","pme",None,None,None,[1535.55,1811.95,2192.44,2630.95,2999.26,3089.24,3761.34,4424.09,5264.67,9212.65],2),
        ("bd_3","bradesco","Copart total — Nacional Plus 4 (Apt)","apt","pme",None,None,None,[889.51,1049.62,1270.03,1524.05,1737.40,1789.52,2178.85,2562.76,3049.68,5336.64],3),
        ("bd_4","bradesco","Sem copart — Efetivo (Enf)","enf","pme",None,None,None,[400.01,472.01,571.13,685.36,781.30,804.74,979.81,1152.46,1371.43,2399.87],4),
        ("bd_5","bradesco","Sem copart — Nacional Flex (Enf)","enf","pme",None,None,None,[466.28,550.22,665.76,798.91,910.76,938.08,1142.16,1343.41,1598.66,2797.50],5),
        ("bd_6","bradesco","Copart total — Efetivo (Enf)","enf","pme",None,None,None,[308.01,363.45,439.77,527.73,601.60,619.65,754.46,887.39,1056.00,1847.90],6),
        ("bd_7","bradesco","Copart total — Nacional Flex (Enf)","enf","pme",None,None,None,[359.04,423.67,512.63,615.16,701.28,722.32,879.47,1034.43,1230.97,2154.07],7),
        # SEGUROS UNIMED — Compulsório 02-04
        ("su_c04_1","segurosunimed","Sem copart — Compacto","enf","pme","02-04","comp",None,[516.84,632.61,792.11,875.32,932.33,1081.49,1292.82,1550.52,1840.83,3101.03],1),
        ("su_c04_2","segurosunimed","Com copart — Compacto","enf","pme","02-04","comp",None,[382.84,468.60,586.75,648.38,690.61,801.10,957.65,1148.53,1363.57,2297.06],2),
        ("su_c04_3","segurosunimed","Sem copart — Efetivo","apt","pme","02-04","comp",None,[580.25,710.22,889.29,982.71,1046.71,1214.17,1451.43,1740.74,2066.67,3481.49],3),
        ("su_c04_4","segurosunimed","Com copart — Efetivo","apt","pme","02-04","comp",None,[429.81,526.09,658.73,727.93,775.34,899.38,1075.13,1289.44,1530.86,2578.88],4),
        ("su_c04_5","segurosunimed","Sem copart — Completo","apt","pme","02-04","comp",None,[686.94,840.82,1052.81,1163.41,1239.18,1437.43,1718.32,2060.83,2446.69,4121.67],5),
        ("su_c04_6","segurosunimed","Com copart — Completo","apt","pme","02-04","comp",None,[508.85,622.83,779.86,861.78,917.91,1064.76,1272.83,1526.54,1812.36,3053.09],6),
        ("su_c04_7","segurosunimed","Sem copart — Superior","apt","pme","02-04","comp",None,[760.09,930.35,1164.91,1287.29,1371.12,1590.49,1901.29,2280.27,2707.21,4560.53],7),
        ("su_c04_8","segurosunimed","Com copart — Superior","apt","pme","02-04","comp",None,[608.07,744.28,931.93,1029.83,1096.90,1272.39,1521.03,1824.21,2165.77,3648.42],8),
        ("su_c04_9","segurosunimed","Sem copart — Superior Plus","apt","pme","02-04","comp",None,[843.75,1032.74,1293.12,1428.97,1522.03,1765.54,2110.55,2531.24,3005.17,5062.47],9),
        ("su_c04_10","segurosunimed","Com copart — Superior Plus","apt","pme","02-04","comp",None,[675.00,826.20,1034.50,1143.17,1217.63,1412.43,1688.44,2024.99,2404.14,4049.98],10),
        ("su_c04_11","segurosunimed","Sem copart — Sênior","apt","pme","02-04","comp",None,[1615.57,1977.45,2476.02,2736.13,2914.32,3380.58,4041.18,4846.70,5754.17,9693.41],11),
        ("su_c04_12","segurosunimed","Com copart — Sênior","apt","pme","02-04","comp",None,[1404.84,1719.53,2153.06,2379.24,2534.19,2939.63,3514.07,4214.52,5003.62,8429.05],12),
        # SEGUROS UNIMED — Compulsório 05-29
        ("su_c29_1","segurosunimed","Sem copart — Compacto","enf","pme","05-29","comp",None,[458.88,561.66,703.27,777.15,827.77,960.20,1147.83,1376.63,1634.38,2753.25],13),
        ("su_c29_2","segurosunimed","Com copart — Compacto","enf","pme","05-29","comp",None,[339.91,416.05,520.94,575.67,613.16,711.26,850.25,1019.72,1210.65,2039.45],14),
        ("su_c29_3","segurosunimed","Sem copart — Efetivo","apt","pme","05-29","comp",None,[515.17,630.57,789.55,872.50,929.32,1078.00,1288.65,1545.52,1834.89,3091.04],15),
        ("su_c29_4","segurosunimed","Com copart — Efetivo","apt","pme","05-29","comp",None,[381.61,467.09,584.85,646.29,688.39,798.52,954.56,1144.83,1359.18,2289.66],16),
        ("su_c29_5","segurosunimed","Sem copart — Completo","apt","pme","05-29","comp",None,[609.90,746.52,934.74,1032.93,1100.21,1276.22,1525.61,1829.71,2172.29,3659.42],17),
        ("su_c29_6","segurosunimed","Com copart — Completo","apt","pme","05-29","comp",None,[451.78,552.98,692.40,765.14,814.97,945.35,1130.08,1355.34,1609.11,2710.68],18),
        ("su_c29_7","segurosunimed","Sem copart — Superior","apt","pme","05-29","comp",None,[674.84,826.01,1034.27,1142.92,1217.35,1412.11,1688.06,2024.53,2403.60,4049.07],19),
        ("su_c29_8","segurosunimed","Com copart — Superior","apt","pme","05-29","comp",None,[539.88,660.81,827.41,914.33,973.88,1129.69,1350.45,1619.63,1922.88,3239.26],20),
        ("su_c29_9","segurosunimed","Sem copart — Superior Plus","apt","pme","05-29","comp",None,[749.12,916.92,1148.10,1268.71,1351.34,1567.53,1873.85,2247.36,2668.14,4494.72],21),
        ("su_c29_10","segurosunimed","Com copart — Superior Plus","apt","pme","05-29","comp",None,[599.30,733.54,918.48,1014.97,1081.07,1254.03,1499.08,1797.89,2134.51,3595.78],22),
        ("su_c29_11","segurosunimed","Sem copart — Sênior","apt","pme","05-29","comp",None,[1434.38,1755.68,2198.33,2429.27,2587.48,3001.45,3587.96,4303.15,5108.84,8606.29],23),
        ("su_c29_12","segurosunimed","Com copart — Sênior","apt","pme","05-29","comp",None,[1247.29,1526.68,1911.60,2112.41,2249.98,2609.95,3119.97,3741.87,4442.47,7483.73],24),
        # SEGUROS UNIMED — Compulsório 30-99
        ("su_c99_1","segurosunimed","Sem copart — Compacto","enf","pme","30-99","comp",None,[420.23,514.37,644.05,711.71,758.06,879.34,1051.17,1260.70,1496.75,2521.40],25),
        ("su_c99_2","segurosunimed","Com copart — Compacto","enf","pme","30-99","comp",None,[311.28,381.01,477.07,527.19,561.53,651.36,778.65,933.85,1108.70,1867.71],26),
        ("su_c99_3","segurosunimed","Sem copart — Efetivo","apt","pme","30-99","comp",None,[471.79,577.47,723.07,799.02,851.06,987.22,1180.14,1415.37,1680.37,2830.74],27),
        ("su_c99_4","segurosunimed","Com copart — Efetivo","apt","pme","30-99","comp",None,[349.47,427.76,535.60,591.87,630.42,731.27,874.17,1048.42,1244.72,2096.84],28),
        ("su_c99_5","segurosunimed","Sem copart — Completo","apt","pme","30-99","comp",None,[558.54,683.66,856.02,945.95,1007.56,1168.75,1397.14,1675.63,1989.36,3351.26],29),
        ("su_c99_6","segurosunimed","Com copart — Completo","apt","pme","30-99","comp",None,[413.74,506.41,634.09,700.70,746.34,865.74,1034.92,1241.21,1473.60,2482.42],30),
        ("su_c99_7","segurosunimed","Sem copart — Superior","apt","pme","30-99","comp",None,[618.02,756.45,947.17,1046.67,1114.84,1293.20,1545.90,1854.05,2201.19,3708.10],31),
        ("su_c99_8","segurosunimed","Com copart — Superior","apt","pme","30-99","comp",None,[494.41,605.16,757.74,837.34,891.87,1034.56,1236.72,1483.24,1760.95,2966.48],32),
        ("su_c99_9","segurosunimed","Sem copart — Superior Plus","apt","pme","30-99","comp",None,[686.04,839.71,1051.42,1161.87,1237.54,1435.53,1716.05,2058.11,2443.46,4116.22],33),
        ("su_c99_10","segurosunimed","Com copart — Superior Plus","apt","pme","30-99","comp",None,[548.83,671.77,841.14,929.50,990.03,1148.42,1372.84,1646.49,1954.76,3292.97],34),
        ("su_c99_11","segurosunimed","Sem copart — Sênior","apt","pme","30-99","comp",None,[1313.59,1607.84,2013.21,2224.70,2369.59,2748.69,3285.82,3940.78,4678.62,7881.55],35),
        ("su_c99_12","segurosunimed","Com copart — Sênior","apt","pme","30-99","comp",None,[1142.25,1398.12,1750.62,1934.52,2060.51,2390.17,2857.23,3426.76,4068.37,6853.53],36),
        # SEGUROS UNIMED — Facultativo 02-04
        ("su_f04_1","segurosunimed","Sem copart — Compacto","enf","pme","02-04","fac",None,[568.52,695.87,871.32,962.85,1025.56,1189.63,1422.10,1705.57,2024.91,3411.14],37),
        ("su_f04_2","segurosunimed","Com copart — Compacto","enf","pme","02-04","fac",None,[421.13,515.46,645.42,713.22,759.67,881.21,1053.41,1263.38,1499.93,2526.77],38),
        ("su_f04_3","segurosunimed","Sem copart — Efetivo","apt","pme","02-04","fac",None,[638.27,781.25,978.22,1080.98,1151.38,1335.58,1596.57,1914.82,2273.33,3829.63],39),
        ("su_f04_4","segurosunimed","Com copart — Efetivo","apt","pme","02-04","fac",None,[472.79,578.70,724.60,800.72,852.87,989.32,1182.65,1418.38,1683.95,2836.77],40),
        ("su_f04_5","segurosunimed","Sem copart — Completo","apt","pme","02-04","fac",None,[755.64,924.90,1158.09,1279.75,1363.10,1581.17,1890.15,2266.92,2691.36,4533.83],41),
        ("su_f04_6","segurosunimed","Com copart — Completo","apt","pme","02-04","fac",None,[559.73,685.11,857.85,947.96,1009.70,1171.24,1400.11,1679.20,1993.60,3358.39],42),
        ("su_f04_7","segurosunimed","Sem copart — Superior","apt","pme","02-04","fac",None,[836.10,1023.38,1281.40,1416.01,1508.24,1749.53,2091.41,2508.29,2977.93,5016.58],43),
        ("su_f04_8","segurosunimed","Com copart — Superior","apt","pme","02-04","fac",None,[668.88,818.71,1025.12,1132.81,1206.59,1399.63,1673.13,2006.63,2382.34,4013.27],44),
        ("su_f04_9","segurosunimed","Sem copart — Superior Plus","apt","pme","02-04","fac",None,[928.12,1136.02,1422.44,1571.86,1674.24,1942.09,2321.60,2784.36,3305.69,5568.72],45),
        ("su_f04_10","segurosunimed","Com copart — Superior Plus","apt","pme","02-04","fac",None,[742.50,908.82,1137.95,1257.49,1339.39,1553.67,1857.28,2227.49,2644.55,4454.98],46),
        ("su_f04_11","segurosunimed","Sem copart — Sênior","apt","pme","02-04","fac",None,[1777.12,2175.20,2723.62,3009.74,3205.75,3718.63,4445.30,5331.37,6329.58,10662.75],47),
        ("su_f04_12","segurosunimed","Com copart — Sênior","apt","pme","02-04","fac",None,[1545.33,1891.48,2368.37,2617.16,2787.61,3233.59,3865.48,4635.98,5503.99,9271.95],48),
        # SEGUROS UNIMED — Facultativo 05-29
        ("su_f29_1","segurosunimed","Sem copart — Compacto","enf","pme","05-29","fac",None,[504.76,617.83,773.60,854.87,910.54,1056.22,1262.62,1514.29,1797.82,3028.58],49),
        ("su_f29_2","segurosunimed","Com copart — Compacto","enf","pme","05-29","fac",None,[373.90,457.65,573.04,633.24,674.48,782.38,935.27,1121.70,1331.72,2243.39],50),
        ("su_f29_3","segurosunimed","Sem copart — Efetivo","apt","pme","05-29","fac",None,[566.69,693.63,868.51,959.75,1022.25,1185.80,1417.52,1700.07,2018.38,3400.14],51),
        ("su_f29_4","segurosunimed","Com copart — Efetivo","apt","pme","05-29","fac",None,[419.77,513.80,643.34,710.92,757.22,878.37,1050.01,1259.31,1495.10,2518.62],52),
        ("su_f29_5","segurosunimed","Sem copart — Completo","apt","pme","05-29","fac",None,[670.89,821.17,1028.21,1136.23,1210.23,1403.85,1678.17,2012.68,2389.52,4025.37],53),
        ("su_f29_6","segurosunimed","Com copart — Completo","apt","pme","05-29","fac",None,[496.96,608.28,761.64,841.65,896.46,1039.89,1243.09,1490.88,1770.02,2981.75],54),
        ("su_f29_7","segurosunimed","Sem copart — Superior","apt","pme","05-29","fac",None,[742.33,908.61,1137.69,1257.21,1339.09,1553.32,1856.86,2226.99,2643.95,4453.98],55),
        ("su_f29_8","segurosunimed","Com copart — Superior","apt","pme","05-29","fac",None,[593.86,726.89,910.16,1005.77,1071.27,1242.66,1485.49,1781.59,2115.16,3563.18],56),
        ("su_f29_9","segurosunimed","Sem copart — Superior Plus","apt","pme","05-29","fac",None,[824.03,1008.62,1262.91,1395.58,1486.47,1724.29,2061.23,2472.10,2934.96,4944.19],57),
        ("su_f29_10","segurosunimed","Com copart — Superior Plus","apt","pme","05-29","fac",None,[659.23,806.89,1010.33,1116.46,1189.18,1379.43,1648.99,1977.68,2347.96,3955.35],58),
        ("su_f29_11","segurosunimed","Sem copart — Sênior","apt","pme","05-29","fac",None,[1577.82,1931.25,2418.17,2672.20,2846.23,3301.59,3946.76,4733.46,5619.72,9466.92],59),
        ("su_f29_12","segurosunimed","Com copart — Sênior","apt","pme","05-29","fac",None,[1372.02,1679.35,2102.75,2323.65,2474.98,2870.95,3431.97,4116.05,4886.72,8232.11],60),
        # SEGUROS UNIMED — Facultativo 30-99
        ("su_f99_1","segurosunimed","Sem copart — Compacto","enf","pme","30-99","fac",None,[462.26,565.80,708.46,782.88,833.87,967.27,1156.29,1386.77,1646.42,2773.54],61),
        ("su_f99_2","segurosunimed","Com copart — Compacto","enf","pme","30-99","fac",None,[342.41,419.11,524.78,579.91,617.68,716.50,856.51,1027.24,1219.57,2054.48],62),
        ("su_f99_3","segurosunimed","Sem copart — Efetivo","apt","pme","30-99","fac",None,[518.97,635.22,795.37,878.93,936.17,1085.94,1298.15,1556.91,1848.41,3113.81],63),
        ("su_f99_4","segurosunimed","Com copart — Efetivo","apt","pme","30-99","fac",None,[384.42,470.53,589.16,651.06,693.46,804.40,961.59,1153.26,1369.19,2306.53],64),
        ("su_f99_5","segurosunimed","Sem copart — Completo","apt","pme","30-99","fac",None,[614.40,752.02,941.63,1040.54,1108.31,1285.63,1536.85,1843.19,2188.30,3686.39],65),
        ("su_f99_6","segurosunimed","Com copart — Completo","apt","pme","30-99","fac",None,[455.11,557.05,697.50,770.77,820.97,952.32,1138.41,1365.33,1620.96,2730.66],66),
        ("su_f99_7","segurosunimed","Sem copart — Superior","apt","pme","30-99","fac",None,[679.82,832.10,1041.89,1151.34,1226.32,1422.52,1700.50,2039.45,2421.31,4078.90],67),
        ("su_f99_8","segurosunimed","Com copart — Superior","apt","pme","30-99","fac",None,[543.85,665.68,833.51,921.07,981.06,1138.01,1360.40,1631.56,1937.04,3263.12],68),
        ("su_f99_9","segurosunimed","Sem copart — Superior Plus","apt","pme","30-99","fac",None,[754.64,923.68,1156.56,1278.06,1361.29,1579.08,1887.66,2263.92,2687.80,4527.84],69),
        ("su_f99_10","segurosunimed","Com copart — Superior Plus","apt","pme","30-99","fac",None,[603.71,738.94,925.25,1022.45,1089.04,1263.27,1510.13,1811.14,2150.24,3622.27],70),
        ("su_f99_11","segurosunimed","Sem copart — Sênior","apt","pme","30-99","fac",None,[1444.95,1768.62,2214.53,2447.17,2606.55,3023.56,3614.40,4334.85,5146.48,8669.71],71),
        ("su_f99_12","segurosunimed","Com copart — Sênior","apt","pme","30-99","fac",None,[1256.48,1537.93,1925.68,2127.97,2266.56,2629.18,3142.96,3769.44,4475.20,7538.88],72),
        # SEGUROS UNIMED — Essencial Compulsório 02-04
        ("su_ec04_1","segurosunimed","Sem copart — Essencial I","enf","pme","02-04","comp",None,[341.65,418.18,523.61,578.61,616.30,714.90,854.60,1024.94,1216.85,2049.89],73),
        ("su_ec04_2","segurosunimed","Sem copart — Essencial II","apt","pme","02-04","comp",None,[382.30,467.94,585.92,647.47,689.64,799.97,956.29,1146.91,1361.65,2293.82],74),
        ("su_ec04_3","segurosunimed","Com copart — Essencial III","enf","pme","02-04","comp",None,[253.07,309.76,387.86,428.60,456.52,529.55,633.03,759.22,901.37,1518.43],75),
        ("su_ec04_4","segurosunimed","Com copart — Essencial IV","apt","pme","02-04","comp",None,[283.19,346.62,434.01,479.61,510.84,592.57,708.37,849.56,1008.63,1699.13],76),
        # SEGUROS UNIMED — Essencial Compulsório 05-29
        ("su_ec29_1","segurosunimed","Sem copart — Essencial I","enf","pme","05-29","comp",None,[303.33,371.28,464.89,513.72,547.18,634.72,758.75,910.00,1080.38,1819.99],77),
        ("su_ec29_2","segurosunimed","Sem copart — Essencial II","apt","pme","05-29","comp",None,[339.43,415.46,520.21,574.86,612.29,710.25,849.05,1018.29,1208.94,2036.57],78),
        ("su_ec29_3","segurosunimed","Com copart — Essencial III","enf","pme","05-29","comp",None,[224.69,275.02,344.36,380.54,405.32,470.16,562.04,674.07,800.28,1348.14],79),
        ("su_ec29_4","segurosunimed","Com copart — Essencial IV","apt","pme","05-29","comp",None,[251.43,307.75,385.34,425.82,453.55,526.11,628.92,754.29,895.51,1508.57],80),
        # SEGUROS UNIMED — Essencial Compulsório 30-99
        ("su_ec99_1","segurosunimed","Sem copart — Essencial I","enf","pme","30-99","comp",None,[277.79,340.01,425.74,470.46,501.10,581.27,694.86,833.36,989.40,1666.73],81),
        ("su_ec99_2","segurosunimed","Sem copart — Essencial II","apt","pme","30-99","comp",None,[310.84,380.47,476.40,526.45,560.73,650.44,777.55,932.53,1107.14,1865.07],82),
        ("su_ec99_3","segurosunimed","Com copart — Essencial III","enf","pme","30-99","comp",None,[205.77,251.86,315.36,348.49,371.19,430.57,514.71,617.31,732.89,1234.61],83),
        ("su_ec99_4","segurosunimed","Com copart — Essencial IV","apt","pme","30-99","comp",None,[230.26,281.83,352.89,389.96,415.36,481.81,575.96,690.77,820.10,1381.53],84),
        # SEGUROS UNIMED — Essencial Facultativo 02-04
        ("su_ef04_1","segurosunimed","Sem copart — Essencial I","enf","pme","02-04","fac",None,[375.81,459.99,575.97,636.48,677.93,786.39,940.06,1127.44,1338.53,2254.87],85),
        ("su_ef04_2","segurosunimed","Sem copart — Essencial II","apt","pme","02-04","fac",None,[420.53,514.73,644.51,712.22,758.60,879.97,1051.92,1261.60,1497.82,2523.20],86),
        ("su_ef04_3","segurosunimed","Com copart — Essencial III","enf","pme","02-04","fac",None,[278.38,340.74,426.64,471.46,502.17,582.51,696.34,835.14,991.50,1670.28],87),
        ("su_ef04_4","segurosunimed","Com copart — Essencial IV","apt","pme","02-04","fac",None,[311.51,381.28,477.42,527.57,561.93,651.83,779.20,934.52,1109.49,1869.04],88),
        # SEGUROS UNIMED — Essencial Facultativo 05-29
        ("su_ef29_1","segurosunimed","Sem copart — Essencial I","enf","pme","05-29","fac",None,[333.67,408.41,511.38,565.10,601.90,698.19,834.63,1001.00,1188.42,2001.99],89),
        ("su_ef29_2","segurosunimed","Sem copart — Essencial II","apt","pme","05-29","fac",None,[373.37,457.01,572.23,632.34,673.52,781.28,933.95,1120.11,1329.84,2240.23],90),
        ("su_ef29_3","segurosunimed","Com copart — Essencial III","enf","pme","05-29","fac",None,[247.16,302.52,378.80,418.59,445.85,517.18,618.24,741.48,880.31,1482.96],91),
        ("su_ef29_4","segurosunimed","Com copart — Essencial IV","apt","pme","05-29","fac",None,[276.57,338.52,423.87,468.40,498.91,578.73,691.82,829.71,985.06,1659.43],92),
        # SEGUROS UNIMED — Essencial Facultativo 30-99
        ("su_ef99_1","segurosunimed","Sem copart — Essencial I","enf","pme","30-99","fac",None,[305.57,374.01,468.31,517.51,551.21,639.40,764.35,916.70,1088.34,1833.40],93),
        ("su_ef99_2","segurosunimed","Sem copart — Essencial II","apt","pme","30-99","fac",None,[341.93,418.52,524.04,579.09,616.81,715.49,855.30,1025.79,1217.85,2051.58],94),
        ("su_ef99_3","segurosunimed","Com copart — Essencial III","enf","pme","30-99","fac",None,[226.35,277.05,346.90,383.34,408.31,473.63,566.18,679.04,806.18,1358.08],95),
        ("su_ef99_4","segurosunimed","Com copart — Essencial IV","apt","pme","30-99","fac",None,[253.28,310.02,388.18,428.96,456.89,529.99,633.56,759.84,902.11,1519.69],96),
        # SULAMERICA — PME 03-04v 12m
        ("sa_04_12_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","03-04",None,12,[388.10,485.12,601.55,667.72,714.46,828.78,990.72,1161.13,1382.33,2328.55],1),
        ("sa_04_12_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","03-04",None,12,[429.21,536.51,665.27,738.45,790.15,916.58,1095.68,1284.14,1528.78,2575.22],2),
        ("sa_04_12_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","03-04",None,12,[703.93,879.90,1091.07,1211.10,1295.87,1503.21,1796.94,2106.00,2507.19,4223.36],3),
        ("sa_04_12_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","03-04",None,12,[740.97,926.20,1148.50,1274.83,1364.07,1582.32,1891.52,2216.85,2639.15,4445.64],4),
        ("sa_04_12_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","03-04",None,12,[1409.78,1762.21,2185.14,2425.50,2595.27,3010.52,3598.77,4217.76,5021.24,8458.27],5),
        ("sa_04_12_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","03-04",None,12,[1685.85,2107.33,2613.09,2900.52,3103.54,3600.11,4303.58,5043.78,6004.62,10114.80],6),
        ("sa_04_12_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","03-04",None,12,[1883.16,2353.96,2918.91,3239.99,3466.79,4021.47,4807.28,5634.13,6707.43,11298.65],7),
        ("sa_04_12_sc_8","sulamerica","Sem copart — Prestige","apt","pme","03-04",None,12,[2469.80,3087.27,3828.22,4249.33,4546.77,5274.25,6304.84,7389.25,8796.92,14818.41],8),
        ("sa_04_12_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","03-04",None,12,[271.67,339.58,421.08,467.41,500.13,580.14,693.51,812.79,967.64,1629.99],9),
        ("sa_04_12_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","03-04",None,12,[300.45,375.56,465.69,516.92,553.11,641.61,766.98,898.91,1070.14,1802.65],10),
        ("sa_04_12_cc_3","sulamerica","Com copart — Especial RC","apt","pme","03-04",None,12,[527.94,659.92,818.31,908.32,971.90,1127.41,1347.71,1579.50,1880.40,3167.51],11),
        ("sa_04_12_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","03-04",None,12,[555.73,694.65,861.37,956.14,1023.06,1186.74,1418.64,1662.63,1979.37,3334.24],12),
        ("sa_04_12_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","03-04",None,12,[1198.30,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.10,4268.06,7189.54],13),
        ("sa_04_12_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","03-04",None,12,[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57],14),
        ("sa_04_12_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","03-04",None,12,[1600.69,2000.88,2481.07,2754.00,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86],15),
        ("sa_04_12_cc_8","sulamerica","Com copart — Prestige","apt","pme","03-04",None,12,[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.10,6280.87,7477.38,12595.65],16),
        # SULAMERICA — PME 03-04v 24m
        ("sa_04_24_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","03-04",None,24,[352.81,441.01,546.85,607.02,649.51,753.43,900.66,1055.57,1256.67,2116.86],17),
        ("sa_04_24_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","03-04",None,24,[390.19,487.74,604.80,671.32,718.32,833.26,996.07,1167.41,1389.79,2341.11],18),
        ("sa_04_24_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","03-04",None,24,[639.92,799.91,991.88,1100.99,1178.06,1366.55,1633.58,1914.55,2279.27,3839.41],19),
        ("sa_04_24_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","03-04",None,24,[673.61,842.01,1044.09,1158.94,1240.07,1438.48,1719.55,2015.31,2399.23,4041.49],20),
        ("sa_04_24_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","03-04",None,24,[1281.60,1602.01,1986.49,2205.00,2359.34,2736.83,3271.61,3834.33,4564.76,7689.35],21),
        ("sa_04_24_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","03-04",None,24,[1532.60,1915.74,2375.53,2636.83,2821.40,3272.83,3912.34,4585.27,5458.74,9195.27],22),
        ("sa_04_24_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","03-04",None,24,[1711.96,2139.97,2653.56,2945.45,3151.63,3655.89,4370.25,5121.94,6097.67,10271.51],23),
        ("sa_04_24_sc_8","sulamerica","Sem copart — Prestige","apt","pme","03-04",None,24,[2245.28,2806.61,3480.20,3863.02,4133.42,4794.77,5731.66,6717.51,7997.19,13471.29],24),
        ("sa_04_24_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","03-04",None,24,[246.97,308.71,382.80,424.91,454.66,527.40,630.46,738.91,879.67,1481.81],25),
        ("sa_04_24_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","03-04",None,24,[273.14,341.42,423.36,469.92,502.82,583.28,697.25,817.18,972.86,1638.78],26),
        ("sa_04_24_cc_3","sulamerica","Com copart — Especial RC","apt","pme","03-04",None,24,[479.94,599.92,743.91,825.75,883.55,1024.92,1225.18,1435.91,1709.45,2879.56],27),
        ("sa_04_24_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","03-04",None,24,[505.21,631.51,783.07,869.22,930.06,1078.87,1289.67,1511.49,1799.42,3031.12],28),
        ("sa_04_24_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","03-04",None,24,[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95],29),
        ("sa_04_24_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","03-04",None,24,[1302.71,1628.38,2019.19,2241.31,2398.20,2781.90,3325.49,3897.48,4639.93,7815.97],30),
        ("sa_04_24_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","03-04",None,24,[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78],31),
        ("sa_04_24_cc_8","sulamerica","Com copart — Prestige","apt","pme","03-04",None,24,[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59],32),
        # SULAMERICA — PME 05-29v 12m
        ("sa_29_12_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","05-29",None,12,[329.88,412.34,511.32,567.56,607.29,704.46,842.12,986.97,1174.99,1979.27],33),
        ("sa_29_12_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","05-29",None,12,[364.83,456.04,565.48,627.69,671.63,779.09,931.33,1091.53,1299.45,2188.94],34),
        ("sa_29_12_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","05-29",None,12,[598.33,747.92,927.40,1029.43,1101.48,1277.74,1527.39,1790.10,2131.12,3589.86],35),
        ("sa_29_12_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","05-29",None,12,[629.82,787.28,976.21,1083.62,1159.47,1344.98,1607.79,1884.32,2243.29,3778.79],36),
        ("sa_29_12_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","05-29",None,12,[1198.30,1497.88,1857.37,2061.66,2205.99,2558.94,3058.96,3585.10,4268.06,7189.54],37),
        ("sa_29_12_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","05-29",None,12,[1432.98,1791.23,2221.11,2465.44,2638.01,3060.09,3658.03,4287.23,5103.93,8597.57],38),
        ("sa_29_12_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","05-29",None,12,[1600.69,2000.88,2481.07,2754.00,2946.78,3418.26,4086.18,4789.01,5701.31,9603.86],39),
        ("sa_29_12_sc_8","sulamerica","Sem copart — Prestige","apt","pme","05-29",None,12,[2099.34,2624.17,3253.99,3611.93,3864.76,4483.11,5359.10,6280.87,7477.38,12595.65],40),
        ("sa_29_12_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","05-29",None,12,[230.91,288.64,357.92,397.29,425.10,493.13,589.48,690.88,822.49,1385.46],41),
        ("sa_29_12_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","05-29",None,12,[255.38,319.23,395.84,439.38,470.14,545.36,651.93,764.07,909.62,1532.25],42),
        ("sa_29_12_cc_3","sulamerica","Com copart — Especial RC","apt","pme","05-29",None,12,[448.74,560.93,695.56,772.07,826.12,958.30,1145.54,1342.58,1598.34,2692.39],43),
        ("sa_29_12_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","05-29",None,12,[472.37,590.46,732.17,812.72,869.60,1008.73,1205.84,1413.25,1682.46,2834.10],44),
        ("sa_29_12_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","05-29",None,12,[1018.56,1273.20,1578.77,1752.42,1875.09,2175.09,2600.11,3047.34,3627.85,6111.11],45),
        ("sa_29_12_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","05-29",None,12,[1218.03,1522.54,1887.95,2095.61,2242.31,2601.09,3109.33,3644.14,4338.35,7307.94],46),
        ("sa_29_12_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","05-29",None,12,[1360.58,1700.74,2108.92,2340.90,2504.76,2905.52,3473.25,4070.65,4846.11,8163.29],47),
        ("sa_29_12_cc_8","sulamerica","Com copart — Prestige","apt","pme","05-29",None,12,[1784.43,2230.54,2765.90,3070.15,3285.04,3810.64,4555.25,5338.74,6355.78,10706.30],48),
        # SULAMERICA — PME 05-29v 24m
        ("sa_29_24_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","05-29",None,24,[299.89,374.86,464.83,515.97,552.08,640.42,765.56,897.24,1068.17,1799.34],49),
        ("sa_29_24_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","05-29",None,24,[331.67,414.58,514.07,570.62,610.57,708.27,846.66,992.30,1181.32,1989.95],50),
        ("sa_29_24_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","05-29",None,24,[543.95,679.91,843.10,935.85,1001.36,1161.58,1388.54,1627.36,1937.38,3263.51],51),
        ("sa_29_24_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","05-29",None,24,[572.56,715.71,887.47,985.10,1054.06,1222.71,1461.62,1713.01,2039.35,3435.27],52),
        ("sa_29_24_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","05-29",None,24,[1089.36,1361.71,1688.51,1874.24,2005.44,2326.31,2780.87,3259.18,3880.05,6535.95],53),
        ("sa_29_24_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","05-29",None,24,[1302.71,1628.38,2019.19,2241.31,2398.20,2781.90,3325.49,3897.48,4639.93,7815.97],54),
        ("sa_29_24_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","05-29",None,24,[1455.17,1818.98,2255.52,2503.63,2678.89,3107.51,3714.71,4353.64,5183.01,8730.78],55),
        ("sa_29_24_sc_8","sulamerica","Sem copart — Prestige","apt","pme","05-29",None,24,[1908.49,2385.62,2958.17,3283.58,3513.41,4075.56,4871.92,5709.88,6797.62,11450.59],56),
        ("sa_29_24_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","05-29",None,24,[209.92,262.40,325.38,361.18,386.46,448.29,535.89,628.07,747.72,1259.52],57),
        ("sa_29_24_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","05-29",None,24,[232.17,290.21,359.86,399.44,427.40,495.79,592.67,694.60,826.93,1392.96],58),
        ("sa_29_24_cc_3","sulamerica","Com copart — Especial RC","apt","pme","05-29",None,24,[407.95,509.94,632.32,701.88,751.01,871.18,1041.40,1220.53,1453.03,2447.63],59),
        ("sa_29_24_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","05-29",None,24,[429.43,536.78,665.60,738.83,790.54,917.03,1096.21,1284.77,1529.51,2576.45],60),
        ("sa_29_24_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","05-29",None,24,[925.96,1157.46,1435.23,1593.11,1704.62,1977.36,2363.73,2770.31,3298.05,5555.55],61),
        ("sa_29_24_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","05-29",None,24,[1107.29,1384.13,1716.32,1905.10,2038.46,2364.62,2826.67,3312.86,3943.95,6643.58],62),
        ("sa_29_24_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","05-29",None,24,[1236.90,1546.13,1917.20,2128.09,2277.06,2641.38,3157.51,3700.60,4405.57,7421.17],63),
        ("sa_29_24_cc_8","sulamerica","Com copart — Prestige","apt","pme","05-29",None,24,[1622.22,2027.78,2514.45,2791.04,2986.41,3464.22,4141.12,4853.39,5777.97,9733.01],64),
        # SULAMERICA — PME 30-99v 12m
        ("sa_99_12_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","30-99",None,12,[302.29,377.86,468.55,520.09,556.49,645.53,771.67,904.40,1076.68,1813.67],65),
        ("sa_99_12_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","30-99",None,12,[334.32,417.90,518.20,575.20,615.46,713.94,853.44,1000.23,1190.77,2005.86],66),
        ("sa_99_12_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","30-99",None,12,[549.38,686.72,851.53,945.20,1011.37,1173.19,1402.43,1643.64,1956.75,3296.15],67),
        ("sa_99_12_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","30-99",None,12,[578.29,722.86,896.35,994.94,1064.59,1234.93,1476.23,1730.14,2059.73,3469.62],68),
        ("sa_99_12_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","30-99",None,12,[1106.79,1383.49,1715.53,1904.24,2037.53,2363.54,2825.38,3311.34,3942.14,6640.54],69),
        ("sa_99_12_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","30-99",None,12,[1323.54,1654.43,2051.49,2277.16,2436.56,2826.41,3378.69,3959.83,4714.17,7941.02],70),
        ("sa_99_12_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","30-99",None,12,[1478.46,1848.08,2291.62,2543.70,2721.76,3157.24,3774.17,4423.32,5265.96,8870.51],71),
        ("sa_99_12_sc_8","sulamerica","Sem copart — Prestige","apt","pme","30-99",None,12,[1939.03,2423.79,3005.50,3336.10,3569.64,4140.78,4949.89,5801.27,6906.40,11633.83],72),
        ("sa_99_12_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","30-99",None,12,[211.60,264.50,327.98,364.06,389.54,451.87,540.16,633.07,753.67,1269.56],73),
        ("sa_99_12_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","30-99",None,12,[234.02,292.53,362.74,402.64,430.82,499.76,597.41,700.16,833.54,1404.10],74),
        ("sa_99_12_cc_3","sulamerica","Com copart — Especial RC","apt","pme","30-99",None,12,[412.03,515.04,638.65,708.90,758.53,879.89,1051.82,1232.73,1467.57,2472.11],75),
        ("sa_99_12_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","30-99",None,12,[433.71,542.14,672.25,746.20,798.44,926.19,1107.16,1297.60,1544.78,2602.19],76),
        ("sa_99_12_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","30-99",None,12,[940.78,1175.97,1458.20,1618.61,1731.91,2009.02,2401.58,2814.65,3350.83,5644.48],77),
        ("sa_99_12_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","30-99",None,12,[1125.02,1406.27,1743.77,1935.59,2071.08,2402.46,2871.90,3365.87,4007.05,6749.89],78),
        ("sa_99_12_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","30-99",None,12,[1256.70,1570.87,1947.88,2162.15,2313.50,2683.66,3208.05,3759.83,4476.07,7539.94],79),
        ("sa_99_12_cc_8","sulamerica","Com copart — Prestige","apt","pme","30-99",None,12,[1648.18,2060.22,2554.67,2835.69,3034.19,3519.66,4207.40,4931.07,5870.43,9888.75],80),
        # SULAMERICA — PME 30-99v 24m
        ("sa_99_24_sc_1","sulamerica","Sem copart — Direto Enf","enf","pme","30-99",None,24,[299.89,374.86,464.83,515.96,552.08,640.41,765.54,897.22,1068.13,1799.27],81),
        ("sa_99_24_sc_2","sulamerica","Sem copart — Direto Qto","apt","pme","30-99",None,24,[331.66,414.58,514.08,570.63,610.57,708.26,846.66,992.28,1181.31,1989.92],82),
        ("sa_99_24_sc_3","sulamerica","Sem copart — Especial RC","apt","pme","30-99",None,24,[543.94,679.93,843.11,935.86,1001.37,1161.59,1388.56,1627.39,1937.41,3263.56],83),
        ("sa_99_24_sc_4","sulamerica","Sem copart — Especial 100 R1","apt","pme","30-99",None,24,[572.57,715.71,887.48,985.10,1054.06,1222.71,1461.63,1713.03,2039.36,3435.30],84),
        ("sa_99_24_sc_5","sulamerica","Sem copart — Executivo R1","apt","pme","30-99",None,24,[1089.36,1361.70,1688.51,1874.24,2005.44,2326.31,2780.88,3259.19,3880.06,6535.96],85),
        ("sa_99_24_sc_6","sulamerica","Sem copart — Executivo R2","apt","pme","30-99",None,24,[1302.70,1628.38,2019.19,2241.30,2398.20,2781.91,3325.49,3897.48,4639.94,7815.98],86),
        ("sa_99_24_sc_7","sulamerica","Sem copart — Executivo R3","apt","pme","30-99",None,24,[1455.18,1818.97,2255.52,2503.63,2678.89,3107.51,3714.72,4353.65,5183.01,8730.78],87),
        ("sa_99_24_sc_8","sulamerica","Sem copart — Prestige","apt","pme","30-99",None,24,[1908.50,2385.62,2958.17,3283.57,3513.42,4075.57,4871.94,5709.91,6797.63,11450.62],88),
        ("sa_99_24_cc_1","sulamerica","Com copart — Direto Enf","enf","pme","30-99",None,24,[209.93,262.41,325.39,361.18,386.46,448.30,535.90,628.07,747.72,1259.53],89),
        ("sa_99_24_cc_2","sulamerica","Com copart — Direto Qto","apt","pme","30-99",None,24,[232.17,290.21,359.86,399.45,427.41,495.79,592.67,694.61,826.93,1392.96],90),
        ("sa_99_24_cc_3","sulamerica","Com copart — Especial RC","apt","pme","30-99",None,24,[407.96,509.95,632.34,701.90,751.03,871.19,1041.42,1220.55,1453.06,2447.68],91),
        ("sa_99_24_cc_4","sulamerica","Com copart — Especial 100 R1","apt","pme","30-99",None,24,[429.43,536.79,665.62,738.84,790.56,917.05,1096.24,1284.79,1529.54,2576.51],92),
        ("sa_99_24_cc_5","sulamerica","Com copart — Executivo R1","apt","pme","30-99",None,24,[925.96,1157.45,1435.24,1593.11,1704.63,1977.38,2363.76,2770.32,3298.06,5555.59],93),
        ("sa_99_24_cc_6","sulamerica","Com copart — Executivo R2","apt","pme","30-99",None,24,[1107.30,1384.12,1716.31,1905.10,2038.46,2364.62,2826.66,3312.85,3943.94,6643.57],94),
        ("sa_99_24_cc_7","sulamerica","Com copart — Executivo R3","apt","pme","30-99",None,24,[1236.90,1546.13,1917.20,2128.09,2277.06,2641.39,3157.52,3700.62,4405.57,7421.19],95),
        ("sa_99_24_cc_8","sulamerica","Com copart — Prestige","apt","pme","30-99",None,24,[1622.22,2027.77,2514.43,2791.02,2986.40,3464.22,4141.13,4853.41,5777.97,9732.99],96),
    ]
    for i, (codigo, op_chave, nome, aco, tipo, fvidas, mod, vig, precos, ordem) in enumerate(_PLANOS):
        op_id = ops_map.get(op_chave)
        if not op_id:
            continue
        conn.execute(
            "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (codigo, op_id, nome, aco, tipo, fvidas, mod, vig, json.dumps(precos), ordem),
        )
    conn.commit()
    conn.close()


# ── Modelos ───────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str

class CorretoraRequest(BaseModel):
    nome: str
    limite_usuarios: int = 5
    data_expiracao: str

class UpdateCorretoraRequest(BaseModel):
    nome: Optional[str] = None
    limite_usuarios: Optional[int] = None
    data_expiracao: Optional[str] = None
    ativo: Optional[int] = None

class CreateUserRequest(BaseModel):
    nome: str
    username: str
    email: Optional[str] = None
    password: str
    role: str = "corretor"
    corretora_id: Optional[int] = None

class CotacaoRequest(BaseModel):
    cliente: str
    dados: dict
    cliente_id: Optional[int] = None

class OperadoraRequest(BaseModel):
    chave: str
    nome: str
    info: Optional[str] = None
    cor: Optional[str] = None
    ativo: Optional[int] = 1
    ordem: Optional[int] = 0

class UpdateOperadoraRequest(BaseModel):
    nome: Optional[str] = None
    info: Optional[str] = None
    cor: Optional[str] = None
    ativo: Optional[int] = None
    ordem: Optional[int] = None

class PlanoRequest(BaseModel):
    codigo: str
    operadora_id: int
    nome: str
    aco: str
    tipo: Optional[str] = None
    fvidas: Optional[str] = None
    mod: Optional[str] = None
    vig: Optional[int] = None
    rede_chave: Optional[str] = None
    precos: list
    ativo: Optional[int] = 1
    ordem: Optional[int] = 0

class UpdatePlanoRequest(BaseModel):
    nome: Optional[str] = None
    aco: Optional[str] = None
    tipo: Optional[str] = None
    fvidas: Optional[str] = None
    mod: Optional[str] = None
    vig: Optional[int] = None
    rede_chave: Optional[str] = None
    precos: Optional[list] = None
    ativo: Optional[int] = None
    ordem: Optional[int] = None


class RedeItemRequest(BaseModel):
    operadora_id: int
    grupo: str = ""
    grupo_ordem: int = 0
    nome: str
    local: Optional[str] = None
    tags: Optional[list] = None
    obs: Optional[str] = None
    tag_extra: Optional[dict] = None
    ordem: int = 0
    ativo: int = 1


class UpdateRedeItemRequest(BaseModel):
    grupo: Optional[str] = None
    grupo_ordem: Optional[int] = None
    nome: Optional[str] = None
    local: Optional[str] = None
    tags: Optional[list] = None
    obs: Optional[str] = None
    tag_extra: Optional[dict] = None
    ordem: Optional[int] = None
    ativo: Optional[int] = None


class RedeMetaRequest(BaseModel):
    rede_adm: Optional[str] = None
    rede_rodape: Optional[str] = None


class ClienteRequest(BaseModel):
    nome: str
    empresa: Optional[str] = None
    cnpj: Optional[str] = None
    telefone: Optional[str] = None
    email: Optional[str] = None
    n_vidas_estimado: Optional[int] = None
    segmento: Optional[str] = None
    origem: Optional[str] = None

class UpdateClienteRequest(BaseModel):
    nome: Optional[str] = None
    empresa: Optional[str] = None
    cnpj: Optional[str] = None
    telefone: Optional[str] = None
    email: Optional[str] = None
    n_vidas_estimado: Optional[int] = None
    segmento: Optional[str] = None
    origem: Optional[str] = None
    ativo: Optional[int] = None
    compartilhado: Optional[int] = None
    plano_atual: Optional[str] = None
    operadora_atual: Optional[str] = None

class OportunidadeRequest(BaseModel):
    estagio: Optional[str] = "lead"
    valor_estimado: Optional[float] = None
    data_prevista_fechamento: Optional[str] = None
    motivo_perda: Optional[str] = None
    obs: Optional[str] = None

class UpdateOportunidadeRequest(BaseModel):
    estagio: Optional[str] = None
    valor_estimado: Optional[float] = None
    data_prevista_fechamento: Optional[str] = None
    motivo_perda: Optional[str] = None
    obs: Optional[str] = None

class InteracaoRequest(BaseModel):
    tipo: str
    descricao: Optional[str] = None


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.post("/api/login")
@limiter.limit("10/minute")  # limite por IP; soma-se ao lockout por conta (abaixo)
def login(req: LoginRequest, request: Request):
    ip = request.client.host if request.client else ""
    conn = get_connection()

    row = conn.execute(
        """SELECT id, hashed_password, nome, ativo, role, corretora_id,
                  tentativas_login, bloqueado_ate
           FROM users WHERE username = ?""",
        (req.username.strip(),),
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(401, "Usuário ou senha incorretos")

    # Verifica bloqueio temporário
    if row["bloqueado_ate"]:
        try:
            bloqueado_dt = datetime.fromisoformat(str(row["bloqueado_ate"]))
            if bloqueado_dt.tzinfo is None:
                bloqueado_dt = bloqueado_dt.replace(tzinfo=timezone.utc)
            agora = datetime.now(timezone.utc)
            if agora < bloqueado_dt:
                conn.close()
                minutos = max(1, int((bloqueado_dt - agora).total_seconds() / 60) + 1)
                raise HTTPException(429, f"Conta bloqueada. Tente novamente em {minutos} minuto(s).")
        except HTTPException:
            raise
        except Exception:
            pass

    # Verifica senha
    if not verify_password(req.password, row["hashed_password"]):
        tentativas = (row["tentativas_login"] or 0) + 1
        bloqueado_ate = None
        if tentativas >= MAX_TENTATIVAS:
            bloqueado_ate = (
                datetime.now(timezone.utc) + timedelta(minutes=BLOQUEIO_MINUTOS)
            ).isoformat()
            tentativas = 0
        conn.execute(
            "UPDATE users SET tentativas_login = ?, bloqueado_ate = ? WHERE username = ?",
            (tentativas, bloqueado_ate, req.username.strip()),
        )
        conn.commit()
        conn.close()
        if bloqueado_ate:
            raise HTTPException(
                429, f"Conta bloqueada por {BLOQUEIO_MINUTOS} minutos após tentativas excessivas."
            )
        restantes = MAX_TENTATIVAS - tentativas
        raise HTTPException(401, f"Senha incorreta. {restantes} tentativa(s) restante(s).")

    if not row["ativo"]:
        conn.close()
        raise HTTPException(401, "Usuário inativo. Contate o administrador.")

    # Verifica assinatura da corretora (não aplica ao superadmin)
    if row["role"] != "superadmin" and row["corretora_id"]:
        corretora = conn.execute(
            "SELECT ativo, data_expiracao FROM corretoras WHERE id = ?",
            (row["corretora_id"],),
        ).fetchone()
        if corretora:
            if not corretora["ativo"]:
                conn.close()
                raise HTTPException(403, "Assinatura da corretora inativa. Contate o suporte.")
            if str(corretora["data_expiracao"]) < date.today().isoformat():
                conn.close()
                raise HTTPException(403, "Assinatura expirada. Contate o suporte para renovar.")

    # Reseta tentativas e grava novo session_token (invalida sessões anteriores)
    session_tok = secrets.token_hex(32)
    conn.execute(
        "UPDATE users SET tentativas_login = 0, bloqueado_ate = NULL, session_token = ? WHERE username = ?",
        (session_tok, req.username.strip()),
    )
    conn.commit()
    conn.close()

    log_action(req.username, "login", "Login bem-sucedido", ip)

    token = create_access_token({
        "sub": req.username.strip(),
        "nome": row["nome"],
        "role": row["role"],
        "corretora_id": row["corretora_id"],
        "session_token": session_tok,
    })
    return {
        "access_token": token,
        "token_type": "bearer",
        "nome": row["nome"],
        "role": row["role"],
        "corretora_id": row["corretora_id"],
    }


@app.get("/api/me")
def me(user=Depends(get_current_user)):
    conn = get_connection()
    row = conn.execute("SELECT id FROM users WHERE username = ?", (user["sub"],)).fetchone()
    user_id = row["id"] if row else None
    conn.close()
    return {
        "id": user_id,
        "username": user["sub"],
        "nome": user.get("nome"),
        "role": user.get("role"),
        "corretora_id": user.get("corretora_id"),
    }


@app.post("/api/logout")
def logout(user=Depends(get_current_user)):
    conn = get_connection()
    conn.execute("UPDATE users SET session_token = NULL WHERE username = ?", (user["sub"],))
    conn.commit()
    conn.close()
    log_action(user["sub"], "logout", "Sessão encerrada")
    return {"ok": True}


# ── Superadmin: Corretoras ────────────────────────────────────────────────────

@app.get("/api/superadmin/corretoras")
def listar_corretoras(admin=Depends(require_superadmin)):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, nome, limite_usuarios, data_expiracao, ativo, criado_em FROM corretoras ORDER BY criado_em DESC"
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        cnt = conn.execute(
            "SELECT COUNT(*) as cnt FROM users WHERE corretora_id = ? AND role = 'corretor'",
            (d["id"],),
        ).fetchone()
        d["total_usuarios"] = cnt["cnt"]
        result.append(d)
    conn.close()
    return result


@app.post("/api/superadmin/corretoras")
def criar_corretora(body: CorretoraRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    conn.execute(
        "INSERT INTO corretoras (nome, limite_usuarios, data_expiracao) VALUES (?, ?, ?)",
        (body.nome.strip(), body.limite_usuarios, body.data_expiracao),
    )
    conn.commit()
    row = conn.execute(
        "SELECT id, nome, limite_usuarios, data_expiracao, ativo, criado_em FROM corretoras ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()
    log_action(admin["sub"], "criar_corretora", f"Corretora: {body.nome}")
    return dict(row)


@app.patch("/api/superadmin/corretoras/{corretora_id}")
def atualizar_corretora(corretora_id: int, body: UpdateCorretoraRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM corretoras WHERE id = ?", (corretora_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Corretora não encontrada")
    updates, params = [], []
    if body.nome is not None:
        updates.append("nome = ?"); params.append(body.nome.strip())
    if body.limite_usuarios is not None:
        updates.append("limite_usuarios = ?"); params.append(body.limite_usuarios)
    if body.data_expiracao is not None:
        updates.append("data_expiracao = ?"); params.append(body.data_expiracao)
    if body.ativo is not None:
        updates.append("ativo = ?"); params.append(body.ativo)
    if updates:
        params.append(corretora_id)
        conn.execute(f"UPDATE corretoras SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    log_action(admin["sub"], "atualizar_corretora", f"Corretora {corretora_id} atualizada")
    return {"ok": True}


@app.delete("/api/superadmin/corretoras/{corretora_id}")
def deletar_corretora(corretora_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM corretoras WHERE id = ?", (corretora_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Corretora não encontrada")
    conn.execute("DELETE FROM users WHERE corretora_id = ?", (corretora_id,))
    conn.execute("DELETE FROM corretoras WHERE id = ?", (corretora_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_corretora", f"Corretora {corretora_id} removida")
    return {"ok": True}


# ── Superadmin: Usuários ──────────────────────────────────────────────────────

@app.get("/api/superadmin/users")
def listar_todos_usuarios(admin=Depends(require_superadmin)):
    conn = get_connection()
    rows = conn.execute(
        """SELECT u.id, u.username, u.nome, u.email, u.role, u.ativo,
                  u.corretora_id, u.criado_em, c.nome as corretora_nome
           FROM users u
           LEFT JOIN corretoras c ON u.corretora_id = c.id
           WHERE u.role != 'superadmin'
           ORDER BY u.criado_em DESC"""
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/superadmin/users")
def criar_usuario_superadmin(body: CreateUserRequest, admin=Depends(require_superadmin)):
    validate_password(body.password)
    if body.role not in ("admin", "corretor"):
        raise HTTPException(400, "Role inválida. Use 'admin' ou 'corretor'.")
    if body.role == "admin" and not body.corretora_id:
        raise HTTPException(400, "Administrador deve pertencer a uma corretora.")
    conn = get_connection()
    if conn.execute("SELECT id FROM users WHERE username = ?", (body.username.strip(),)).fetchone():
        conn.close()
        raise HTTPException(409, "Nome de usuário já cadastrado.")
    conn.execute(
        "INSERT INTO users (username, email, hashed_password, nome, role, corretora_id) VALUES (?, ?, ?, ?, ?, ?)",
        (body.username.strip(), body.email, hash_password(body.password), body.nome.strip(), body.role, body.corretora_id),
    )
    conn.commit()
    conn.close()
    log_action(admin["sub"], "criar_usuario", f"Usuário {body.username} ({body.role})")
    return {"ok": True}


@app.patch("/api/superadmin/users/{user_id}/toggle")
def toggle_usuario_superadmin(user_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT ativo, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Usuário não encontrado")
    if row["role"] == "superadmin":
        conn.close()
        raise HTTPException(400, "Não é possível alterar o super administrador")
    new_status = 0 if row["ativo"] else 1
    conn.execute("UPDATE users SET ativo = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"ativo": new_status}


@app.delete("/api/superadmin/users/{user_id}")
def deletar_usuario_superadmin(user_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT role, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Usuário não encontrado")
    if row["role"] == "superadmin":
        conn.close()
        raise HTTPException(400, "Não é possível remover o super administrador")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_usuario", f"Usuário {row['username']} removido")
    return {"ok": True}


# ── Superadmin: Auditoria ─────────────────────────────────────────────────────

@app.get("/api/superadmin/audit")
def listar_audit(admin=Depends(require_superadmin)):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, usuario, acao, detalhes, ip, criado_em FROM audit_log ORDER BY criado_em DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Admin da corretora ────────────────────────────────────────────────────────

@app.get("/api/admin/users")
def listar_usuarios_corretora(admin=Depends(require_admin)):
    corretora_id = admin.get("corretora_id")
    conn = get_connection()
    corretora = conn.execute(
        "SELECT nome, limite_usuarios FROM corretoras WHERE id = ?", (corretora_id,)
    ).fetchone() if corretora_id else None
    rows = conn.execute(
        "SELECT id, username, nome, email, ativo, criado_em FROM users WHERE corretora_id = ? AND role = 'corretor' ORDER BY criado_em DESC",
        (corretora_id,),
    ).fetchall()
    conn.close()
    return {
        "corretora": dict(corretora) if corretora else None,
        "usuarios": [dict(r) for r in rows],
        "total": len(rows),
        "limite": corretora["limite_usuarios"] if corretora else None,
    }


@app.post("/api/admin/users")
def criar_usuario_corretora(body: CreateUserRequest, admin=Depends(require_admin)):
    corretora_id = admin.get("corretora_id")
    validate_password(body.password)
    conn = get_connection()
    corretora = conn.execute(
        "SELECT limite_usuarios FROM corretoras WHERE id = ?", (corretora_id,)
    ).fetchone()
    if not corretora:
        conn.close()
        raise HTTPException(404, "Corretora não encontrada")
    count = conn.execute(
        "SELECT COUNT(*) as cnt FROM users WHERE corretora_id = ? AND role = 'corretor'",
        (corretora_id,),
    ).fetchone()
    if count["cnt"] >= corretora["limite_usuarios"]:
        conn.close()
        raise HTTPException(400, f"Limite de {corretora['limite_usuarios']} colaborador(es) atingido. Contrate mais vagas.")
    if conn.execute("SELECT id FROM users WHERE username = ?", (body.username.strip(),)).fetchone():
        conn.close()
        raise HTTPException(409, "Nome de usuário já cadastrado.")
    conn.execute(
        "INSERT INTO users (username, email, hashed_password, nome, role, corretora_id) VALUES (?, ?, ?, ?, 'corretor', ?)",
        (body.username.strip(), body.email, hash_password(body.password), body.nome.strip(), corretora_id),
    )
    conn.commit()
    conn.close()
    log_action(admin["sub"], "criar_corretor", f"Corretor {body.username} adicionado")
    return {"ok": True}


@app.patch("/api/admin/users/{user_id}/toggle")
def toggle_usuario_corretora(user_id: int, admin=Depends(require_admin)):
    corretora_id = admin.get("corretora_id")
    conn = get_connection()
    row = conn.execute(
        "SELECT ativo, corretora_id FROM users WHERE id = ? AND role = 'corretor'", (user_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Usuário não encontrado")
    if corretora_id and row["corretora_id"] != corretora_id:
        conn.close()
        raise HTTPException(403, "Sem permissão para gerenciar este usuário")
    new_status = 0 if row["ativo"] else 1
    conn.execute("UPDATE users SET ativo = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    return {"ativo": new_status}


@app.delete("/api/admin/users/{user_id}")
def deletar_usuario_corretora(user_id: int, admin=Depends(require_admin)):
    corretora_id = admin.get("corretora_id")
    conn = get_connection()
    row = conn.execute(
        "SELECT username, corretora_id FROM users WHERE id = ? AND role = 'corretor'", (user_id,)
    ).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Usuário não encontrado")
    if corretora_id and row["corretora_id"] != corretora_id:
        conn.close()
        raise HTTPException(403, "Sem permissão para remover este usuário")
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_corretor", f"Corretor {row['username']} removido")
    return {"ok": True}


# ── Cotações ──────────────────────────────────────────────────────────────────

@app.post("/api/cotacoes")
def salvar_cotacao(body: CotacaoRequest, user=Depends(require_corretor)):
    conn = get_connection()
    if body.cliente_id is not None:
        cli = conn.execute("SELECT * FROM clientes WHERE id = ?", (body.cliente_id,)).fetchone()
        if not cli:
            conn.close()
            raise HTTPException(400, "Cliente informado não existe")
        try:
            _check_cliente_acesso(dict(cli), user)
        except HTTPException:
            conn.close()
            raise
    conn.execute(
        "INSERT INTO cotacoes (usuario, usuario_id, corretora_id, cliente, cliente_id, dados) VALUES (?, ?, ?, ?, ?, ?)",
        (user["sub"], user.get("id"), user.get("corretora_id"), body.cliente, body.cliente_id, json.dumps(body.dados, ensure_ascii=False)),
    )
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/cotacoes")
def listar_cotacoes(user=Depends(require_corretor)):
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, cliente, dados, criado_em FROM cotacoes WHERE usuario = ? ORDER BY criado_em DESC LIMIT 100",
        (user["sub"],),
    ).fetchall()
    conn.close()
    return [
        {"id": r["id"], "cliente": r["cliente"], "dados": json.loads(r["dados"]), "criado_em": r["criado_em"]}
        for r in rows
    ]


# ── Catálogo público (usado pelo cotador) ─────────────────────────────────────

FAIXAS = ['0 a 18','19 a 23','24 a 28','29 a 33','34 a 38','39 a 43','44 a 48','49 a 53','54 a 58','59 ou mais']

@app.get("/api/catalogo")
def catalogo_publico():
    conn = get_connection()
    ops_rows = conn.execute(
        "SELECT id, chave, nome, info, cor, rede_adm, rede_rodape FROM operadoras WHERE ativo = 1 ORDER BY ordem, id"
    ).fetchall()
    planos_rows = conn.execute(
        """SELECT p.codigo, o.chave as op, p.nome, p.acomodacao as aco, p.tipo,
                  p.faixa_vidas as fvidas, p.moderador as mod, p.mes_vigencia as vig, p.rede_chave, p.precos
           FROM planos p JOIN operadoras o ON p.operadora_id = o.id
           WHERE p.ativo = 1 AND o.ativo = 1
           ORDER BY o.ordem, p.ordem, p.id"""
    ).fetchall()
    rede_rows = conn.execute(
        """SELECT rc.grupo, rc.grupo_ordem, rc.nome, rc.local, rc.tags, rc.obs, rc.tag_extra, rc.ordem, o.chave as op_chave
           FROM rede_credenciada rc JOIN operadoras o ON rc.operadora_id = o.id
           WHERE rc.ativo = 1 AND o.ativo = 1
           ORDER BY o.ordem, rc.grupo_ordem, rc.ordem, rc.id"""
    ).fetchall()
    conn.close()
    operadoras = {r["chave"]: {"nome": r["nome"], "info": r["info"] or "", "cor": r["cor"] or ""} for r in ops_rows}
    planos = []
    for r in planos_rows:
        p = {
            "id":     r["codigo"],
            "op":     r["op"],
            "nome":   r["nome"],
            "aco":    r["aco"],
            "tipo":   r["tipo"] or "adesao",
            "precos": json.loads(r["precos"]),
        }
        if r["fvidas"]:     p["fvidas"] = r["fvidas"]
        if r["mod"]:        p["mod"] = r["mod"]
        if r["vig"]:        p["vig"] = r["vig"]
        if r["rede_chave"]: p["rede_chave"] = r["rede_chave"]
        planos.append(p)
    # Build rede dict only when there are rows in the DB
    rede = {}
    if rede_rows:
        op_meta_map = {r["chave"]: r for r in ops_rows}
        for r in rede_rows:
            op = r["op_chave"]
            if op not in rede:
                meta = op_meta_map.get(op, {})
                rede[op] = {
                    "adm": (meta["rede_adm"] or "") if meta else "",
                    "grupos": [],
                    "rodape": (meta["rede_rodape"] or "") if meta else "",
                }
            grupo_titulo = r["grupo"] or ""
            grupos = rede[op]["grupos"]
            existing = next((g for g in grupos if g["titulo"] == grupo_titulo), None)
            if not existing:
                existing = {"titulo": grupo_titulo, "itens": []}
                grupos.append(existing)
            item = {"nome": r["nome"]}
            if r["local"]:     item["local"] = r["local"]
            if r["tags"]:      item["tags"] = json.loads(r["tags"])
            if r["obs"]:       item["obs"] = r["obs"]
            if r["tag_extra"]: item["tagExtra"] = json.loads(r["tag_extra"])
            existing["itens"].append(item)
    return {"faixas": FAIXAS, "operadoras": operadoras, "planos": planos, "rede": rede}


# ── Superadmin: Catálogo — Operadoras ─────────────────────────────────────────

@app.get("/api/superadmin/catalogo/operadoras")
def listar_operadoras(admin=Depends(require_superadmin)):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM operadoras ORDER BY ordem, id").fetchall()
    result = []
    for r in rows:
        d = dict(r)
        cnt = conn.execute("SELECT COUNT(*) as cnt FROM planos WHERE operadora_id = ?", (d["id"],)).fetchone()
        d["total_planos"] = cnt["cnt"]
        result.append(d)
    conn.close()
    return result

@app.post("/api/superadmin/catalogo/operadoras")
def criar_operadora(body: OperadoraRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if conn.execute("SELECT id FROM operadoras WHERE chave = ?", (body.chave.strip(),)).fetchone():
        conn.close()
        raise HTTPException(409, "Chave de operadora já existe.")
    conn.execute(
        "INSERT INTO operadoras (chave, nome, info, cor, ativo, ordem) VALUES (?, ?, ?, ?, ?, ?)",
        (body.chave.strip(), body.nome.strip(), body.info, (body.cor or None), body.ativo, body.ordem),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM operadoras WHERE chave = ?", (body.chave.strip(),)).fetchone()
    conn.close()
    log_action(admin["sub"], "criar_operadora", f"Operadora: {body.nome}")
    return dict(row)

@app.patch("/api/superadmin/catalogo/operadoras/{op_id}")
def atualizar_operadora(op_id: int, body: UpdateOperadoraRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM operadoras WHERE id = ?", (op_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Operadora não encontrada")
    updates, params = [], []
    for field in ("nome", "info", "cor", "ativo", "ordem"):
        val = getattr(body, field)
        if val is not None:
            updates.append(f"{field} = ?"); params.append(val.strip() if isinstance(val, str) else val)
    if updates:
        params.append(op_id)
        conn.execute(f"UPDATE operadoras SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/api/superadmin/catalogo/operadoras/{op_id}")
def deletar_operadora(op_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT nome FROM operadoras WHERE id = ?", (op_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Operadora não encontrada")
    conn.execute("DELETE FROM planos WHERE operadora_id = ?", (op_id,))
    conn.execute("DELETE FROM operadoras WHERE id = ?", (op_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_operadora", f"Operadora {row['nome']} removida")
    return {"ok": True}


# ── Superadmin: Catálogo — Planos ─────────────────────────────────────────────

@app.get("/api/superadmin/catalogo/planos")
def listar_planos(admin=Depends(require_superadmin)):
    conn = get_connection()
    rows = conn.execute(
        """SELECT p.*, o.nome as op_nome, o.chave as op_chave
           FROM planos p JOIN operadoras o ON p.operadora_id = o.id
           ORDER BY o.ordem, p.ordem, p.id"""
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["precos"] = json.loads(d["precos"])
        result.append(d)
    return result

@app.post("/api/superadmin/catalogo/planos")
def criar_plano(body: PlanoRequest, admin=Depends(require_superadmin)):
    if len(body.precos) != 10:
        raise HTTPException(400, "precos deve ter exatamente 10 valores (um por faixa etária)")
    conn = get_connection()
    if conn.execute("SELECT id FROM planos WHERE codigo = ?", (body.codigo.strip(),)).fetchone():
        conn.close()
        raise HTTPException(409, "Código de plano já existe.")
    conn.execute(
        "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, rede_chave, precos, ativo, ordem) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (body.codigo.strip(), body.operadora_id, body.nome.strip(), body.aco, body.tipo, body.fvidas, body.mod, body.vig, (body.rede_chave or None), json.dumps(body.precos), body.ativo, body.ordem),
    )
    conn.commit()
    conn.close()
    log_action(admin["sub"], "criar_plano", f"Plano {body.codigo} — {body.nome}")
    return {"ok": True}

@app.patch("/api/superadmin/catalogo/planos/{plano_id}")
def atualizar_plano(plano_id: int, body: UpdatePlanoRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM planos WHERE id = ?", (plano_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Plano não encontrado")
    if body.precos is not None and len(body.precos) != 10:
        conn.close()
        raise HTTPException(400, "precos deve ter exatamente 10 valores")
    _COL = {"aco": "acomodacao", "fvidas": "faixa_vidas", "mod": "moderador", "vig": "mes_vigencia"}
    updates, params = [], []
    for field in ("nome", "aco", "tipo", "fvidas", "mod", "vig", "rede_chave", "ativo", "ordem"):
        val = getattr(body, field)
        if val is not None:
            db_col = _COL.get(field, field)
            updates.append(f"{db_col} = ?"); params.append(val.strip() if isinstance(val, str) else val)
    if body.precos is not None:
        updates.append("precos = ?"); params.append(json.dumps(body.precos))
    if updates:
        params.append(plano_id)
        conn.execute(f"UPDATE planos SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/api/superadmin/catalogo/planos/{plano_id}")
def deletar_plano(plano_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT codigo, nome FROM planos WHERE id = ?", (plano_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Plano não encontrado")
    conn.execute("DELETE FROM planos WHERE id = ?", (plano_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_plano", f"Plano {row['codigo']} removido")
    return {"ok": True}


@app.patch("/api/superadmin/catalogo/operadoras/{op_id}/toggle")
def toggle_operadora(op_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT ativo FROM operadoras WHERE id = ?", (op_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Operadora não encontrada")
    new_status = 0 if row["ativo"] else 1
    conn.execute("UPDATE operadoras SET ativo = ? WHERE id = ?", (new_status, op_id))
    conn.commit()
    conn.close()
    return {"ativo": new_status}


@app.patch("/api/superadmin/catalogo/planos/{plano_id}/toggle")
def toggle_plano(plano_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT ativo FROM planos WHERE id = ?", (plano_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Plano não encontrado")
    new_status = 0 if row["ativo"] else 1
    conn.execute("UPDATE planos SET ativo = ? WHERE id = ?", (new_status, plano_id))
    conn.commit()
    conn.close()
    return {"ativo": new_status}


# ── Superadmin: Catálogo — Rede Credenciada ───────────────────────────────────

@app.get("/api/superadmin/catalogo/rede")
def listar_rede(operadora_id: Optional[int] = None, admin=Depends(require_superadmin)):
    conn = get_connection()
    if operadora_id:
        rows = conn.execute(
            "SELECT * FROM rede_credenciada WHERE operadora_id = ? ORDER BY grupo_ordem, ordem, id",
            (operadora_id,)
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM rede_credenciada ORDER BY operadora_id, grupo_ordem, ordem, id"
        ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("tags"):      d["tags"]      = json.loads(d["tags"])
        if d.get("tag_extra"): d["tag_extra"]  = json.loads(d["tag_extra"])
        result.append(d)
    return result

@app.post("/api/superadmin/catalogo/rede")
def criar_rede_item(body: RedeItemRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM operadoras WHERE id = ?", (body.operadora_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Operadora não encontrada")
    conn.execute(
        """INSERT INTO rede_credenciada
           (operadora_id, grupo, grupo_ordem, nome, local, tags, obs, tag_extra, ordem, ativo)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            body.operadora_id, body.grupo, body.grupo_ordem, body.nome.strip(),
            body.local, json.dumps(body.tags) if body.tags is not None else None,
            body.obs,  json.dumps(body.tag_extra) if body.tag_extra is not None else None,
            body.ordem, body.ativo,
        ),
    )
    conn.commit()
    conn.close()
    log_action(admin["sub"], "criar_rede_item", f"Rede op={body.operadora_id} item={body.nome}")
    return {"ok": True}

@app.patch("/api/superadmin/catalogo/rede/{item_id}")
def atualizar_rede_item(item_id: int, body: UpdateRedeItemRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM rede_credenciada WHERE id = ?", (item_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Item de rede não encontrado")
    updates, params = [], []
    for field in ("grupo", "grupo_ordem", "nome", "local", "obs", "ordem", "ativo"):
        val = getattr(body, field)
        if val is not None:
            updates.append(f"{field} = ?"); params.append(val.strip() if isinstance(val, str) else val)
    if body.tags is not None:
        updates.append("tags = ?"); params.append(json.dumps(body.tags))
    if body.tag_extra is not None:
        updates.append("tag_extra = ?"); params.append(json.dumps(body.tag_extra))
    if updates:
        params.append(item_id)
        conn.execute(f"UPDATE rede_credenciada SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}

@app.delete("/api/superadmin/catalogo/rede/{item_id}")
def deletar_rede_item(item_id: int, admin=Depends(require_superadmin)):
    conn = get_connection()
    row = conn.execute("SELECT nome FROM rede_credenciada WHERE id = ?", (item_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Item de rede não encontrado")
    conn.execute("DELETE FROM rede_credenciada WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    log_action(admin["sub"], "deletar_rede_item", f"Rede item={row['nome']} removido")
    return {"ok": True}

@app.patch("/api/superadmin/catalogo/operadoras/{op_id}/rede-meta")
def atualizar_rede_meta(op_id: int, body: RedeMetaRequest, admin=Depends(require_superadmin)):
    conn = get_connection()
    if not conn.execute("SELECT id FROM operadoras WHERE id = ?", (op_id,)).fetchone():
        conn.close()
        raise HTTPException(404, "Operadora não encontrada")
    updates, params = [], []
    if body.rede_adm is not None:
        updates.append("rede_adm = ?"); params.append(body.rede_adm)
    if body.rede_rodape is not None:
        updates.append("rede_rodape = ?"); params.append(body.rede_rodape)
    if updates:
        params.append(op_id)
        conn.execute(f"UPDATE operadoras SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}


# ── Superadmin: Importar catálogo em lote (dados.js → DB) ─────────────────────

@app.post("/api/superadmin/catalogo/importar")
async def importar_catalogo(request: Request, admin=Depends(require_superadmin)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "JSON inválido no corpo da requisição")
    operadoras = body.get("operadoras") or []
    planos     = body.get("planos")     or []
    if not isinstance(operadoras, list) or not isinstance(planos, list):
        raise HTTPException(400, "Campos 'operadoras' e 'planos' devem ser listas")
    conn = get_connection()
    ops_novas = 0
    planos_novos = 0
    for i, op in enumerate(operadoras):
        if not isinstance(op, dict):
            continue
        chave = str(op.get("chave") or "").strip()
        if not chave:
            continue
        if not conn.execute("SELECT id FROM operadoras WHERE chave = ?", (chave,)).fetchone():
            conn.execute(
                "INSERT INTO operadoras (chave, nome, info, ordem) VALUES (?, ?, ?, ?)",
                (chave, str(op.get("nome","") or ""), str(op.get("info","") or ""), int(op.get("ordem", i+1) or 0)),
            )
            ops_novas += 1
    conn.commit()
    ops_map = {r["chave"]: r["id"] for r in conn.execute("SELECT id, chave FROM operadoras").fetchall()}
    for i, pl in enumerate(planos):
        if not isinstance(pl, dict):
            continue
        codigo   = str(pl.get("codigo")   or "").strip()
        op_chave = str(pl.get("op_chave") or "").strip()
        if not codigo or not op_chave:
            continue
        op_id = ops_map.get(op_chave)
        if not op_id:
            continue
        if not conn.execute("SELECT id FROM planos WHERE codigo = ?", (codigo,)).fetchone():
            precos = pl.get("precos") or []
            vig_val = pl.get("vig")
            try:
                vig_int = int(vig_val) if vig_val is not None else None
            except (ValueError, TypeError):
                vig_int = None
            conn.execute(
                "INSERT INTO planos (codigo, operadora_id, nome, acomodacao, tipo, faixa_vidas, moderador, mes_vigencia, precos, ordem) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (codigo, op_id, str(pl.get("nome","") or ""), str(pl.get("aco","enf") or "enf"),
                 pl.get("tipo") or None, pl.get("fvidas") or None,
                 pl.get("mod") or None, vig_int,
                 json.dumps(precos), int(pl.get("ordem", i+1) or 0)),
            )
            planos_novos += 1
    conn.commit()
    conn.close()
    log_action(admin["sub"], "importar_catalogo", f"{ops_novas} operadoras e {planos_novos} planos importados")
    return {"ok": True, "ops_novas": ops_novas, "planos_novos": planos_novos}


@app.post("/api/superadmin/catalogo/importar-rede")
async def importar_rede(request: Request, admin=Depends(require_superadmin)):
    try:
        rede_data = await request.json()
    except Exception:
        raise HTTPException(400, "JSON inválido no corpo da requisição")
    if not isinstance(rede_data, dict):
        raise HTTPException(400, "'rede_data' deve ser um objeto")
    conn = get_connection()
    ops_map = {r["chave"]: r["id"] for r in conn.execute("SELECT id, chave FROM operadoras").fetchall()}
    itens_novos = 0
    metas_atualizadas = 0
    for op_chave, rd in rede_data.items():
        if not isinstance(rd, dict):
            continue
        op_id = ops_map.get(op_chave)
        if not op_id:
            continue
        # Atualiza meta (adm / rodape)
        rede_adm    = rd.get("adm")    or None
        rede_rodape = rd.get("rodape") or None
        if rede_adm or rede_rodape:
            conn.execute(
                "UPDATE operadoras SET rede_adm = ?, rede_rodape = ? WHERE id = ?",
                (rede_adm, rede_rodape, op_id)
            )
            metas_atualizadas += 1
        # Insere itens por grupo
        grupos = rd.get("grupos") or []
        for g_idx, grupo in enumerate(grupos):
            if not isinstance(grupo, dict):
                continue
            titulo = str(grupo.get("titulo") or "")
            itens  = grupo.get("itens") or []
            for i_idx, item in enumerate(itens):
                if not isinstance(item, dict):
                    continue
                nome = str(item.get("nome") or "").strip()
                if not nome:
                    continue
                # Não duplica: mesmo nome + grupo + operadora_id
                existe = conn.execute(
                    "SELECT id FROM rede_credenciada WHERE operadora_id = ? AND grupo = ? AND nome = ?",
                    (op_id, titulo, nome)
                ).fetchone()
                if existe:
                    continue
                tags     = item.get("tags")     or None
                tag_extra = item.get("tagExtra") or None
                conn.execute(
                    """INSERT INTO rede_credenciada
                       (operadora_id, grupo, grupo_ordem, nome, local, tags, obs, tag_extra, ordem, ativo)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (
                        op_id, titulo, g_idx, nome,
                        item.get("local") or None,
                        json.dumps(tags)      if tags      else None,
                        item.get("obs")  or None,
                        json.dumps(tag_extra) if tag_extra else None,
                        i_idx,
                    )
                )
                itens_novos += 1
    conn.commit()
    conn.close()
    log_action(admin["sub"], "importar_rede", f"{itens_novos} itens e {metas_atualizadas} metas importados")
    return {"ok": True, "itens_novos": itens_novos, "metas_atualizadas": metas_atualizadas}


# ── CRM: Clientes ─────────────────────────────────────────────────────────────

def _check_cliente_acesso(cliente, user, write=False):
    """Garante que o usuário tem acesso ao cliente. Lança 403 se não tiver.

    write=False (leitura): cliente compartilhado é visível para colegas da
    mesma corretora. write=True (escrita): apenas dono, admin da mesma
    corretora ou superadmin — compartilhamento NÃO dá direito de escrita.
    """
    role = user.get("role")
    if role == "superadmin":
        return
    if role == "admin":
        if cliente["corretora_id"] != user.get("corretora_id"):
            raise HTTPException(403, "Sem permissão para acessar este cliente")
        return
    if cliente["corretor_id"] == user.get("id"):
        return
    if (not write and cliente.get("compartilhado") == 1
            and cliente["corretora_id"] == user.get("corretora_id")):
        return
    if write:
        raise HTTPException(403, "Cliente compartilhado é somente leitura — apenas o dono pode editar")
    raise HTTPException(403, "Sem permissão para acessar este cliente")


@app.get("/api/clientes")
def listar_clientes(view: Optional[str] = None, q: Optional[str] = None, user=Depends(require_corretor)):
    conn = get_connection()
    role = user.get("role")
    if q is not None:
        like = f"%{q}%"
        sq = """
            SELECT c.id, c.nome, c.empresa,
                COALESCE((SELECT estagio FROM oportunidades WHERE cliente_id = c.id ORDER BY criado_em DESC LIMIT 1), 'lead') AS estagio_atual
            FROM clientes c WHERE c.ativo = 1
        """
        if role == "superadmin":
            rows = conn.execute(sq + "AND (c.nome LIKE ? OR c.empresa LIKE ?) ORDER BY c.nome LIMIT 20", (like, like)).fetchall()
        elif role == "admin":
            rows = conn.execute(sq + "AND c.corretora_id = ? AND (c.nome LIKE ? OR c.empresa LIKE ?) ORDER BY c.nome LIMIT 20", (user.get("corretora_id"), like, like)).fetchall()
        else:
            rows = conn.execute(sq + "AND c.corretor_id = ? AND (c.nome LIKE ? OR c.empresa LIKE ?) ORDER BY c.nome LIMIT 20", (user.get("id"), like, like)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    base = """
        SELECT c.*,
            (SELECT MAX(criado_em) FROM interacoes WHERE cliente_id = c.id) AS ultima_interacao_em,
            COALESCE((SELECT estagio FROM oportunidades WHERE cliente_id = c.id ORDER BY criado_em DESC LIMIT 1), 'lead') AS estagio_atual,
            (SELECT id FROM oportunidades WHERE cliente_id = c.id ORDER BY criado_em DESC LIMIT 1) AS oportunidade_id,
            (SELECT nome FROM users WHERE id = c.corretor_id) AS corretor_nome
        FROM clientes c
    """
    if view == "empresa":
        rows = conn.execute(
            base + "WHERE c.corretora_id = ? AND c.compartilhado = 1 AND c.ativo = 1 ORDER BY c.criado_em DESC",
            (user.get("corretora_id"),),
        ).fetchall()
    elif role == "superadmin":
        rows = conn.execute(base + "WHERE c.ativo = 1 ORDER BY c.criado_em DESC").fetchall()
    elif role == "admin":
        rows = conn.execute(
            base + "WHERE c.corretora_id = ? AND c.ativo = 1 ORDER BY c.criado_em DESC",
            (user.get("corretora_id"),),
        ).fetchall()
    else:
        rows = conn.execute(
            base + "WHERE c.corretor_id = ? AND c.ativo = 1 ORDER BY c.criado_em DESC",
            (user.get("id"),),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/clientes")
def criar_cliente(body: ClienteRequest, user=Depends(require_corretor)):
    conn = get_connection()
    row = insert_returning(
        conn,
        """INSERT INTO clientes
           (nome, empresa, cnpj, telefone, email, n_vidas_estimado, segmento, origem, corretor_id, corretora_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            body.nome.strip(), body.empresa, body.cnpj, body.telefone,
            body.email, body.n_vidas_estimado, body.segmento, body.origem,
            user.get("id"), user.get("corretora_id"),
        ),
        "clientes",
    )
    conn.close()
    log_action(user["sub"], "criar_cliente", f"Cliente: {body.nome}", usuario_id=user.get("id"))
    return dict(row)


@app.get("/api/clientes/{cliente_id}")
def obter_cliente(cliente_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Cliente não encontrado")
    cliente = dict(row)
    _check_cliente_acesso(cliente, user)
    return cliente


@app.patch("/api/clientes/{cliente_id}")
def atualizar_cliente(cliente_id: int, body: UpdateClienteRequest, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user, write=True)
    except HTTPException:
        conn.close()
        raise
    updates, params = [], []
    for field in ("nome", "empresa", "cnpj", "telefone", "email", "n_vidas_estimado", "segmento", "origem", "ativo", "compartilhado", "plano_atual", "operadora_atual"):
        val = getattr(body, field)
        if val is not None:
            updates.append(f"{field} = ?")
            params.append(val.strip() if isinstance(val, str) else val)
    if updates:
        updates.append("atualizado_em = ?")
        params.append(datetime.utcnow().isoformat() + 'Z')
        params.append(cliente_id)
        conn.execute(f"UPDATE clientes SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/clientes/{cliente_id}")
def desativar_cliente(cliente_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user, write=True)
    except HTTPException:
        conn.close()
        raise
    conn.execute(
        "UPDATE clientes SET ativo = 0, atualizado_em = ? WHERE id = ?",
        (datetime.utcnow().isoformat() + 'Z', cliente_id),
    )
    conn.commit()
    conn.close()
    log_action(user["sub"], "desativar_cliente", f"Cliente {cliente_id}", usuario_id=user.get("id"))
    return {"ok": True}


# ── CRM: Oportunidades ─────────────────────────────────────────────────────────

@app.get("/api/clientes/{cliente_id}/oportunidades")
def listar_oportunidades(cliente_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user)
    except HTTPException:
        conn.close()
        raise
    rows = conn.execute(
        "SELECT * FROM oportunidades WHERE cliente_id = ? ORDER BY criado_em DESC",
        (cliente_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/clientes/{cliente_id}/oportunidades")
def criar_oportunidade(cliente_id: int, body: OportunidadeRequest, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user, write=True)
    except HTTPException:
        conn.close()
        raise
    novo = insert_returning(
        conn,
        """INSERT INTO oportunidades
           (cliente_id, estagio, valor_estimado, data_prevista_fechamento, motivo_perda, obs)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (cliente_id, body.estagio, body.valor_estimado, body.data_prevista_fechamento, body.motivo_perda, body.obs),
        "oportunidades",
    )
    conn.close()
    return dict(novo)


@app.patch("/api/oportunidades/{op_id}")
def atualizar_oportunidade(op_id: int, body: UpdateOportunidadeRequest, user=Depends(require_corretor)):
    conn = get_connection()
    op = conn.execute("SELECT * FROM oportunidades WHERE id = ?", (op_id,)).fetchone()
    if not op:
        conn.close()
        raise HTTPException(404, "Oportunidade não encontrada")
    cliente = conn.execute("SELECT * FROM clientes WHERE id = ?", (op["cliente_id"],)).fetchone()
    if not cliente:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(cliente), user, write=True)
    except HTTPException:
        conn.close()
        raise
    updates, params = [], []
    for field in ("estagio", "valor_estimado", "data_prevista_fechamento", "motivo_perda", "obs"):
        val = getattr(body, field)
        if val is not None:
            updates.append(f"{field} = ?")
            params.append(val)
    if updates:
        updates.append("atualizado_em = ?")
        params.append(datetime.utcnow().isoformat() + 'Z')
        params.append(op_id)
        conn.execute(f"UPDATE oportunidades SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return {"ok": True}


# ── CRM: Interações ────────────────────────────────────────────────────────────

@app.get("/api/clientes/{cliente_id}/interacoes")
def listar_interacoes(cliente_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user)
    except HTTPException:
        conn.close()
        raise
    rows = conn.execute(
        "SELECT * FROM interacoes WHERE cliente_id = ? ORDER BY criado_em DESC",
        (cliente_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/clientes/{cliente_id}/interacoes")
def criar_interacao(cliente_id: int, body: InteracaoRequest, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user, write=True)
    except HTTPException:
        conn.close()
        raise
    nova = insert_returning(
        conn,
        "INSERT INTO interacoes (cliente_id, tipo, descricao, usuario) VALUES (?, ?, ?, ?)",
        (cliente_id, body.tipo, body.descricao, user["sub"]),
        "interacoes",
    )
    conn.close()
    return dict(nova)


@app.delete("/api/interacoes/{interacao_id}")
def deletar_interacao(interacao_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    inter = conn.execute("SELECT * FROM interacoes WHERE id = ?", (interacao_id,)).fetchone()
    if not inter:
        conn.close()
        raise HTTPException(404, "Interação não encontrada")
    cliente = conn.execute("SELECT * FROM clientes WHERE id = ?", (inter["cliente_id"],)).fetchone()
    if not cliente:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(cliente), user, write=True)
    except HTTPException:
        conn.close()
        raise
    conn.execute("DELETE FROM interacoes WHERE id = ?", (interacao_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── CRM: Cotações vinculadas ao cliente ────────────────────────────────────────

@app.get("/api/clientes/{cliente_id}/cotacoes")
def listar_cotacoes_cliente(cliente_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM clientes WHERE id = ?", (cliente_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cliente não encontrado")
    try:
        _check_cliente_acesso(dict(row), user)
    except HTTPException:
        conn.close()
        raise
    rows = conn.execute(
        "SELECT id, usuario, cliente, dados, criado_em FROM cotacoes WHERE cliente_id = ? ORDER BY criado_em DESC",
        (cliente_id,),
    ).fetchall()
    conn.close()
    return [
        {"id": r["id"], "usuario": r["usuario"], "cliente": r["cliente"],
         "dados": json.loads(r["dados"]), "criado_em": r["criado_em"]}
        for r in rows
    ]


@app.delete("/api/cotacoes/{cotacao_id}")
def excluir_cotacao(cotacao_id: int, user=Depends(require_corretor)):
    conn = get_connection()
    row = conn.execute("SELECT * FROM cotacoes WHERE id = ?", (cotacao_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(404, "Cotação não encontrada")
    role = user.get("role")
    if role == "superadmin":
        pass
    elif role == "admin":
        if row["corretora_id"] != user.get("corretora_id"):
            conn.close()
            raise HTTPException(403, "Sem permissão para excluir cotação de outra corretora")
    elif row["usuario"] != user["sub"]:
        conn.close()
        raise HTTPException(403, "Sem permissão")
    conn.execute("DELETE FROM cotacoes WHERE id = ?", (cotacao_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── Redirects para caminhos antigos (raiz → app/) ─────────────────────────────

@app.get("/cotador-planos-saude.html")
async def _r_cotador():
    return RedirectResponse("/app/cotador-planos-saude.html", status_code=301)

@app.get("/sistema-saude-prime.html")
async def _r_sistema():
    return RedirectResponse("/app/sistema-saude-prime.html", status_code=301)

@app.get("/apresentacao-executiva.html")
async def _r_apresentacao():
    return RedirectResponse("/app/apresentacao-executiva.html", status_code=301)

@app.get("/dados.js")
async def _r_dados():
    return RedirectResponse("/app/dados.js", status_code=301)


# ── Static (deve ficar DEPOIS de todas as rotas /api) ─────────────────────────
app.mount("/", StaticFiles(directory=PROJECT_DIR, html=True), name="static")
