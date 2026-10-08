"""
Projeto Aplicado: Práticas de Mercado
Módulo Principal de Aplicação Web (Flask)

Arquitetura: Secure by Design & Secure by Default
Mitigações OWASP Top 10 Ativas:
 - A01: Broken Access Control (Controle de acesso rigoroso & sessões protegidas)
 - A07: Identification and Authentication Failures (Hash com sal, anti-brute force, anti-enumeração)
 - A03: Injection & XSS (Escape contextual Jinja2 & sanitização de inputs)
 - A05: Security Misconfiguration (Cabeçalhos HTTP de segurança obrigatórios)
"""

import os
import secrets
import logging
from datetime import timedelta, datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    Response,
    abort
)
from werkzeug.security import generate_password_hash, check_password_hash

# Carregamento seguro de variáveis de ambiente
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configuração de Logging de Auditoria de Segurança
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SECURITY-AUDIT] %(message)s"
)
logger = logging.getLogger("ProjetoAplicado")

# Inicialização da Aplicação Flask
app = Flask(__name__, template_folder="templates", static_folder="static")

# ==============================================================================
# CONFIGURAÇÃO DE SEGURANÇA (OWASP A01 & A05: Secure Session & Configuration)
# ==============================================================================
# Chave Secreta para Assinatura Criptográfica de Sessões
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    logger.warning("FLASK_SECRET_KEY não definida no ambiente. Gerada chave efêmera segura para a sessão.")
app.secret_key = SECRET_KEY

# Configuração de Cookies de Sessão Seguros
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,     # Previne roubo de cookie via scripts maliciosos (XSS)
    SESSION_COOKIE_SAMESITE="Lax",    # Mitigação contra CSRF (Cross-Site Request Forgery)
    SESSION_COOKIE_SECURE=(os.getenv("COOKIE_SECURE", "false").lower() == "true"), # Exige HTTPS em produção
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60), # Expiração automática da sessão
    SESSION_COOKIE_NAME="__Host_SecSession" if os.getenv("COOKIE_SECURE", "false").lower() == "true" else "SecSession",
)

# ==============================================================================
# RATE LIMITING (OWASP A07: Proteção contra Força Bruta)
# ==============================================================================
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["300 per day", "60 per hour"],
        storage_uri="memory://",
    )
    RATE_LIMIT_AVAILABLE = True
except Exception as e:
    logger.warning(f"Flask-Limiter não inicializado: {e}. Executando com proteção base.")
    limiter = None
    RATE_LIMIT_AVAILABLE = False


# ==============================================================================
# REPOSITÓRIO SEGURO DE USUÁRIOS (Mock em Memória com Hash Criptográfico)
# Em conformidade com o escopo: sem obrigatoriedade de BD externo complexo
# ==============================================================================
ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_RAW_PASS = os.getenv("ADMIN_PASSWORD", "Admin@Sec2026!Projeto")

# As senhas NUNCA são salvas em texto puro. Armazenamos apenas o hash com sal (PBKDF2/Scrypt)
# OWASP A07: Identification and Authentication Failures
USERS_DATABASE = {
    ADMIN_USER: {
        "password_hash": generate_password_hash(ADMIN_RAW_PASS, method="pbkdf2:sha256"),
        "role": "administrador",
        "created_at": datetime.utcnow().isoformat()
    }
}


# ==============================================================================
# MIDDLEWARE & DECORATORS DE SEGURANÇA (OWASP A01: Broken Access Control)
# ==============================================================================
def login_required(f):
    """
    Decorator para restringir acesso a rotas internas.
    Previne Forced Browsing e falhas de controle de acesso (OWASP A01).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            logger.warning(f"Acesso não autorizado bloqueado na rota '{request.path}' vindo do IP {request.remote_addr}")
            flash("Acesso restrito. Faça autenticação para continuar.", "danger")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


@app.after_request
def apply_security_headers(response: Response):
    """
    Injeta cabeçalhos HTTP de segurança obrigatórios em todas as respostas.
    OWASP A05: Security Misconfiguration & Proteção em Camadas.
    """
    # Impede que o navegador interprete arquivos com MIME types incorretos
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Previne ataques de Clickjacking impedindo renderização em iframes
    response.headers["X-Frame-Options"] = "DENY"

    # Habilita filtro XSS nos navegadores legados
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Política estrita de envio do cabeçalho Referer
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # Content Security Policy (CSP): restringe origem de scripts, estilos e fontes
    csp_policy = (
        "default-src 'self'; "
        "font-src 'self' https://fonts.gstatic.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "script-src 'self';"
    )
    response.headers["Content-Security-Policy"] = csp_policy

    # Se estiver rodando em ambiente seguro (HTTPS), injeta HSTS (Strict-Transport-Security)
    if request.is_secure or os.getenv("COOKIE_SECURE", "false").lower() == "true":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Oculta informações do servidor de aplicação
    response.headers["Server"] = "WebSecurity-Host"

    return response


# ==============================================================================
# ROTAS DA APLICAÇÃO (Eixo 3: Login, Página Interna e Logout Funcional)
# ==============================================================================

@app.route("/")
def index():
    """Rota raiz: redireciona para dashboard se autenticado, caso contrário para login."""
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Tela e Ação de Login.
    Mitigações:
     - Rate Limiting contra força bruta (5 tentativas / minuto)
     - Mensagem de erro genérica contra enumeração de usuários (OWASP A07)
     - Validação e higienização estrita de inputs (OWASP A03)
    """
    if request.method == "POST":
        # Extração e sanitização básica de parâmetros
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Validação de preenchimento mínimo
        if not username or not password or len(username) > 64 or len(password) > 128:
            logger.warning(f"Tentativa de login com payload inválido ou excessivo do IP {request.remote_addr}")
            flash("Credenciais inválidas. Verifique usuário e senha.", "danger")
            return render_template("login.html"), 401

        user_record = USERS_DATABASE.get(username)

        # OWASP A07: Resposta de timing constante e mensagem genérica para evitar enumeração
        # Mesmo se o usuário não existir, executamos check_password_hash contra hash dummy
        dummy_hash = "pbkdf2:sha256:600000$dummy$0000000000000000000000000000000000000000000000000000000000000000"
        target_hash = user_record["password_hash"] if user_record else dummy_hash
        password_valid = check_password_hash(target_hash, password)

        if user_record and password_valid:
            # Login bem-sucedido: regenerar sessão para prevenir Session Fixation (OWASP A07)
            session.clear()
            session["user"] = username
            session["role"] = user_record.get("role", "usuario")
            session["login_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

            logger.info(f"Usuário '{username}' autenticado com sucesso via IP {request.remote_addr}")
            return redirect(url_for("dashboard"))
        else:
            logger.warning(f"Falha de autenticação para usuário '{username}' via IP {request.remote_addr}")
            # Mensagem deliberadamente ambígua para proteção anti-enumeração
            flash("Credenciais inválidas. Verifique os dados e tente novamente.", "danger")
            return render_template("login.html"), 401

    # Método GET: se já estiver autenticado, vai para o dashboard
    if "user" in session:
        return redirect(url_for("dashboard"))

    return render_template("login.html")


# Aplica rate limiting se disponível
if limiter:
    login = limiter.limit("5 per minute")(login)


@app.route("/dashboard")
@login_required
def dashboard():
    """
    Página interna restrita da aplicação.
    Acessível exclusivamente após autenticação comprovada (OWASP A01).
    """
    username = session.get("user", "Usuário")
    return render_template("dashboard.html", username=username)


@app.route("/logout", methods=["GET", "POST"])
def logout():
    """
    Botão e Rota de Logout Funcional.
    Invalida completamente a sessão e limpa os dados do cliente (OWASP A01).
    """
    user = session.get("user")
    if user:
        logger.info(f"Sessão encerrada com sucesso para o usuário '{user}' (IP {request.remote_addr})")
    
    # Destruição atômica da sessão
    session.clear()
    flash("Sessão finalizada com sucesso. Até logo!", "info")
    return redirect(url_for("login"))


# ==============================================================================
# TRATAMENTO SEGURO DE ERROS (OWASP A05: Evita vazamento de stack traces)
# ==============================================================================
@app.errorhandler(404)
def handle_404(e):
    return render_template("login.html"), 404

@app.errorhandler(429)
def handle_429(e):
    logger.warning(f"Limite de requisições excedido (Rate Limit) do IP {request.remote_addr}")
    flash("Muitas tentativas em pouco tempo. Por motivos de segurança, aguarde um minuto.", "danger")
    return render_template("login.html"), 429

@app.errorhandler(500)
def handle_500(e):
    logger.error(f"Erro interno de servidor capturado: {e}")
    flash("Ocorreu um erro interno temporário. Tente novamente mais tarde.", "danger")
    return render_template("login.html"), 500


# Ponto de Entrada para Execução Local de Desenvolvimento
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("DEBUG", "false").lower() == "true"
    print(f"\n[+] Servidor do Projeto Aplicado iniciado em: http://127.0.0.1:{port}")
    print(f"[+] Credenciais padrão: {ADMIN_USER} / {ADMIN_RAW_PASS}")
    print("[+] Pressione Ctrl+C para encerrar.\n")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
