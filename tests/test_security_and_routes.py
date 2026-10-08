"""
Suíte de Testes Automatizados de Segurança e Rotas
Projeto Aplicado: Práticas de Mercado
Validação das Mitigações OWASP Top 10 e Fluxo de Autenticação
"""

import unittest
from src.main import app, USERS_DATABASE, ADMIN_USER, ADMIN_RAW_PASS

class TestSecurityAndRoutes(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_security_headers_present(self):
        """Validação OWASP A05: Injeção de Security Headers defensivos em todas as respostas."""
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")
        self.assertIn("Content-Security-Policy", response.headers)
        self.assertEqual(response.headers.get("Server"), "WebSecurity-Host")

    def test_broken_access_control_unauthenticated(self):
        """Validação OWASP A01: Acesso direto ao /dashboard sem login deve ser impedido."""
        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_invalid_login_credentials(self):
        """Validação OWASP A07: Resposta genérica contra enumeração de usuário em credenciais incorretas."""
        response = self.client.post("/login", data={
            "username": "usuario_inexistente",
            "password": "senha_incorreta_123"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Credenciais inválidas", response.get_data(as_text=True))

    def test_successful_login_and_access(self):
        """Validação do fluxo completo: Login bem-sucedido -> Acesso ao Dashboard."""
        response = self.client.post("/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_RAW_PASS
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Área Interna Protegida", response.get_data(as_text=True))
        self.assertIn(ADMIN_USER, response.get_data(as_text=True))

    def test_logout_invalidates_session(self):
        """Validação OWASP A01: Logout encerra a sessão e revoga acesso ao dashboard."""
        # 1. Realiza login
        self.client.post("/login", data={
            "username": ADMIN_USER,
            "password": ADMIN_RAW_PASS
        })
        
        # 2. Executa logout
        logout_resp = self.client.get("/logout", follow_redirects=True)
        self.assertEqual(logout_resp.status_code, 200)
        self.assertIn("Sessão finalizada com sucesso", logout_resp.get_data(as_text=True))

        # 3. Tenta acessar novamente o dashboard (deve falhar)
        dash_resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(dash_resp.status_code, 302)
        self.assertIn("/login", dash_resp.headers["Location"])

if __name__ == "__main__":
    unittest.main()
