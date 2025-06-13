# 🛡️ HidanGuard

<p align="center">
   <img src="https://i.postimg.cc/m2pYdRFY/Hidan-Guard.png" width="400" height="400" alt="Logo"/> 
</p>

**HidanGuard** é um sistema de segurança inteligente para aplicações web desenvolvido em **Python/Flask**, inspirado no personagem Hidan (Naruto), voltado para detectar, bloquear e enganar possíveis invasores com armadilhas visuais, detecção de padrões maliciosos e limitação de requisições.

> 🚨 Proteção visual, funcional e estratégica para sua aplicação Flask.

---

## 🔥 Funcionalidades

- 🔍 **Detecção de Ataques**: SQL Injection, XSS, acesso malicioso por `User-Agent`, etc.
- 🎭 **Honeypot Visual (Armadilha)**: exibe página personalizada para enganar e registrar atacantes.
- ⛔ **Bloqueio de IPs**: temporário ou permanente com exibição de tempo restante (countdown).
- 🧠 **Headers de Segurança**: inclui CSP, X-Frame-Options, X-XSS-Protection, entre outros.
- 🕒 **Rate Limiting**: limite de tentativas por IP, com feedback visual ao usuário.
- 💾 **Logs de Segurança**: ataques registrados com IP, tipo, detalhes e data.
- 🧠 **Sistema de Blacklist** atacantes são bloqueados por meio do seu IP.
- ⚡️ **Templates Temáticos** com background, animações e estilo baseado em Hidan (Akatsuki).

---

## 💻 Requisitos

- Python 3.9+
- Flask
- Flask-Limiter
- MySql ou outro banco (ajustável)

---

## 🚀 Instalação

1. Clone este repositório:
   ```bash
   git clone https://github.com/Lucas-Rosada/HidanGuard
   cd HidanGuard
   ```

2. Crie e ative um ambiente virtual:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows
   ```

3. Configure variáveis de ambiente no arquivo `.env` (exemplo incluído).

4. Execute a aplicação:
   ```bash
   python app.py
   ```

---

## 🧪 Estrutura dos Templates

- `hidan_guard_trap.html` → Página de armadilha (honeypot visual) e exibida apos o Bot cair na armadilha
- `hidan_guard_blocked.html` → Página de IP bloqueado
- `rate_limit_exceed.html` → Excesso de tentativas

Todos com contagem regressiva e exibição de IP.

---

## 📂 Exemplo de Registro de Ataque

```json
{
  "ip_ataque": "192.168.0.100",
  "data_ataque": "2025-06-12T12:34:56",
  "tipo_ataque": "SQL Injection",
  "detalhes": "Payload: ' OR 1=1 --",
  "bloqueado": true
}
```

---

## 🧠 Inspiração

Baseado no personagem **Hidan** (Naruto) – imortal e sádico, representando o bloqueio implacável contra invasores.

---

## 🙋‍♂️ Contato

Desenvolvido por **Lucas**  
📧 GitHub: [github.com/Lucas-Rosada](https://github.com/Lucas-Rosada)

---

> “A armadilha foi armada....” – *HidanGuard*
