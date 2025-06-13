from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.exceptions import TooManyRequests
import os
import re
import hashlib
import json

class HidanGuard:
    def __init__(self, app):
        self.app = app
        self.blocked_ips = set()
        self.failed_attempts = {}
        self.setup_honeypot()
        self.setup_middlewares()
        
    def setup_honeypot(self):
        self.HONEYPOT_FIELD = "honeypot_field"
        self.HONEYPOT_TRAP_MESSAGE = "Site protegido por HidanGuard! Acesso suspeito detectado."

    def setup_middlewares(self):
        @self.app.before_request
        def hidan_guard_middleware():
            if self.check_ip(request.remote_addr):
                return self.render_blocked_page(request.remote_addr, request.path)

        @self.app.after_request
        def hidan_guard_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            
            csp = (
                "default-src 'self'; "
                "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; "
                "font-src 'self' https://fonts.gstatic.com; "
                "script-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:;"
            )
            response.headers['Content-Security-Policy'] = csp
            return response

    def protect(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', '').lower()

            if self.check_ip(ip):
                abort(403, description="Seu IP foi bloqueado por HidanGuard!")

            if self.detect_exploit_attempts():
                return self.render_trap_page(ip, "Tentativa de exploração de vulnerabilidade")

            honeypot_result = self.check_honeypot()
            if honeypot_result:
                return honeypot_result

            for key, value in request.args.items():
                if self.check_sqli(value):
                    self.log_suspicious_activity(ip, "SQL Injection Attempt", f"Parameter: {key}")
                    self.block_ip(ip, "Tentativa de SQL Injection")
                    return self.render_trap_page(ip, "SQL Injection")

            for key, value in request.args.items():
                if re.search(r'<script>|javascript:', value, re.IGNORECASE):
                    self.log_suspicious_activity(ip, "XSS Attempt", f"Parameter: {key}")
                    self.block_ip(ip, "Tentativa de XSS")
                    return self.render_trap_page(ip, "XSS")

            bad_agents = ['sqlmap', 'nikto', 'wget', 'curl', 'hydra', 'metasploit']
            if any(bad in user_agent for bad in bad_agents):
                self.block_ip(ip, "User-Agent de ferramenta de ataque")
                return self.render_trap_page(ip, "Ferramenta de ataque detectada")

            return f(*args, **kwargs)
        return decorated_function

    def detect_exploit_attempts(self):
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '').lower()
        
        exploit_patterns = [
            (r'(\%27)|(\')|(\-\-)', "SQL Injection attempt"),
            (r'((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-))', "SQL Injection attempt"),
            (r'\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', "SQL Injection attempt"),
            (r'(eval\()', "Command Injection attempt"),
            (r'(union\s+select)', "SQL Injection attempt"),
            (r'(base64_decode\()', "PHP Code Injection attempt"),
            (r'(\.\.\/)', "Path Traversal attempt"),
            (r'(;\s*(sh|bash|cmd|powershell)\s*)', "Command Injection attempt"),
            (r'(<script>)', "XSS attempt"),
            (r'(document\.cookie)', "XSS attempt"),
            (r'(alert\()', "XSS attempt"),
            (r'(onerror=)', "XSS attempt"),
            (r'(javascript:)', "XSS attempt"),
            (r'(onload\s*=)', "XSS attempt"),
            (r'(onmouseover\s*=)', "XSS attempt")
        ]
        
        sources_to_check = []
        if request.query_string:
            sources_to_check.append(request.query_string.decode('utf-8', 'ignore'))
        if request.method == "POST":
            try:
                sources_to_check.append(request.get_data().decode('utf-8', 'ignore'))
            except:
                pass
        
        for source in sources_to_check:
            for pattern, attack_type in exploit_patterns:
                try:
                    if re.search(pattern, source, re.IGNORECASE):
                        self.block_ip(ip, attack_type)
                        self.log_suspicious_activity(ip, attack_type, f"Detectado em: {source[:100]}...")
                        return True
                except re.error:
                    self.app.logger.error(f"Erro na expressão regular: {pattern}")
                    continue
        
        suspicious_headers = {
            'User-Agent': ['sqlmap', 'nikto', 'wget', 'curl', 'hydra', 'metasploit'],
            'Accept': ['../', '\\', 'etc/passwd'],
            'Referer': ['<script>', 'javascript:']
        }
        
        for header, patterns in suspicious_headers.items():
            header_value = request.headers.get(header, '')
            for pattern in patterns:
                if pattern.lower() in header_value.lower():
                    self.block_ip(ip, f"Padrão suspeito no header {header}")
                    self.log_suspicious_activity(ip, "Header suspeito", f"Header {header} contém: {pattern}")
                    return True
        
        return False

    def check_honeypot(self):
        if self.HONEYPOT_FIELD in request.form and request.form[self.HONEYPOT_FIELD]:
            ip = request.remote_addr
            user_agent = request.headers.get('User-Agent', 'Desconhecido')
            self.log_suspicious_activity(ip, "Honeypot", f"User-Agent: {user_agent}")
            self.block_ip(ip, "Honeypot trigger")
            return self.render_trap_page(ip, "Honeypot trigger")

    def block_ip(self, ip, motivo):
        self.blocked_ips.add(ip)
        self.log_suspicious_activity(ip, "IP Bloqueado", f"Motivo: {motivo}")

    def check_ip(self, ip):
        return ip in self.blocked_ips

    def sanitize_input(self, input_str):
        if not input_str:
            return input_str
        sanitized = re.sub(r'<[^>]*>', '', str(input_str))
        sanitized = re.sub(r"[\;\-\-]", "", sanitized)
        return sanitized.strip()

    def check_sqli(self, input_str):
        sql_keywords = [
            'select', 'insert', 'update', 'delete', 'drop', 
            'truncate', 'create', 'alter', 'exec', 'xp_'
        ]
        input_str = input_str.lower()
        for keyword in sql_keywords:
            if keyword in input_str and not re.search(r'\b' + re.escape(keyword) + r'\b', input_str):
                return True
        return False

    def log_suspicious_activity(self, ip, action, details):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[HidanGuard] {timestamp} - IP: {ip} - Ação: {action} - Detalhes: {details}"
        self.app.logger.warning(log_entry)

    def render_trap_page(self, ip, attack_type):
        return render_template(
            'hidan_guard_trap.html',
            ip=ip,
            user_agent=request.headers.get('User-Agent', 'Desconhecido'),
            attack_type=attack_type
        ), 403

    def render_blocked_page(self, ip, path):
        return render_template(
            'hidan_guard_blocked.html',
            ip=ip,
            path=path
        ), 403

    def rate_limit_handler(self, e):
        ip = get_remote_address()
        self.log_suspicious_activity(ip, "Rate limit exceeded", f"Too many requests to {request.path}")
        return render_template('rate_limit_exceeded.html', ip=ip), 429
