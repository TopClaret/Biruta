from flask import Flask, render_template, jsonify, request, g, Response
import subprocess
print("DEBUG: app.py está sendo executado!")
import os
import threading
import queue
from collections import deque
import uuid
import json
import wmi
import time
import logging
import pythoncom
import socket
import win32com.client
import pywintypes
from datetime import datetime, timezone
from dotenv import load_dotenv
from security_manager import SecurityManager

app = Flask(__name__)
load_dotenv()

# Configuração do Logging
LOG_FILE = os.path.join(os.path.dirname(__file__), "spooler_restart_log.log")
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def log_action(action_type, target, status, message):
    log_entry = f"Tipo: {action_type}, Alvo: {target}, Status: {status}, Mensagem: {message}"
    logging.info(log_entry)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}

def build_csp(nonce=None):
    if nonce:
        return " ".join([
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            f"style-src 'self' 'nonce-{nonce}'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "font-src 'self' data:",
            "base-uri 'self'",
            "form-action 'self'",
        ])
    else:
        return " ".join([
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "connect-src 'self'",
            "font-src 'self' data:",
            "base-uri 'self'",
            "form-action 'self'",
        ])

@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = build_csp(getattr(g, 'csp_nonce', None))
    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    for k, v in SECURITY_HEADERS.items():
        resp.headers[k] = v
    return resp

@app.before_request
def enforce_request_security():
    if request.method in ("POST", "PUT", "PATCH") and not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403

RATE_STORE = {}

def rate_limit(key, limit=60, window_sec=60):
    return SECURITY.rate_limit(key, limit, window_sec, RATE_STORE)

def client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')

def validate_remote_host(host):
    return SECURITY.validate_remote_host(host)

def validate_username(user):
    return SECURITY.validate_username(user)

def validate_password(pwd):
    return SECURITY.validate_password(pwd)

def require_csrf():
    cookie_token = request.cookies.get('XSRF-TOKEN')
    header_token = request.headers.get('X-CSRF-Token')
    ok = SECURITY.validate_csrf(cookie_token, header_token)
    if not ok:
        log_action("Segurança", client_ip(), "Falha", "CSRF token inválido ou ausente")
    return ok

RESTART_LOCKS = {}
SERVICE_LOCKS = {}
STATUS_SUBSCRIBERS = set()
STATUS_HISTORY = deque(maxlen=1000)
CURRENT_STATUS = {}
MONITOR_THREAD = None
SESSIONS = {}
SESSION_MONITORS = {}
SECURITY = SecurityManager()

def acquire_lock(lock_dict, key):
    if lock_dict.get(key):
        return False
    lock_dict[key] = True
    return True

def release_lock(lock_dict, key):
    if key in lock_dict:
        del lock_dict[key]
ACTIVE_WMI_CONNECTIONS = []
def track_wmi_conn(conn):
    try:
        ACTIVE_WMI_CONNECTIONS.append(conn)
    except Exception:
        pass
def release_all_wmi_connections():
    try:
        for i in range(len(ACTIVE_WMI_CONNECTIONS)):
            ACTIVE_WMI_CONNECTIONS[i] = None
        ACTIVE_WMI_CONNECTIONS.clear()
    except Exception:
        pass
    try:
        pythoncom.CoUninitialize()
    except Exception:
        pass

def is_local_host(host):
    try:
        if not host:
            return True
        h = host.strip().lower()
        if h in ("127.0.0.1", "localhost", "::1"):
            return True
        local_names = {
            (os.environ.get("COMPUTERNAME", "") or "").strip().lower(),
            socket.gethostname().strip().lower(),
            socket.getfqdn().strip().lower(),
        }
        if h in local_names:
            return True
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            if h == (local_ip or "").strip().lower():
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False

def connect_wmi(remote_host, user, password, domain=None):
    if is_local_host(remote_host):
        conn = wmi.WMI(namespace='root\\cimv2')
        track_wmi_conn(conn)
        return conn
    locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
    locator.Security_.AuthenticationLevel = 6
    _user = user or ""
    _domain = domain
    if not _domain and isinstance(_user, str) and "\\" in _user:
        parts = _user.split("\\", 1)
        if len(parts) == 2 and parts[0] and parts[1]:
            _domain, _user = parts[0], parts[1]
    # Primeiro tenta com a assinatura básica (sem authority)
    try:
        services = locator.ConnectServer(remote_host, "root\\cimv2", _user, password)
    except pywintypes.com_error as ce:
        # Se houver domínio, tenta novamente com authority NTLM em caixa alta
        if _domain:
            authority = f"NTLMDOMAIN:{_domain}"
            services = locator.ConnectServer(remote_host, "root\\cimv2", _user, password, None, authority)
        else:
            raise ce
    services.Security_.ImpersonationLevel = 3
    conn = wmi.WMI(wmi=services)
    track_wmi_conn(conn)
    return conn

def format_wmi_error(e):
    s = str(e)
    if ("-2147024891" in s) or ("Acesso negado" in s) or ("Access is denied" in s):
        return "Acesso negado via WMI. Verifique permissões DCOM/WMI no host remoto, regra de firewall WMI-In, e se o usuário possui 'Remote Enable' em root\\cimv2. Se usar conta local admin, avalie 'LocalAccountTokenFilterPolicy=1'."
    if ("0x80041003" in s) or ("WBEM_E_ACCESS_DENIED" in s):
        return "Acesso negado na consulta WMI (WBEM_E_ACCESS_DENIED). Conceda 'Remote Enable' em root\\cimv2 e revise permissões DCOM/WMI e firewall WMI-In."
    if ("-2147023174" in s) or ("RPC server is unavailable" in s):
        return "Servidor RPC indisponível. Verifique conectividade de rede e porta 135, além das regras de firewall (WMI/DCOM)."
    return s

# Define o caminho para o script PowerShell
# Certifique-se de que este caminho está correto no seu sistema
POWERSHELL_RESTART_SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "restart_spooler.ps1")

# Lista de serviços padrão para reinício sequencial
DEFAULT_SERVICES_TO_RESTART = [
    "nddPrint.Agent.Watcher",
    "nddPrint.Agent.Sender",
    "nddPrint.Agent.Listener",
    "nddPrint.Agent.HttpServer",
    "nddPrint.Agent.Guardian",
    "DCSServer",
    "Spooler"
]
CRITICAL_SERVICES = {
    "Wininit", "Winlogon", "LSM", "SessionEnv", "TermService", "PlugPlay", "EventLog",
    "RpcSs", "SecurityHealthService", "WdiServiceHost", "Winmgmt", "LanmanServer",
    "LanmanWorkstation", "Power", "DcomLaunch", "ProfSvc", "TrustedInstaller", "msiserver"
}
def is_restartable_service(s):
    try:
        name = s.Name
        if not name or name in CRITICAL_SERVICES:
            return False
        if hasattr(s, "AcceptStop") and str(s.AcceptStop).lower() == "false":
            return False
        start_mode = getattr(s, "StartMode", "Unknown")
        if start_mode not in ("Auto", "Manual"):
            return False
        return True
    except Exception:
        return False

def _fetch_default_services_status_local():
    try:
        pythoncom.CoInitialize()
        conn = wmi.WMI(namespace='root\\cimv2')
        statuses = []
        for name in DEFAULT_SERVICES_TO_RESTART:
            try:
                svc = conn.Win32_Service(Name=name)
                if svc:
                    statuses.append({"name": name, "status": svc[0].State, "start_mode": svc[0].StartMode})
                else:
                    statuses.append({"name": name, "status": "Unknown", "start_mode": "Unknown"})
            except Exception:
                statuses.append({"name": name, "status": "Unknown", "start_mode": "Unknown"})
        return statuses
    except Exception:
        return []
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass

def broadcast_status_update(payload):
    for q in list(STATUS_SUBSCRIBERS):
        try:
            q.put_nowait(payload)
        except Exception:
            pass

def service_status_monitor_for(token, remote_host, auth_username, auth_password, domain=None, interval=0.5):
    q = SESSIONS[token]["queue"]
    current = {}
    try:
        while True:
            pythoncom.CoInitialize()
            try:
                conn = None
                if remote_host:
                    conn = connect_wmi(remote_host, auth_username, auth_password, domain)
                else:
                    conn = wmi.WMI(namespace='root\\cimv2')
                statuses = []
                for name in DEFAULT_SERVICES_TO_RESTART:
                    try:
                        svc = conn.Win32_Service(Name=name)
                        if svc:
                            statuses.append({"name": name, "status": svc[0].State, "start_mode": svc[0].StartMode})
                        else:
                            statuses.append({"name": name, "status": "Unknown", "start_mode": "Unknown"})
                    except Exception:
                        statuses.append({"name": name, "status": "Unknown", "start_mode": "Unknown"})
                ts = datetime.now(timezone.utc).isoformat()
                changed = []
                for s in statuses:
                    prev = current.get(s["name"]) if s else None
                    curr = s["status"]
                    if prev != curr:
                        current[s["name"]] = curr
                        STATUS_HISTORY.append({"service": s["name"], "from": prev, "to": curr, "ts": ts, "host": remote_host or "localhost"})
                        log_action("Status", remote_host or "localhost", "Mudança", f"{s['name']} {prev}->{curr}")
                        changed.append({"service": s["name"], "status": curr, "start_mode": s.get("start_mode"), "ts": ts})
                payload = {"type": "services_status", "changed": changed, "all": statuses, "ts": ts}
                try:
                    q.put_nowait(payload)
                except Exception:
                    pass
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
            if not SESSION_MONITORS[token]["running"]:
                break
            time.sleep(interval)
    except Exception as e:
        err = {"type": "error", "message": str(e), "ts": datetime.now(timezone.utc).isoformat()}
        try:
            q.put_nowait(err)
        except Exception:
            pass

def service_status_monitor():
    while True:
        statuses = _fetch_default_services_status_local()
        ts = datetime.now(timezone.utc).isoformat()
        changed = []
        for s in statuses:
            prev = CURRENT_STATUS.get(s["name"]) if s else None
            curr = s["status"]
            if prev != curr:
                CURRENT_STATUS[s["name"]] = curr
                STATUS_HISTORY.append({"service": s["name"], "from": prev, "to": curr, "ts": ts})
                log_action("Status", "localhost", "Mudança", f"{s['name']} {prev}->{curr}")
                changed.append({"service": s["name"], "status": curr, "start_mode": s.get("start_mode"), "ts": ts})
        if changed:
            broadcast_status_update({"type": "services_status", "changed": changed, "all": statuses, "ts": ts})
        time.sleep(0.5)


@app.route('/')
def index():
    """
    Rota principal que serve o arquivo HTML do frontend.
    """
    csp_nonce = os.urandom(16).hex()
    g.csp_nonce = csp_nonce
    resp = app.make_response(render_template('index.html', csp_nonce=csp_nonce))
    token = SECURITY.generate_csrf_token()
    try:
        is_secure = request.is_secure
    except Exception:
        is_secure = False
    resp.set_cookie('XSRF-TOKEN', token, samesite='Strict', secure=is_secure, httponly=False)
    return resp

@app.route('/events/services_status')
def events_services_status():
    def _gen():
        q = queue.Queue(maxsize=100)
        STATUS_SUBSCRIBERS.add(q)
        try:
            initial = {"type": "services_status", "changed": [], "all": _fetch_default_services_status_local(), "ts": datetime.now(timezone.utc).isoformat()}
            yield f"data: {json.dumps(initial)}\n\n"
            while True:
                data = q.get()
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            STATUS_SUBSCRIBERS.discard(q)
    return Response(_gen(), mimetype='text/event-stream')

@app.route('/start_service_monitor', methods=['POST'])
def start_service_monitor():
    ip = client_ip()
    key = f"rl_start_monitor:{ip}"
    if not rate_limit(key, limit=10, window_sec=60):
        log_action("SSE", ip, "Alerta", "Rate limit atingido em start_service_monitor")
        return jsonify({"status": "error", "message": "Limite de requisições atingido."}), 429
    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    domain = SECURITY.sanitize_string(data.get('domain'))
    auth_username = frontend_username
    auth_password = frontend_password
    domain = SECURITY.sanitize_string(data.get('domain'))
    if remote_host and not validate_remote_host(remote_host):
        return jsonify({"status": "error", "message": "IP/Host remoto inválido."}), 400
    if remote_host and (not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password)):
        return jsonify({"status": "error", "message": "Credenciais inválidas."}), 500

    token = SECURITY.generate_auth_token()
    q = queue.Queue(maxsize=200)
    SESSIONS[token] = {"queue": q, "host": remote_host}
    SESSION_MONITORS[token] = {"thread": None, "running": True}
    t = threading.Thread(target=service_status_monitor_for, args=(token, remote_host, auth_username, auth_password, domain, 0.5), daemon=True)
    SESSION_MONITORS[token]["thread"] = t
    t.start()
    log_action("SSE", remote_host or "localhost", "Iniciado", f"Monitor de serviços iniciado para token {token}")
    return jsonify({"status": "success", "token": token})

@app.route('/events/services_status_by_token')
def events_services_status_by_token():
    token = request.args.get('token')
    if not token or token not in SESSIONS:
        return Response("data: {}\n\n", mimetype='text/event-stream')
    q = SESSIONS[token]["queue"]
    def _gen():
        try:
            init_payload = {"type": "services_status", "changed": [], "all": [], "ts": datetime.now(timezone.utc).isoformat()}
            yield f"data: {json.dumps(init_payload)}\n\n"
            while True:
                data = q.get()
                yield f"data: {json.dumps(data)}\n\n"
        except GeneratorExit:
            try:
                SESSION_MONITORS[token]["running"] = False
                t = SESSION_MONITORS[token]["thread"]
                SESSIONS.pop(token, None)
                if t:
                    t.join(timeout=1)
                SESSION_MONITORS.pop(token, None)
            except Exception:
                pass
    return Response(_gen(), mimetype='text/event-stream')

def _get_single_service_status(service_name, remote_host, auth_username, auth_password, domain=None):
    try:
        pythoncom.CoInitialize()
        conn = None
        if remote_host:
            conn = connect_wmi(remote_host, auth_username, auth_password, domain)
        else:
            conn = wmi.WMI(namespace='root\\cimv2')

        wmi_service = conn.Win32_Service(Name=service_name)
        if wmi_service:
            return {"status": "success", "state": wmi_service[0].State, "start_mode": wmi_service[0].StartMode}
        else:
            return {"status": "error", "message": f"Serviço {service_name} não encontrado."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        pythoncom.CoUninitialize()

def _restart_single_service(service_name, remote_host, auth_username, auth_password, domain=None):
    target_info = remote_host if remote_host else "localhost"
    log_action("Reinício", target_info, "Iniciado", f"Iniciando processo de reinício para o serviço {service_name}.")

    try:
        pythoncom.CoInitialize() # Inicializa COM para WMI
        _u = auth_username
        _p = auth_password

        # 1. Obter status atual do serviço
        current_status_result = _get_single_service_status(service_name, remote_host, _u, _p, domain)
        if current_status_result["status"] == "error":
            message = f"Erro ao obter status inicial do serviço {service_name}: {current_status_result['message']}"
            log_action("Reinício", target_info, "Falha", message)
            return {"status": "error", "message": message}

        initial_state = current_status_result["state"]
        log_action("Reinício", target_info, "Verificação", f"Status inicial do serviço {service_name}: {initial_state}.")

        conn = None
        if remote_host:
            conn = connect_wmi(remote_host, _u, _p, domain)
        else:
            conn = wmi.WMI(namespace='root\\cimv2')
        
        services = conn.Win32_Service(Name=service_name)
        if not services:
            message = f"Serviço {service_name} não encontrado em {target_info}."
            log_action("Reinício", target_info, "Falha", message)
            return {"status": "error", "message": message}
        target_service = services[0]

        # 2. Parar o serviço se estiver em execução
        if initial_state == "Running":
            log_action("Reinício", target_info, "Em Andamento", f"Tentando parar o serviço {service_name}.")
            push_service_event(remote_host, service_name, "Stop Pending")
            stop_raw = target_service.StopService()
            stop_result = stop_raw[0] if isinstance(stop_raw, (tuple, list)) else stop_raw
            if stop_result != 0:
                message = f"Erro ao parar o serviço {service_name} em {target_info} (código de erro: {stop_result})"
                log_action("Reinício", target_info, "Falha", message)
                push_service_event(remote_host, service_name, "Error")
                return {"status": "error", "message": message}
            
            # Esperar até que o serviço esteja realmente parado
            for _ in range(10): # Tentar por até 10 segundos
                time.sleep(1)
                status_after_stop = _get_single_service_status(service_name, remote_host, _u, _p)
                if status_after_stop["status"] == "success" and status_after_stop["state"] == "Stopped":
                    log_action("Reinício", target_info, "Em Andamento", f"Serviço {service_name} parado com sucesso.")
                    push_service_event(remote_host, service_name, "Stopped")
                    break
            else:
                message = f"Serviço {service_name} não parou após a tentativa em {target_info}."
                log_action("Reinício", target_info, "Falha", message)
                push_service_event(remote_host, service_name, "Error")
                return {"status": "error", "message": message}
        elif initial_state == "Stopped":
            log_action("Reinício", target_info, "Informação", f"Serviço {service_name} já estava parado. Prosseguindo para iniciar.")
        else:
            log_action("Reinício", target_info, "Aviso", f"Serviço {service_name} em estado inesperado ({initial_state}). Tentando iniciar mesmo assim.")

        # 3. Iniciar o serviço
        log_action("Reinício", target_info, "Em Andamento", f"Tentando iniciar o serviço {service_name}.")
        push_service_event(remote_host, service_name, "Start Pending")
        start_raw = target_service.StartService()
        start_result = start_raw[0] if isinstance(start_raw, (tuple, list)) else start_raw
        if start_result != 0:
            message = f"Erro ao iniciar o serviço {service_name} em {target_info} (código de erro: {start_result})"
            log_action("Reinício", target_info, "Falha", message)
            push_service_event(remote_host, service_name, "Error")
            return {"status": "error", "message": message}

        # 4. Verificar status pós-início
        for _ in range(10): # Tentar por até 10 segundos
            time.sleep(1)
            status_after_start = _get_single_service_status(service_name, remote_host, _u, _p)
            if status_after_start["status"] == "success" and status_after_start["state"] == "Running":
                message = f"Serviço {service_name} reiniciado e em execução com sucesso em {target_info}!"
                log_action("Reinício", target_info, "Sucesso", message)
                push_service_event(remote_host, service_name, "Running")
                return {"status": "success", "message": message}
        else:
            message = f"Serviço {service_name} não iniciou após a tentativa em {target_info}. Estado final: {status_after_start.get('state', 'Desconhecido')}."
            log_action("Reinício", target_info, "Falha", message)
            push_service_event(remote_host, service_name, "Error")
            return {"status": "error", "message": message}

    except Exception as e:
        message = f"Erro inesperado ao reiniciar o serviço {service_name} em {target_info}. {format_wmi_error(e)}"
        log_action("Reinício", target_info, "Falha", message)
        print(f"DEBUG: Erro inesperado ao reiniciar o serviço {service_name}: {e}")
        return {"status": "error", "message": message}
    finally:
        pythoncom.CoUninitialize() # Finaliza COM para WMI

@app.route('/restart_service', methods=['POST'])
def restart_service():
    ip = client_ip()
    key = f"rl_restart_service:{ip}"
    if not rate_limit(key, limit=30, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em restart_service")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    
    service_name = data.get('service_name')
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    domain = SECURITY.sanitize_string(data.get('domain'))

    if not service_name:
        message = "Nome do serviço não fornecido para reinício."
        log_action("Reinício Serviço Único", remote_host if remote_host else "localhost", "Falha", message)
        return jsonify({"status": "error", "message": message}), 400

    auth_username = frontend_username
    auth_password = frontend_password

    if remote_host and (not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password) or not validate_remote_host(remote_host)):
        message = "Credenciais inválidas para acesso remoto. Informe usuário e senha no frontend."
        log_action("Reinício Serviço Único", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500

    target_info = remote_host if remote_host else "localhost"
    lock_key = f"{target_info}:{service_name}"
    if not acquire_lock(SERVICE_LOCKS, lock_key):
        message = f"Já existe um reinício em andamento para {service_name} em {target_info}."
        log_action("Reinício Serviço Único", target_info, "Aviso", message)
        return jsonify({"status": "error", "message": message}), 409

    log_action("Reinício Serviço Único", target_info, "Iniciado", f"Solicitado reinício do serviço {service_name}.")
    try:
        result = _restart_single_service(service_name, remote_host, auth_username, auth_password, domain)
    finally:
        release_lock(SERVICE_LOCKS, lock_key)
        auth_username = None
        auth_password = None
    status_code = 200 if result["status"] == "success" else 500
    log_action("Reinício Serviço Único", target_info, result["status"], result["message"])
    return jsonify(result), status_code

def push_service_event(host, name, status):
    ts = datetime.now(timezone.utc).isoformat()
    payload = {"type": "services_status", "changed": [{"service": name, "status": status, "ts": ts}], "all": [], "ts": ts}
    for q in list(STATUS_SUBSCRIBERS):
        try:
            q.put_nowait(payload)
        except Exception:
            pass
    for token, info in list(SESSIONS.items()):
        try:
            if (info.get("host") or "localhost") == (host or "localhost"):
                info["queue"].put_nowait(payload)
        except Exception:
            pass

@app.route('/restart_multiple_services', methods=['POST'])
def restart_multiple_services():
    ip = client_ip()
    key = f"rl_restart_multiple:{ip}"
    if not rate_limit(key, limit=15, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em restart_multiple_services")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    services_to_restart = data.get('service_names', DEFAULT_SERVICES_TO_RESTART)
    domain = SECURITY.sanitize_string(data.get('domain'))

    auth_username = frontend_username
    auth_password = frontend_password
    if remote_host and (not validate_remote_host(remote_host)):
        return jsonify({"status": "error", "message": "IP/Host remoto inválido."}), 400
    if remote_host and (not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password)):
        return jsonify({"status": "error", "message": "Credenciais inválidas."}), 500

    results = []
    target_info = remote_host if remote_host else "localhost"
    if not acquire_lock(RESTART_LOCKS, target_info):
        message = f"Já existe um reinício sequencial em andamento para {target_info}."
        log_action("Reinício Sequencial", target_info, "Aviso", message)
        return jsonify({"status": "error", "message": message}), 409
    log_action("Reinício Sequencial", target_info, "Iniciado", f"Iniciando reinício sequencial de {len(services_to_restart)} serviços.")

    try:
        for service_name in services_to_restart:
            log_action("Reinício Sequencial", target_info, "Em Andamento", f"Processando serviço: {service_name}")
            result = _restart_single_service(service_name, remote_host, auth_username, auth_password, domain)
            results.append({"service": service_name, "status": result["status"], "message": result["message"]})
            
            if result["status"] == "error":
                log_action("Reinício Sequencial", target_info, "Interrompido", f"Reinício sequencial interrompido devido a erro em {service_name}: {result['message']}")
                return jsonify({"status": "error", "message": f"Reinício sequencial interrompido. Erro ao reiniciar {service_name}.", "results": results}), 500
            
            log_action("Reinício Sequencial", target_info, "Sucesso Parcial", f"Serviço {service_name} processado com sucesso. Pausando antes do próximo.")
            time.sleep(5)
        
        log_action("Reinício Sequencial", target_info, "Sucesso", "Todos os serviços foram reiniciados sequencialmente com sucesso.")
        return jsonify({"status": "success", "message": "Todos os serviços foram reiniciados sequencialmente com sucesso.", "results": results})
    finally:
        release_lock(RESTART_LOCKS, target_info)
        auth_username = None
        auth_password = None

@app.route('/restart_all_services_once', methods=['POST'])
def restart_all_services_once():
    ip = client_ip()
    key = f"rl_restart_all:{ip}"
    if not rate_limit(key, limit=1, window_sec=60):
        log_action("Reinício Total", ip, "Alerta", "Rate limit atingido em restart_all_services_once")
        return jsonify({"status": "error", "message": "Operação já executada recentemente."}), 429
    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    auth_username = frontend_username
    auth_password = frontend_password
    target_info = remote_host if remote_host else "localhost"
    if remote_host and not validate_remote_host(remote_host):
        return jsonify({"status": "error", "message": "IP/Host remoto inválido."}), 400
    if remote_host and (not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password)):
        return jsonify({"status": "error", "message": "Credenciais inválidas."}), 500

    if not acquire_lock(RESTART_LOCKS, target_info):
        message = f"Já existe um reinício sequencial em andamento para {target_info}."
        log_action("Reinício Total", target_info, "Aviso", message)
        return jsonify({"status": "error", "message": message}), 409

    results = []
    try:
        pythoncom.CoInitialize()
        log_action("Reinício Total", target_info, "Iniciado", "Listando serviços e reiniciando uma vez.")
        if remote_host:
            try:
                conn = connect_wmi(remote_host, auth_username, auth_password, data.get('domain'))
            except pywintypes.com_error as ce:
                raise ce
            except Exception:
                conn = wmi.WMI(computer=remote_host, user=auth_username, password=auth_password, namespace='root\\cimv2')
        else:
            conn = wmi.WMI(namespace='root\\cimv2')

        target_services = []
        for name in DEFAULT_SERVICES_TO_RESTART:
            try:
                svc_list = conn.Win32_Service(Name=name)
                if svc_list and is_restartable_service(svc_list[0]):
                    target_services.append(name)
                else:
                    log_action("Reinício Total", target_info, "Aviso", f"Serviço {name} não reiniciável ou não encontrado.")
            except Exception as e:
                log_action("Reinício Total", target_info, "Aviso", f"Erro ao avaliar {name}: {e}")

        for name in target_services:
            res = _restart_single_service(name, remote_host, auth_username, auth_password, data.get('domain'))
            results.append({"service": name, "status": res["status"], "message": res["message"]})
            if res["status"] == "error":
                log_action("Reinício Total", target_info, "Interrompido", f"Falha em {name}: {res['message']}")
                return jsonify({"status": "error", "message": f"Interrompido em {name}", "results": results}), 500

        release_all_wmi_connections()
        log_action("Reinício Total", target_info, "Sucesso", "Conexões WMI encerradas após reinício.")
        return jsonify({"status": "success", "message": "Serviços reiniciados uma vez e conexões WMI encerradas.", "results": results})
    except Exception as e:
        message = f"Erro em reinício total para {target_info}. {format_wmi_error(e)}"
        log_action("Reinício Total", target_info, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500
    finally:
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        release_lock(RESTART_LOCKS, target_info)
        auth_username = None
        auth_password = None


@app.route('/list_printers', methods=['POST'])
def list_printers():
    ip = client_ip()
    key = f"rl_list_printers:{ip}"
    if not rate_limit(key, limit=30, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em list_printers")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    print("DEBUG: Endpoint /list_printers foi acessado.")
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')

    auth_username = frontend_username
    auth_password = frontend_password

    if not remote_host or not validate_remote_host(remote_host):
        return jsonify({"status": "error", "message": "Nome do host ou IP remoto não fornecido."}), 400

    if not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password):
        message = "Credenciais inválidas. Informe usuário e senha no frontend."
        log_action("Listar Impressoras Remoto", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500

    response_data = None
    status_code = 200 # Default to success

    try:
        pythoncom.CoInitialize()
        log_action("Listar Impressoras Remoto", remote_host, "Iniciado", "Tentando conectar e listar impressoras via WMI.")
        print(f"DEBUG: Iniciando conexão WMI para listar impressoras em {remote_host}")
        conn = None
        try:
            conn = connect_wmi(remote_host, auth_username, auth_password, data.get('domain'))
        except pywintypes.com_error as ce:
            raise ce
        except Exception:
            conn = wmi.WMI(computer=remote_host, user=auth_username, password=auth_password, namespace='root\\cimv2')
        
        printers = []
        printer_job_counts = {}
        for job in conn.Win32_PrintJob():
            # O nome da impressora no Win32_PrintJob é geralmente no formato "PrinterName, JobID"
            # Precisamos extrair apenas o nome da impressora
            printer_name_from_job = job.Name.split(',')[0].strip()
            printer_job_counts[printer_name_from_job] = printer_job_counts.get(printer_name_from_job, 0) + 1

        print(f"DEBUG: Tentando iterar sobre Win32_Printer para {remote_host}")
        for printer in conn.Win32_Printer():
            printer_name = printer.Name
            job_count = printer_job_counts.get(printer_name, 0)
            printers.append({
                "Name": printer.Name,
                "Location": printer.Location,
                "DriverName": printer.DriverName,
                "PortName": printer.PortName,
                "ShareName": printer.ShareName,
                "Status": printer.PrinterStatus,
                "Default": printer.Default,
                "Local": printer.Local,
                "Network": printer.Network,
                "JobCount": job_count
            })
        
        message = f"Impressoras listadas com sucesso em {remote_host} via WMI!"
        log_action("Listar Impressoras Remoto", remote_host, "Sucesso", message)
        print(f"DEBUG: {len(printers)} impressoras encontradas em {remote_host}")
        auth_username = None
        auth_password = None
        response_data = jsonify({"status": "success", "message": message, "printers": printers})
        status_code = 200

    except Exception as e:
        message = f"Erro ao listar impressoras em {remote_host}. {format_wmi_error(e)}"
        log_action("Listar Impressoras Remoto", remote_host, "Falha", message)
        print(f"Erro ao listar impressoras em {remote_host}: {e}")
        auth_username = None
        auth_password = None
        response_data = jsonify({"status": "error", "message": message})
        status_code = 500
    finally:
        pythoncom.CoUninitialize()
    
    return response_data, status_code

@app.route('/clear_print_jobs_robust', methods=['POST'])
def clear_print_jobs_robust():
    ip = client_ip()
    key = f"rl_clear_print_jobs_robust:{ip}"
    if not rate_limit(key, limit=20, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em clear_print_jobs_robust")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    domain = SECURITY.sanitize_string(data.get('domain'))

    auth_username = frontend_username
    auth_password = frontend_password
    if not remote_host or not validate_remote_host(remote_host):
        return jsonify({"status": "error", "message": "Nome do host ou IP remoto não fornecido."}), 400
    if not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password):
        message = "Credenciais inválidas. Informe usuário e senha no frontend."
        log_action("Limpar Fila Robusta", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500

    try:
        pythoncom.CoInitialize()
        conn = connect_wmi(remote_host, auth_username, auth_password, domain)
        before_jobs = []
        try:
            for j in conn.Win32_PrintJob():
                before_jobs.append(1)
        except Exception:
            pass

        ps = []
        ps.append("$printers = Get-Printer -ErrorAction SilentlyContinue;")
        ps.append("$resumed = 0; $removed = 0;")
        ps.append("foreach ($pr in $printers) { $n = $pr.Name; $jobs = Get-PrintJob -PrinterName $n -ErrorAction SilentlyContinue; foreach ($j in $jobs) { $js = ([string]$j.JobStatus + ' ' + [string]$j.Status).ToLower(); if ($js -match 'paused|pausado') { try { Resume-PrintJob -PrinterName $n -ID $j.ID -ErrorAction SilentlyContinue; $resumed++ } catch {} } try { Remove-PrintJob -PrinterName $n -ID $j.ID -ErrorAction SilentlyContinue; $removed++ } catch {} } }")
        ps.append("$remaining = 0; foreach ($pr in $printers) { $remaining += (Get-PrintJob -PrinterName $pr.Name -ErrorAction SilentlyContinue).Count }")
        ps.append("Write-Output ('Resumed=' + $resumed + ';Removed=' + $removed + ';Remaining=' + $remaining)")
        cmd = "powershell -NoProfile -ExecutionPolicy Bypass -Command \"" + " ".join(ps) + "\""

        if is_local_host(remote_host):
            try:
                subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-Command", cmd], check=False)
            except Exception:
                pass
        else:
            try:
                conn.Win32_Process.Create(CommandLine=cmd)
            except Exception:
                pass

        time.sleep(2)

        after_jobs = []
        try:
            for j in conn.Win32_PrintJob():
                after_jobs.append(1)
        except Exception:
            pass

        message = "Limpeza robusta executada."
        log_action("Limpar Fila Robusta", remote_host, "Sucesso", message)
        return jsonify({"status": "success", "message": message, "before_count": len(before_jobs), "after_count": len(after_jobs)})
    except Exception as e:
        message = f"Erro ao executar limpeza robusta em {remote_host}. {format_wmi_error(e)}"
        log_action("Limpar Fila Robusta", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500
    finally:
        pythoncom.CoUninitialize()

@app.route('/test_wmi', methods=['POST'])
def test_wmi():
    ip = client_ip()
    key = f"rl_test_wmi:{ip}"
    if not rate_limit(key, limit=20, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em test_wmi")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    domain = SECURITY.sanitize_string(data.get('domain'))

    auth_username = frontend_username
    auth_password = frontend_password

    if not remote_host or not validate_remote_host(remote_host):
        return jsonify({"status": "error", "message": "Nome do host ou IP remoto não fornecido."}), 400

    if not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password):
        message = "Credenciais inválidas. Informe usuário e senha no frontend."
        log_action("Teste WMI Remoto", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500

    try:
        pythoncom.CoInitialize()
        log_action("Teste WMI Remoto", remote_host, "Iniciado", "Tentando conectar via WMI.")
        
        conn = None
        try:
            conn = connect_wmi(remote_host, auth_username, auth_password, domain)
        except pywintypes.com_error as ce:
            raise ce
        except Exception:
            conn = wmi.WMI(computer=remote_host, user=auth_username, password=auth_password, namespace='root\\cimv2')

        # Se a conexão for bem-sucedida, tentamos uma consulta simples para validar
        conn.Win32_OperatingSystem()[0] 
        
        message = f"Conexão WMI bem-sucedida com {remote_host}!"
        log_action("Teste WMI Remoto", remote_host, "Sucesso", message)
        auth_username = None
        auth_password = None
        return jsonify({"status": "success", "message": message})

    except Exception as e:
        message = f"Erro ao testar conexão WMI com {remote_host}. {format_wmi_error(e)}"
        log_action("Teste WMI Remoto", remote_host, "Falha", message)
        print(f"Erro ao testar conexão WMI com {remote_host}: {e}")
        auth_username = None
        auth_password = None
        return jsonify({"status": "error", "message": message}), 500
    finally:
        pythoncom.CoUninitialize()

@app.route('/get_services_status', methods=['POST'])
def get_services_status():
    ip = client_ip()
    key = f"rl_get_services_status:{ip}"
    if not rate_limit(key, limit=60, window_sec=60):
        log_action("Segurança", ip, "Alerta", "Rate limit atingido em get_services_status")
        return jsonify({"status": "error", "message": "Limite de requisições atingido. Tente novamente mais tarde."}), 429

    if request.method == 'POST' and not require_csrf():
        return jsonify({"status": "error", "message": "Falha de validação CSRF."}), 403
    print("DEBUG: Endpoint /get_services_status foi acessado.")
    data = request.get_json()
    remote_host = SECURITY.sanitize_string(data.get('remote_host'))
    frontend_username = SECURITY.sanitize_string(data.get('username'))
    frontend_password = data.get('password')
    
    # Permite que o frontend envie uma lista específica de serviços para verificar
    services_to_check = data.get('service_names', DEFAULT_SERVICES_TO_RESTART)

    auth_username = frontend_username
    auth_password = frontend_password

    print(f"DEBUG: Credenciais WMI: Usuário={auth_username}, Senha=***")
    if not remote_host:
        print("DEBUG: Host remoto não fornecido. Tentando obter status de serviços locais.")
    elif not auth_username or not auth_password or not validate_username(auth_username) or not validate_password(auth_password) or (remote_host and not validate_remote_host(remote_host)):
        message = "Credenciais inválidas para acesso remoto. Informe usuário e senha no frontend."
        log_action("Status Serviços Remoto", remote_host, "Falha", message)
        return jsonify({"status": "error", "message": message}), 500

    service_statuses = []
    try:
        pythoncom.CoInitialize()
        log_action("Status Serviços Remoto", remote_host if remote_host else "localhost", "Iniciado", "Tentando obter status dos serviços via WMI.")
        print(f"DEBUG: Iniciando conexão WMI para obter status dos serviços em {remote_host if remote_host else 'localhost'}")
        
        conn = None
        try:
            if remote_host:
                conn = connect_wmi(remote_host, auth_username, auth_password, domain)
            else:
                conn = wmi.WMI(namespace='root\\cimv2') # Conexão local
        except pywintypes.com_error as ce:
            print(f"DEBUG: Erro pywintypes.com_error ao conectar WMI: {ce}")
            raise ce
        except Exception as e:
            print(f"DEBUG: Erro geral ao conectar WMI: {e}")
            if remote_host:
                conn = wmi.WMI(computer=remote_host, user=auth_username, password=auth_password, namespace='root\\cimv2')
            else:
                conn = wmi.WMI(namespace='root\\cimv2') # Conexão local
        
        print(f"DEBUG: Conexão WMI estabelecida para {remote_host if remote_host else 'localhost'}")

        for service_name in services_to_check:
            try:
                print(f"DEBUG: Tentando obter status do serviço: {service_name}")
                if conn:
                    wmi_service = conn.Win32_Service(Name=service_name)[0]
                    status = wmi_service.State
                    start_mode = wmi_service.StartMode
                    service_statuses.append({
                        "name": service_name,
                        "status": status,
                        "start_mode": start_mode
                    })
                    print(f"DEBUG: Status do serviço {service_name}: {status}")
                else:
                    # Fallback para serviços locais se a conexão WMI falhar ou não for remota
                    # Isso pode ser feito com 'sc query' via subprocess
                    print(f"DEBUG: Conexão WMI não estabelecida para {service_name}. Tentando método alternativo (local).")
                    result = subprocess.run(["sc", "query", service_name],
                                            capture_output=True, text=True, check=False)
                    if result.returncode == 0:
                        output = result.stdout.lower()
                        status = "Unknown"
                        if "running" in output: status = "Running"
                        elif "stopped" in output: status = "Stopped"
                        elif "paused" in output: status = "Paused"
                        start_mode = "Unknown" # sc query não dá o start mode diretamente
                        service_statuses.append({
                            "name": service_name,
                            "status": status,
                            "start_mode": start_mode
                        })
                        print(f"DEBUG: Status do serviço local {service_name}: {status}")
                    else:
                        service_statuses.append({
                            "name": service_name,
                            "status": "Não Encontrado/Erro",
                            "start_mode": "N/A"
                        })
                        print(f"DEBUG: Erro ao obter status do serviço local {service_name}: {result.stderr}")
            except Exception as e:
                service_statuses.append({
                    "name": service_name,
                    "status": "Erro",
                    "start_mode": "N/A",
                    "error": str(e)
                })
                print(f"DEBUG: Erro ao obter status do serviço {service_name}: {e}")

        message = f"Status dos serviços obtido com sucesso em {remote_host if remote_host else 'localhost'} via WMI!"
        log_action("Status Serviços Remoto", remote_host if remote_host else "localhost", "Sucesso", message)
        print(f"DEBUG: Status dos serviços obtido com sucesso. Total de serviços: {len(service_statuses)}")
        auth_username = None
        auth_password = None
        return jsonify({"status": "success", "message": message, "services": service_statuses})

    except Exception as e:
        message = f"Erro ao obter status dos serviços em {remote_host if remote_host else 'localhost'}. {format_wmi_error(e)}"
        log_action("Status Serviços Remoto", remote_host if remote_host else "localhost", "Falha", message)
        print(f"DEBUG: Erro geral na função get_services_status: {e}")
        auth_username = None
        auth_password = None
        return jsonify({"status": "error", "message": message}), 500
    finally:
        pythoncom.CoUninitialize()

if __name__ == '__main__':
    if MONITOR_THREAD is None:
        MONITOR_THREAD = threading.Thread(target=service_status_monitor, daemon=True)
        MONITOR_THREAD.start()
    cert_path = os.path.join(os.path.dirname(__file__), 'cert.pem')
    key_path = os.path.join(os.path.dirname(__file__), 'key.pem')
    ssl_ctx = (cert_path, key_path) if os.path.exists(cert_path) and os.path.exists(key_path) else None
    app.run(debug=True, host='127.0.0.1', port=5000, ssl_context=ssl_ctx)
