# Configuração do Gunicorn para produção
import multiprocessing

# Número de workers (processos)
workers = multiprocessing.cpu_count() * 2 + 1

# Endereço e porta
bind = "127.0.0.1:5001"

# Timeouts
timeout = 30
keepalive = 2

# Logging
accesslog = "-"  # stdout
errorlog = "-"  # stdout
loglevel = "info"

# Segurança
limit_request_line = 4096
limit_request_fields = 100
limit_request_field_size = 8190

# Performance
max_requests = 1000
max_requests_jitter = 100
preload_app = True