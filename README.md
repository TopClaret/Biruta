# Segurança Centralizada com SecurityManager

Este projeto utiliza a classe `SecurityManager` para concentrar lógica de segurança com responsabilidade única e testabilidade.

## Objetivos
- Encapsular validações, geração de tokens, sanitização e autorização.
- Padronizar o uso de utilitários de segurança pela aplicação.

## Uso

### Validações e Sanitização
```python
from security_manager import SecurityManager
sm = SecurityManager()
sm.validate_username("user")
sm.validate_password("abc")
sm.validate_remote_host("host-1")
sm.sanitize_string("  HOST-1  ")
```

### CSRF e Tokens
```python
csrf = sm.generate_csrf_token()
sm.validate_csrf(csrf, csrf)

auth_token = sm.generate_auth_token()
```

### Rate Limit
```python
store = {}
sm.rate_limit("rl:ip", limit=60, window_sec=60, store=store)
```

### Autorização
```python
sm.is_authorized("remote_operation", {"role": "admin"})
```

## Integração com a Aplicação
A aplicação (`app.py`) usa `SecurityManager` para:
- Validação e sanitização de `remote_host` e `username`.
- Geração/validação de tokens CSRF.
- Rate limit centralizado.

Referências principais:
- `security_manager.py`: classe central de segurança
- `app.py`: integração em `require_csrf`, rate limit, SSE e operações de serviço

## Boas Práticas
- Nunca versionar `.env` nem segredos; use o `.env.example` como guia.
- Zerar credenciais em variáveis após o uso.
- Preferir variáveis de ambiente em produção ou um secrets manager.

## Testes
Os testes unitários estão em `tests/test_security_manager.py` e cobrem:
- Validações e sanitização
- CSRF e rate limit

Execute:
```
python -m unittest discover -s tests -v
```

## Compatibilidade
A migração mantém compatibilidade com o código legado:
- As funções existentes (`require_csrf`, `validate_*`, `rate_limit`) delegam ao `SecurityManager`.
