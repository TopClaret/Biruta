import subprocess
import os
import sys

# Caminho completo para o executável openssl.exe
# Substitua este caminho pelo caminho real onde seu openssl.exe está localizado
OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"

# Verifica se o openssl.exe existe no caminho especificado
if not os.path.exists(OPENSSL_PATH):
    print(f"Erro: openssl.exe não encontrado em {OPENSSL_PATH}")
    print("Por favor, verifique o caminho e tente novamente.")
    sys.exit(1)

# Comando para gerar o certificado autoassinado
command = [
    OPENSSL_PATH,
    "req",
    "-x509",
    "-newkey", "rsa:4096",
    "-nodes",
    "-out", "cert.pem",
    "-keyout", "key.pem",
    "-days", "365",
    "-subj", "/CN=localhost"
]

print(f"Executando comando: {' '.join(command)}")

try:
    # Executa o comando
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    print("Certificado e chave gerados com sucesso!")
    print("Saída do OpenSSL:")
    print(result.stdout)
    if result.stderr:
        print("Erros/Avisos do OpenSSL:")
        print(result.stderr)
except subprocess.CalledProcessError as e:
    print(f"Erro ao gerar certificado: {e}")
    print("Saída padrão:")
    print(e.stdout)
    print("Saída de erro:")
    print(e.stderr)
except FileNotFoundError:
    print(f"Erro: O executável do OpenSSL não foi encontrado no caminho: {OPENSSL_PATH}")
    print("Por favor, verifique se o caminho está correto e se o OpenSSL está instalado.")
except Exception as e:
    print(f"Ocorreu um erro inesperado: {e}")