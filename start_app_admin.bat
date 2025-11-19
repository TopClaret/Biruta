@echo off
REM Este script inicia o aplicativo Flask com permissões de administrador.
REM Para executá-lo, clique com o botão direito do mouse e selecione "Executar como administrador".

cd /d "%~dp0"

REM Ativa o ambiente virtual
call .\.venv\Scripts\activate.bat

REM Inicia o servidor Flask
py app.py

pause