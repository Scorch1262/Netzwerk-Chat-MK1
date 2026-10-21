@echo off
title Netzwerk-Chat v1.1.0
cd /d "%~dp0"
python netzwerk_chat.py %*
if errorlevel 1 pause
