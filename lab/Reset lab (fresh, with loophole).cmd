@echo off
title SegCheck demo lab - reset
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\reset-demo.ps1"
echo.
pause
