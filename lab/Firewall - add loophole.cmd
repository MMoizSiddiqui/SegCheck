@echo off
title SegCheck demo lab - add loophole
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\firewall.ps1" office
pause
