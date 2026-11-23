@echo off
title SegCheck demo lab - fix loophole
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\firewall.ps1" fixed
pause
