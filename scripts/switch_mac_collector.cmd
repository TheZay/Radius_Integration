@echo off

REM Navigate to the src directory
cd %~dp0\..\src

REM Run the Python script with all arguments passwed to the batch script
python main.py %*
