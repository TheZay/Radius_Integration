@echo off

REM Navigate to the src directory
cd %~dp0\..

REM Run the Python script with all arguments passwed to the batch script
python -m src.main %*
