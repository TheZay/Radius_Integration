@echo off

REM Navigate to the src directory
cd %~dp0\..

REM Run the Python script with all arguments passed to the batch script
python -m src.macollector.macollector %*
