#!/bin/bash

# Navigate to the src directory
cd "$(dirname "$0")"/../src

# Run the Python script with all arguments passwed to the shell script
python3 main.py "$@"
