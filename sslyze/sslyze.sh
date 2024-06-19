#!/bin/bash

# Prompt for user input
read -p "Enter the URL or IP address to scan with sslyze: " target
read -p "Enter the port number (default is 443): " port

# Check if target is provided
if [ -z "$target" ]; then
    echo "Error: No target specified."
    exit 1
fi

# Set default port if none is provided
if [ -z "$port" ]; then
    port=443
fi

# Run sslyze with specific scan commands and save output to sslyze_results.txt
sslyze ${target}:${port} > sslyze_results.txt

echo "Scan completed. Results saved to sslyze_results.txt"
echo "Now run 'python3 ssl.py'"

