#!/bin/bash

# Detect the operating system and install necessary packages for the virtual environment
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Linux detected. Installing packages..."
    sudo apt update
    sudo apt install python3-venv python3-pip -y  # Use python3-venv which is more universally applicable
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected. Assuming Homebrew is installed."
    # Install Python3 and pip if they are not installed
    brew install python3
    # The next line is not necessary as pip comes with Python3
    echo "Assuming Python 3 and pip are already installed."
    # Check if virtualenv is installed and install it if not
    if ! type "virtualenv" > /dev/null; then
        pip3 install --user virtualenv
    fi
fi

# Deactivate the virtual environment if it is active
# Note: This only works if the script is sourced or run in an interactive shell
if type "deactivate" &> /dev/null; then
    deactivate
fi

# Ensure the virtual environment directory exists or create a new one
if [ ! -d "myenv" ]; then
    python3 -m venv myenv
    echo "Virtual environment created."
fi

# Activate the virtual environment
source myenv/bin/activate

# Upgrade pip to its latest version inside the virtual environment
pip install --upgrade pip

# Install or upgrade dependencies listed in requirements.txt
# The --upgrade flag will install the specified versions or upgrade them if they're already installed
if [ -f "requirements.txt" ]; then
    pip install --upgrade -r requirements.txt
else
    echo "requirements.txt file not found."
fi

# Linux-specific operations
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Setting up firewall rules..."
    sudo ufw allow 3478/tcp
    sudo ufw allow 3478/udp
    sudo ufw allow 5349/tcp
    sudo ufw allow 5349/udp
    sudo ufw allow 5000/tcp  # Allow traffic on port 5000 for the Flask app
    sudo ufw enable
    sudo ufw status
    # Kill processes running on port 8000 to free it up
    echo "Attempting to kill processes running on port 8000..."
    sudo lsof -ti:8000 | sudo xargs kill -9
fi

# Initialize, migrate, and upgrade the database
# Note: Ensure that your Flask application is configured to use Flask-Migrate correctly for these commands to work
echo "Initializing, migrating, and upgrading database..."
python3 -m flask db init
python3 -m flask db migrate
python3 -m flask db upgrade

# Start the Flask app
# Ensure app.py is the correct name of your Flask application script
echo "Starting Flask app..."
python3 app.py
