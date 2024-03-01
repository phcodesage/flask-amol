#!/bin/bash

# Detect the operating system and install necessary packages for virtual environment
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update
    sudo apt install python3-virtualenv python3-pip -y
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected. Assuming Python 3 and virtualenv are already installed."
    # You may need to install virtualenv via pip if it's not already installed
    pip3 install --user virtualenv
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
pip3 install --upgrade pip

# Install or upgrade dependencies listed in requirements.txt
# The --upgrade flag will install the specified versions or upgrade them if they're already installed
if [ -f "requirements.txt" ]; then
    pip3 install --upgrade -r requirements.txt
else
    echo "requirements.txt file not found"
fi

# Optional: Kill processes running on port 5000 to free it up
# Be cautious with using sudo; it might not be necessary or safe in all environments
# sudo lsof -ti:5000 | xargs sudo kill -9

# Initialize, migrate, and upgrade the database
# Note: Ensure that your Flask application is configured to use Flask-Migrate correctly for these commands to work
python3 -m flask db init
python3 -m flask db migrate
python3 -m flask db upgrade

# Start the Flask app
# Ensure app.py is the correct name of your Flask application script
python3 app.py
