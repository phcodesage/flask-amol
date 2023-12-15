#!/bin/bash

# Detect the OS and install necessary packages
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo apt update
    sudo apt install python3-virtualenv -y
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "macOS detected. Assuming Python 3 and virtualenv are already installed."
fi

# Deactivate the virtual environment if it is active
if type "deactivate" > /dev/null 2>&1; then
    deactivate
fi

# Activate the virtual environment
source myenv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Kill processes running on port 5000 to free it up
sudo fuser -k 5000/tcp

flask db init
flask db migrate
flask db upgrade


# Start the Flask app
python3 app.py

