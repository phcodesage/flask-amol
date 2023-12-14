# Flask Server Interface Project

## Description
This Flask-based project provides a server interface that facilitates communication with connected devices. The server supports various functionalities like file upload, device communication, TURN server credentials handling, and real-time messaging using SocketIO.

## Features
- **User Authentication**: Supports user login functionality to access the server interface.
- **Device Management**: View and manage connected devices in real time.
- **File Upload**: Allows uploading and sending files to connected devices.
- **Real-Time Communication**: Utilizes SocketIO for real-time messaging between the server and connected devices.
- **TURN Server Integration**: Generates TURN server credentials for secure connections.
- **Audio and Video Call Support**: Basic implementation for handling audio and video calls.

## Installation

### Prerequisites
- Python 3.7 or higher
- Flask
- Flask-SocketIO
- Flask-Login
- Flask-SQLAlchemy
- Eventlet or Gevent (for WebSocket support)

## Usage
- Access the server interface through the browser at `http://localhost:5000`.
- Log in with your credentials.
- View and manage connected devices.
- Utilize the chat feature for real-time communication.
- Use file upload functionality for sending files to devices.


## Known Issues
- Occasionally, the SocketIO `emit` function may encounter issues with the `broadcast` argument. Ensure correct usage as per Flask-SocketIO documentation.

## Contributing
Contributions to the project are welcome. Please follow the standard fork, branch, and pull request workflow.

## License

All rights reserved. Copyright 2023, PHCODESAGE.TECH.

The code and associated documentation in this project are proprietary to [Your Name or Your Company's Name]. Unauthorized copying of files, via any medium, distribution, modification, public display, or performance of this material without prior written permission from PHCODESAGE.TECH is strictly prohibited.


## Contact
For any queries or contributions, please contact rechceltoledo@gmail.com.