from flask import Flask, redirect, render_template, request, jsonify, send_from_directory, url_for, current_app, redirect, url_for, flash
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.utils import secure_filename
import traceback
import os
import time
import socket
import logging
import psutil
import subprocess
import mimetypes
import json
from eventlet import wsgi
import eventlet
from eventlet.green import ssl
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask import session  # Don't forget to import session
from flask_migrate import Migrate
from datetime import datetime




# Load environment variables from .env file
load_dotenv()

# Initialize Flaskctre
app = Flask(__name__)
project_root = os.path.dirname(os.path.abspath(__file__))

# Set the SQLALCHEMY_DATABASE_URI configuration to point to the project root
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(project_root, 'mydatabase.db')
app.config['SECRET_KEY'] = '##PoppyMan123'


print(app.config['SQLALCHEMY_DATABASE_URI'])


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)



class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    color = db.Column(db.String(30), nullable=True)
    is_connected = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"Device('{self.name}', '{self.ip_address}', '{self.color}')"


# User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False) # <- Change here

    def __repr__(self):
        return f"User('{self.username}')"

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Message('{self.sender}', '{self.content}', '{self.timestamp}')"


# Initialize SocketIO and other components
socketio = SocketIO(app, cors_allowed_origins="*")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

# Initialize SQLAlchemy

with app.app_context():
        db.create_all()
        # Get all users
        users = User.query.all()

        # Print all users
        for user in users:
            print(f'User ID: {user.id}, Username: {user.username}, Password: {user.password}')
# Initialize Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize global variables
all_devices = []
device_socket_map = {}
device_messages = {}
connected_devices = []

# Setup the upload folder
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PREFERRED_URL_SCHEME'] = 'https'

ALLOWED_EXTENSIONS = {
        # Image formats
        'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff', 'ico', 'jfif', 'webp', 'psd', 'svg', 'heif', 'indd', 'ai', 'eps', 'pdf',

        # Audio formats
        'mp3', 'wav', 'aac', 'flac', 'ogg', 'm4a', 'wma', 'aiff', 'ra', 'mka',

        # Video formats
        'mp4', 'avi', 'mkv', 'flv', 'mov', 'wmv', 'm4v', 'mpg', 'mpeg', '3gp', 'f4v', 'swf', 'h264',

        # Document formats
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'odp', 'ods', 'txt', 'rtf', 'tex', 'pdf', 'epub', 'md', 'csv', 'json', 'log', 'xml',

        # Archive formats
        'zip', 'rar', 'tar', 'gz', '7z', 'bz2', 'lzma', 'xz', 'z', 'apk', 'jar', 'iso', 'cab', 'deb', 'rpm',

        # Design
        'psd', 'ai', 'indd', 'sketch', 'fig', 

        # Font formats
        'ttf', 'otf', 'woff', 'woff2', 'eot', 'fon',

        # 3D formats
        'obj', 'fbx', 'dae', '3ds', 'blend', 'md2', 'md3', 'mdl',

        # Database
        'sql', 'db', 'dbf', 'mdb', 'accdb',

        # Other
        'html', 'htm', 'xhtml', 'js', 'css', 'lua', 'py', 'java', 'rb', 'c', 'cpp', 'h', 'hpp', 'cs', 'sh', 'bat', 'ini', 'pl', 'go', 'swift', 'yml', 'yaml'
    }

# User loader for flask-login
@login_manager.user_loader
def load_user(user_id):
    if user_id is None or user_id == 'None':
        return None
    return User.query.get(int(user_id))


def get_server_ip():
    addresses = []
    for interface_name, snics in psutil.net_if_addrs().items():
        for snic in snics:
            if snic.family == socket.AF_INET and not snic.address.startswith("127."):
                addresses.append(snic.address)
    return addresses


def ensure_upload_folder_exists():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.errorhandler(Exception)
def handle_exception(e):
    # Print the error message for debugging
    print(str(e))
    
    # Log the exception
    logging.error(f"Unhandled Exception: {str(e)}")
    traceback.print_exc()  # Print traceback to the console

    # Get the type of exception and convert to string
    exception_type = str(type(e).__name__)
    exception_message = str(e)

    # Create a JSON response with the specific error type and message
    error_details = {
        'type': exception_type,
        'message': exception_message
    }

    return jsonify(status='error', error=error_details), 500


@app.route('/', methods=['GET'])
def home():
    if current_user.is_authenticated:
        return redirect(url_for('server_interface'))
    else:
        return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if current_user.is_authenticated:
        return redirect(url_for('server_interface'))
    
    # Get username and password from environment variables
    correct_username = os.environ.get('USERNAME') or "default_username"
    correct_password = os.environ.get('PASSWORD') or "default_password"


    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']
            print(f"Username from form: {username}")  # Debugging line
            user = User.query.filter_by(username=username).first()  # Check if user exists in DB

            # Validate username and password
            if user and bcrypt.check_password_hash(user.password, password): 
                login_user(user)
                return redirect(url_for('server_interface'))
            else:
                error = 'Invalid username or password'

            if username == correct_username:
                if password == correct_password: 
                    # Assuming User is a user class you've defined elsewhere
                    user = User(username=correct_username)
                    login_user(user)
                    current_app.logger.info('User logged in successfully')
                    session['success'] = "Login successful! Welcome."
                    return redirect(url_for('server_interface')) # Rexirect instead of calling the function
                else:
                    error = 'Invalid password'
            else:
                error = 'Invalid username'
    except Exception as e:
        error = 'Internal server error'
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()  # This will print the traceback
        # Log the exact error message for debugging purposes
        app.logger.error(f"Internal server error: {e}")

    return render_template('login.html', error=error)



@app.route('/server-interface', methods=['GET'])
def server_interface():
    global connected_devices
    # Proceed to get base_url and endpoint from tunnel_url
    base_url = "https://" + "amol.flask-server.tech"

    current_app.logger.info('Server interface route called')
    success = session.pop('success', None)
    
    if current_user.is_authenticated:
        current_app.logger.info('User is authenticated')
    else:
        current_app.logger.info('User is not authenticated')
    
    try:
        ip_address = get_server_ip()
    except Exception as e:
        ip_address = "Error obtaining IP address"
        app.logger.error(f"Error obtaining IP address: {e}")

    endpoint = "/device"
    
    # Check if there are connected devices
    if connected_devices:
        # Convert all non-string items to strings and filter out None values and empty strings
        connected_devices = [str(device) for device in connected_devices if device and device.strip()]
        devices_string = ", ".join(connected_devices)
    else:
        devices_string = "No devices connected"

    return render_template('server_interface.html', base_url=base_url, success=success, devices_string=devices_string, devices=connected_devices, ip_addresses=[ip_address], endpoint=endpoint)


def get_device_name_from_session():
    return session.get('device_name')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

def is_device_registered(device_name):
    # Check if the device is in the socket map or in the database
    if device_name in device_socket_map:
        return True
    
    device = Device.query.filter_by(name=device_name).first()
    return device is not None



@app.route('/device')
def device():
    client_ip = request.remote_addr
    all_devices = json.loads(session.get('all_devices', '{}'))
    device_name = next((name for name, ip in all_devices.items() if ip == client_ip), None)

    if device_name:
        # Redirect to device dashboard with device name if IP is registered
        app.logger.info(f"Device with IP {client_ip} is recognized, redirecting to device dashboard.")
        return render_template('device.html', device_name=device_name)  # Assuming you have a device dashboard template
    else:
        # Redirect to device registration if IP is not registered
        app.logger.warning(f"Device with IP {client_ip} not recognized, redirecting to registration page.")
        return redirect(url_for('register_device'))

@app.route('/register_device', methods=['GET', 'POST'])
def register_device():
    try:
        if request.method == 'POST':
            device_name = request.form.get('device_name')
            client_ip = request.remote_addr
            app.logger.info(f"Received device_name: {device_name} from IP: {client_ip}")

            if not device_name:
                flash('Device name is required', 'danger')
                return render_template('register_device.html')

            all_devices = json.loads(session.get('all_devices', '{}'))

            # Check if the device name or IP is already in the session
            if device_name in all_devices or client_ip in all_devices.values():
                flash('Device or IP already registered', 'info')
                return redirect(url_for('device_login'))  # Redirect to device login

            # Save device with IP address
            all_devices[device_name] = client_ip
            session['all_devices'] = json.dumps(all_devices)  # Save to session
            session['device_name'] = device_name

            socketio.emit('update_device_list', list(all_devices.keys()))

            flash('Device registered successfully. Redirecting to your device dashboard.', 'success')
            return redirect(url_for('device'))  # Redirect to device dashboard after registration
        else:
            return render_template('register_device.html')

    except Exception as e:
        app.logger.error(f"Error: {e}")
        flash('Internal server error', 'danger')
        return render_template('register_device.html')


@app.route('/device_login', methods=['GET', 'POST'])
def device_login():
    pre_filled_device_name = request.args.get('device_name', '')  # Get device name from URL if present
    client_ip = request.remote_addr  # Get the IP address of the client
    all_devices = json.loads(session.get('all_devices', '{}'))  # Load all registered devices from session

    # Check if the client's IP already has an associated device name registered
    device_name_by_ip = next((name for name, ip in all_devices.items() if ip == client_ip), None)

    if device_name_by_ip:
        # If a device with this IP is found, automatically log in and redirect to the device page
        app.logger.info(f"Device with IP {client_ip} recognized as {device_name_by_ip}. Automatically logging in.")
        return redirect(url_for('device', device_name=device_name_by_ip))

    if request.method == 'POST':
        device_name = request.form['device_name']

        # Check if the provided device name matches the registered IP
        if device_name in all_devices and all_devices[device_name] == client_ip:
            app.logger.info(f"Successful login for device {device_name} with IP {client_ip}.")
            return redirect(url_for('device', device_name=device_name))  # Redirect to the device route
        else:
            flash('Invalid device name or your device is not registered from this IP', 'danger')
            return render_template('device_login.html', device_name=pre_filled_device_name)

    # Render the login form with pre-filled device name if it was passed in the URL
    return render_template('device_login.html', device_name=pre_filled_device_name)



@app.route('/error')
def error_page():
    error_message = "An error occurred. Please try again."
    return render_template('error.html', error_message=error_message)



@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify(status='success', message='File deleted successfully'), 200
    else:
        return jsonify(status='fail', message='File not found'), 404


@socketio.on('connect')
def handle_connect():
    device_name = session.get('device_name')
    if device_name:
        device = Device.query.filter_by(name=device_name).first()
        if device:
            device.is_connected = True
            db.session.commit()

        if device_name not in connected_devices:
            connected_devices.append(device_name)
            emit('device_connected', {'device_name': device_name, 'status': 'connected'})
        device_socket_map[device_name] = request.sid

@socketio.on('disconnect')
def handle_disconnect():
    disconnected_device = [device for device, sid in device_socket_map.items() if sid == request.sid]
    if disconnected_device:
        device_name = disconnected_device[0]
        device = Device.query.filter_by(name=device_name).first()
        if device:
            device.is_connected = False
            db.session.commit()
        connected_devices.remove(device_name)
        del device_socket_map[device_name]
    emit('update_device_list', connected_devices, broadcast=True)
    
@socketio.on('server_typing')
def handle_server_typing_event(data):
    print("Received a server_typing event with data:", data)
    emit('server_typing', data, broadcast=True)

@socketio.on('server_stop_typing')
def handle_server_stop_typing_event(data):
    print("Received a server_stop_typing event with data:", data)
    emit('server_stop_typing', data, broadcast=True)

@socketio.on('client_typing')
def handle_client_typing_event(data):
    print("Received a client_typing event with data:", data)  # Debugging line
    emit('client_typing', data, broadcast=True)  # Send the data back to all connected clients


@socketio.on('client_stop_typing')
def handle_client_stop_typing_event(data):
    print("Received a client_stop_typing event with data:", data)  # Debugging line 
    emit('client_stop_typing', broadcast=True)

@socketio.on('chat_message_to_device')
def handle_chat_message(data):
    target_device = data.get('target_device')
    sender_device = data.get('sender_device')  # assuming data contains sender's device
    
    # Get the current timestamp and convert it to a string
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Add the timestamp to the message data
    data['timestamp'] = timestamp

    # Store the message
    if target_device not in device_messages:
        device_messages[target_device] = []
    device_messages[target_device].append(data['message'])

    # Save the chat message to the database
    message = Message(sender=target_device, content=data['message'])
    db.session.add(message)
    db.session.commit()

    # Emitting the message only once, either to a specific device or as a broadcast
    if target_device and target_device in device_socket_map and target_device != sender_device:
        socket_id = device_socket_map[target_device]
        emit('broadcast_message', data, room=socket_id)
    # Check if the sender is not the server to avoid echoing back the message
    elif not target_device or (target_device == sender_device and sender_device != "Server"):
        emit('broadcast_message', data, broadcast=True)

@socketio.on('chat_message_to_server')
def handle_message_to_server(data):
    name_of_device = data.get('name')
    message_content = data.get('message')
    target_device = data.get('target_device')

    # Assuming the server device name is "Server"
    if target_device.lower() == "server":
        timestamp = datetime.utcnow()  # Get the current UTC time
        formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')

        # Save the message to the database (if required)
        new_message = Message(sender=name_of_device, content=message_content, timestamp=timestamp)
        db.session.add(new_message)
        db.session.commit()

        # Broadcast or emit the message to the server
        # If you have a specific namespace or room for the server, specify it in the emit() function
        emit('broadcast_message_to_server', data, broadcast=True)  # Set broadcast=True if you want to send to all clients, otherwise target a specific room or session

@socketio.on('change_color')
def change_color(data):
    app.logger.info("Received data: %s", data)
    target_device = data.get('target_device')
    color = data.get('color')

    # Error handling for missing data
    if not target_device and not color:
        app.logger.error("Error: Target device and color not provided.")
        return
    elif not target_device:
        app.logger.error("Error: Target device not provided.")
        return
    elif not color:
        app.logger.error("Error: Color not provided.")
        return

    app.logger.info("Received request to change color for device %s to color %s", target_device, color)

    if target_device in device_socket_map:
        socket_id = device_socket_map[target_device]
        emit('set_background', color, room=socket_id)
        app.logger.info("Color changed successfully for device %s", target_device)
    else:
        app.logger.error("Device %s not found in device_socket_map.", target_device)


@socketio.on('clear_chat')
def handle_clear_chat():
    print("Clearing chat on client side")  # Debugging line
    emit('clear_chat', broadcast=True)


@app.route('/send_file_to_device', methods=['POST'])
def send_file_to_device():
    try:
        device_name = request.args.get('device')
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            original_extension = file.filename.rsplit('.', 1)[1].lower()
            filename_base = secure_filename(file.filename.rsplit('.', 1)[0])
            filename = f"{filename_base}.{original_extension}"
            
            ensure_upload_folder_exists()

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            download_url = url_for('download_file', filename=filename)

            if device_name in device_socket_map:
                socket_id = device_socket_map[device_name]
                time.sleep(2)
                socketio.emit('receive_file', {'file_path': download_url, 'filename': filename}, room=socket_id)

            return jsonify(status='success', message='File sent successfully'), 200

        return jsonify(status='fail', message='Failed to send file'), 400

    except Exception as e:
        return jsonify(status='error', message=str(e)), 500



@app.route('/send_message_to_device', methods=['POST'])
def send_message_to_device():
    device_name = request.form.get('device')
    message = request.form.get('message', '')

    if not message:
        return jsonify(status='fail', message='Message is empty!'), 400
    
    if not device_name or not message:
        return jsonify(status='fail', message='Missing device or message'), 400

    if device_name in device_socket_map:
        socket_id = device_socket_map[device_name]
        socketio.emit('broadcast_message', {'message': message}, room=socket_id)
        return jsonify(status='success', message='Message sent successfully'), 200

    return jsonify(status='fail', message='Device not found'), 400


@app.route('/change_background_color', methods=['POST'])
def change_background_color_request():
    device_name = request.form.get('device')
    color = request.form.get('color')

    if not device_name or not color:
        return jsonify(status='fail', message='Missing device or color'), 400

    if device_name in device_socket_map:
        socket_id = device_socket_map[device_name]
        socketio.emit('set_background', {'color': color}, room=socket_id)
        return jsonify(status='success', message='Background color changed successfully'), 200

    return jsonify(status='fail', message='Device not found'), 400


@app.route('/upload_file', methods=['POST'])
def upload_file():
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)

        ensure_upload_folder_exists()

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Use 'send' for broadcasting to all clients
        socketio.emit('file_uploaded', {'filename': filename})

        # Create a public URL for the uploaded file
        public_url = url_for('static', filename=os.path.join('uploads', filename))

        # Include the 'success' field in the response
        return jsonify(success=True, status='success', message='File uploaded successfully', url=public_url), 200

    return jsonify(success=False, status='fail', message='Failed to upload file'), 400




@app.route('/download/<filename>', methods=['GET'])
def download_file(filename):
    try:
        file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)

        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify(status='fail', message='File not found'), 404

        content_type = mimetypes.guess_type(filename)[0] or 'application/octet-stream'

        response = send_from_directory(
            current_app.config['UPLOAD_FOLDER'],
            filename, 
            as_attachment=True,
            mimetype=content_type
        )

        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        return response

    except Exception as e:
        # Log the exception for debugging
        current_app.logger.error(f"Error serving the file: {e}")
        return jsonify(status='error', message='Internal Server Error'), 500

def get_pending_actions_for_device(device_name):
    # Query the database for unprocessed notifications for this device
    pending_notifications = db_session.query(Notification).filter_by(
        device_name=device_name,
        processed=False  # assuming there is a 'processed' field in your Notification model
    ).all()
    
    # Converting database objects to dictionaries, replace with your actual implementation
    return [notification.to_dict() for notification in pending_notifications]  


@app.route('/device_messages/<device_name>', methods=['GET'])
def get_device_messages(device_name):
    return jsonify(device_messages.get(device_name, []))

@app.route('/fetch_messages', methods=['GET'])
def fetch_messages():
    # Get the last session's messages from the database using SQLAlchemy
    messages = Message.query.all()

    # Convert the messages to a format suitable for your frontend (e.g., JSON)
    message_list = [{"sender": msg.sender, "content": msg.content, "timestamp": msg.timestamp} for msg in messages]
    
    return jsonify(message_list)


@socketio.on('send_notification_to_device')
def handle_send_notification_to_device(data):
    print("Received send_notification_to_device with data:", data)
    target_device = data.get('target_device')
    
    if target_device not in device_socket_map:
        print(f"Error: {target_device} not found in device_socket_map. Checking the database.")
        device = Device.query.filter_by(name=target_device).first()

        if device:
            print(f"Device {target_device} found in the database. But it's not connected to the socket.")
            # Store the action/notification in the database for the device to execute when it connects next
            # Assuming you have a mechanism to store pending actions/notifications
        else:
            print(f"Error: {target_device} not found in the database.")
            return
    
    else:
        socket_id = device_socket_map[target_device]
        emit('receive_notification', data, room=socket_id)


@socketio.on('send_notification_to_server')
def handle_send_notification(data):
    print(data)
    target_device = data.get('target_device')
    notification = data.get('notification')
    
    # Broadcasting the message to all connected clients
    emit('server_notification', {'message': notification, 'device': target_device}, broadcast=True)

    

@socketio.on('check_for_pending_notifications')
def check_for_pending_notifications(data):
    try:
        device_name = data.get('deviceName')
        if not device_name:
            print("Error: deviceName not provided.")
            return

        # Check the database for pending notifications or actions for this device
        pending_actions = get_pending_actions_for_device(device_name)
        
        if pending_actions:
            emit('execute_pending_actions', pending_actions, room=request.sid)
    except Exception as e:
        print(f"Error checking for pending notifications: {e}")


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.254.254.254', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP



if __name__ == '__main__':
    app.debug = True  # Enable debug mode
    local_ip = '0.0.0.0'  # To listen on all available interfaces and make it accessible via ngrok
    # Wrap Flask application with socket.io's middleware

    # Deploy as an eventlet WSGI server
    eventlet.wsgi.server(eventlet.listen((local_ip, 5000)), app)
    app.run(debug=True)