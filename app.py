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
import hmac
import hashlib
import base64
from eventlet import wsgi
import eventlet
from eventlet.green import ssl
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import request, abort
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from flask import session  # Don't forget to import session
from flask_migrate import Migrate
from datetime import datetime

ALLOWED_IPS = ['127.0.0.1', '182.18.238.241', '182.18.238.149', '110.54.204.206', '114.108.224.203', '114.108.224.240']

TURN_SECRET = "!!Bird123"  # Your static-auth-secret from turnserver.conf
TURN_SERVER = "phcodesage.tech"  # Your TURN server address
TURN_PORT = "3480"  # Your TURN server port

eventlet.monkey_patch()

# Load environment variables from .env file
load_dotenv()

# Initialize Flaskctre
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
socketio = SocketIO(app)
project_root = os.path.dirname(os.path.abspath(__file__))

# Setup logging
logging.basicConfig(level=logging.INFO)

# Set the SQLALCHEMY_DATABASE_URI configuration to point to the project root
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(project_root, 'mydatabase.db')
app.config['SECRET_KEY'] = '##PoppyMan123'


print(app.config['SQLALCHEMY_DATABASE_URI'])


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

users_in_room = {}
rooms_sid = {}
names_sid = {}


class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    color = db.Column(db.String(30), nullable=True)
    is_connected = db.Column(db.Boolean, default=False)
    in_call = db.Column(db.Boolean, default=False)  # Add this line

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
    message_class = db.Column(db.String(100), nullable=False)

    def __repr__(self):
       return f"Message('{self.sender}', '{self.content}', '{self.timestamp}', '{self.message_class}')"


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

def is_allowed_ip():
    client_ip = request.remote_addr
    return client_ip in ALLOWED_IPS

def update_connected_devices_list():
    global connected_devices
    connected_devices = [device.name for device in Device.query.filter_by(is_connected=True).all()]
    socketio.emit('update_device_list', connected_devices)


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

def create_turn_credentials(secret, username):
    timestamp = int(time.time()) + 86400  # Valid for the next 24 hours
    username = "{}:{}".format(timestamp, username)
    password = hmac.new(secret.encode(), username.encode(), hashlib.sha1).digest()
    password = base64.b64encode(password).decode()
    return username, password

@app.route('/get_turn_credentials')
def get_turn_credentials():
    username, password = create_turn_credentials(TURN_SECRET, "exampleUser")
    return jsonify({
        'username': username,
        'password': password,
        'urls': [
            f"turn:{TURN_SERVER}:{TURN_PORT}?transport=udp",
            f"turn:{TURN_SERVER}:{TURN_PORT}?transport=tcp"
        ]
    })

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

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not is_allowed_ip():
        abort(403)
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

    if not is_allowed_ip():
            abort(403)  

    global connected_devices
    # Update the connected devices list each time this route is accessed
    update_connected_devices_list()

    # Proceed to get base_url and endpoint from tunnel_url
    base_url = "https://" + "app.phcodesage.tech"

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
    
    # Generate a string representation of connected devices
    devices_string = ", ".join(connected_devices) if connected_devices else "No devices connected"

    return render_template('server_interface.html', base_url=base_url, success=success, devices_string=devices_string, devices=connected_devices, ip_addresses=[ip_address], endpoint=endpoint)

@app.route('/register_device', methods=['GET', 'POST'])
def register_device():
    try:
        if request.method == 'POST':
            device_name = request.form.get('device_name')
            client_ip = request.remote_addr
            app.logger.info(f"Received device_name: {device_name} from IP: {client_ip}")

            if not device_name:
                flash('Device name is required.', 'danger')
                return render_template('register_device.html')

            # Check if the device is already registered
            existing_device = Device.query.filter_by(name=device_name).first()
            if existing_device:
                flash('Device already registered. Redirecting to the device dashboard.', 'info')
                session['device_name'] = device_name
                # Set the existing device as connected
                existing_device.is_connected = True
                db.session.commit()
                update_connected_devices_list()
                return redirect(url_for('device', device_name=device_name))

            # Register new device
            new_device = Device(name=device_name, ip_address=client_ip, is_connected=True)
            db.session.add(new_device)
            db.session.commit()

            session['device_name'] = device_name
            update_connected_devices_list()

            flash('Device registered successfully. Redirecting to your device dashboard.', 'success')
            return redirect(url_for('device', device_name=device_name))
        else:
            return render_template('register_device.html')
    except Exception as e:
        app.logger.error(f"Error: {e}")
        flash('Internal server error.', 'danger')
        return render_template('register_device.html')



def get_device_name_from_session():
    return session.get('device_name')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')


def is_device_registered(device_name):
    all_devices = json.loads(session.get('all_devices', '{}'))
    return device_name in all_devices



@app.route('/device')
def device():
    device_name = session.get('device_name')
    if not device_name:
        return redirect(url_for('register_device'))

    device = Device.query.filter_by(name=device_name).first()
    if not device:
        flash('Device not recognized. Please register your device.', 'danger')
        return redirect(url_for('register_device'))

    app.logger.info(f"Device {device_name} is recognized, redirecting to device interface")
    return render_template('device.html', device_name=device_name)


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
    device_name = get_device_name_from_session()
    if device_name:
        device = Device.query.filter_by(name=device_name).first()
        if device:
            device.is_connected = True
            db.session.commit()
            if device_name not in connected_devices:
                connected_devices.append(device_name)
                emit('device_connected', {'device_name': device_name, 'status': 'connected'})
            update_connected_devices_list()
            device_socket_map[device_name] = request.sid


@socketio.on('disconnect')
def handle_disconnect():
    device_name = get_device_name_from_session()
    if device_name in device_socket_map:
        device = Device.query.filter_by(name=device_name).first()
        if device:
            device.is_connected = False
            db.session.commit()
            connected_devices.remove(device_name)
        del device_socket_map[device_name]
        update_connected_devices_list()


@socketio.on('server_typing')
def handle_server_typing_event(data):
    print("Received a server_typing event with data:", data)
    emit('server_typing', data, broadcast=True)

@socketio.on('server_stop_typing')
def handle_server_stop_typing_event():
    print("Received a server_stop_typing event")
    emit('server_stop_typing', broadcast=True)

@socketio.on('client_typing')
def handle_client_typing_event(data):
    app.logger.info("Received a client_typing event with data: %s", data)
    # Include the sender's name when broadcasting the typing event
    emit('client_typing', data, broadcast=True)

@socketio.on('client_stop_typing')
def handle_client_stop_typing_event(data):
    app.logger.info("Received a client_stop_typing event with data: %s", data)
    # Include the sender's name when broadcasting the stop typing event
    emit('client_stop_typing', data, broadcast=True)


@socketio.on('chat_message_to_device')
def handle_chat_message(data):
    target_device = data.get('target_device')
    sender_device = data.get('sender_device')  # This could be 'Server' or the device name
    message_class = data.get('message_class')  # This will be 'server-message' or 'device-message'
    
    # Get the current UTC timestamp
    timestamp = datetime.utcnow()
    formatted_timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')

    # Add the formatted timestamp to the message data
    data['timestamp'] = formatted_timestamp

    # Save the chat message to the database
    try:
        message = Message(
            sender=data['sender_device'],
            content=data['message'],
            message_class=data['message_class']
        )
        db.session.add(message)
        db.session.commit()
        print("Message saved to database.")
    except Exception as e:
        print("An error occurred while saving the message:", e)
        db.session.rollback()
    
    # Emit the message to the specified device or broadcast it
    if target_device and target_device in device_socket_map:
        socket_id = device_socket_map[target_device]
        emit('broadcast_message', data, room=socket_id)
    else:
        emit('broadcast_message', data, broadcast=True)


@socketio.on('change_server_color')
def handle_change_server_color(data):
    # This function assumes that you want to broadcast the color change to all connected clients.
    # Replace this with your actual logic to change the server's color.
    new_color = data['color']
    emit('server_color_changed', {'color': new_color}, broadcast=True)


@socketio.on('chat_message_to_server')
def handle_message_to_server(data):
    sender_device = data.get('name')
    message_content = data.get('message')
    message_class = data.get('message_class', 'server-message')  # Default to 'server-message' if not provided

    # Get the current UTC timestamp
    timestamp = datetime.utcnow()

    # Save the message to the database with the sender's device name and class
    new_message = Message(sender=sender_device, content=message_content, timestamp=timestamp, message_class=message_class)
    db.session.add(new_message)
    db.session.commit()

    # Prepare the data to send to the client
    data['timestamp'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
    data['sender'] = sender_device
    data['message_class'] = message_class  # Make sure to include this in the emitted data

    # Broadcast the message to the server interface
    emit('broadcast_message_to_server', data, broadcast=True)


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

@socketio.on('start_video_call')
def start_video_call(data):
    room_name = data.get('room_name', 'defaultRoom')  # Use a default room name if none provided
    emit('initiate_video_call', {'room_name': room_name}, broadcast=True)

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

@app.route('/send_audio_to_device', methods=['POST'])
def send_audio_to_device():
    try:
        device_name = request.args.get('device')
        audio_file = request.files['audio']

        if audio_file:
            filename = secure_filename(audio_file.filename)
            # Use the upload folder from app config
            upload_folder = app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)
            file_path = os.path.join(upload_folder, filename)
            audio_file.save(file_path)

            # Generate the download URL using the 'uploaded_file' view
            download_url = url_for('uploaded_file', filename=filename, _external=True)

            if device_name in device_socket_map:
                socket_id = device_socket_map[device_name]
                socketio.emit('new_audio_message_to_device', {'url': download_url}, room=socket_id)

            return jsonify(status='success', message='Audio sent successfully'), 200

        return jsonify(status='fail', message='No audio file provided'), 400

    except Exception as e:
        return jsonify(status='error', message=str(e)), 500

@socketio.on('offer')
def handle_offer(data):
    # Forward the offer to the receiver
    emit('offer', data, broadcast=True, include_self=False)



@socketio.on('message')
def handle_message(data):
    if 'iceCandidate' in data:
        # Forward the ICE candidate to the other peer
        emit('message', {'iceCandidate': data['iceCandidate']}, broadcast=True, include_self=False)

    elif 'offer' in data:
        # Forward the offer to the other peer
        emit('message', {'offer': data['offer']}, broadcast=True, include_self=False)

    elif 'answer' in data:
        # Forward the answer to the other peer
        emit('message', {'answer': data['answer']}, broadcast=True, include_self=False)

@socketio.on('answer')
def handle_answer(data):
    # Forward the answer to the caller
    emit('answer', data, broadcast=True, include_self=False)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    # Forward the ICE candidate to the other peer
    emit('ice_candidate', data, broadcast=True, include_self=False)

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


##upload-file route
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

@app.route('/upload_audio', methods=['POST'])
def upload_audio():
    if 'audio' not in request.files:
        return jsonify({'status': 'error', 'message': 'No audio file found'}), 400

    audio_file = request.files['audio']
    filename = secure_filename(audio_file.filename)
    if filename == '':
        return jsonify({'status': 'error', 'message': 'No filename provided'}), 400

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    audio_file.save(filepath)
    
    # Create a URL that can be accessed over HTTP
    file_url = url_for('uploaded_file', filename=filename, _external=True)
    
    # Emit the socket event with the correct HTTP URL
    socketio.emit('new_audio_message', {'url': file_url})
    
    return jsonify({'status': 'success', 'message': 'Audio file uploaded successfully', 'url': file_url})



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


@app.route('/fetch_messages', methods=['GET'])
def fetch_messages():
    # Get the last session's messages from the database using SQLAlchemy
    messages = Message.query.order_by(Message.timestamp).all()

    # Convert the messages to a format suitable for your frontend (e.g., JSON)
    message_list = [
        {
            "sender": msg.sender,
            "content": msg.content,
            "timestamp": msg.timestamp.isoformat() if msg.timestamp else None,
            "message_class": msg.message_class  # Include the message_class attribute
        }
        for msg in messages
    ]
    
    return jsonify(message_list)




##calling feature

@app.route("/join", methods=["GET"])
def join():
    display_name = request.args.get('display_name')
    mute_audio = request.args.get('mute_audio') # 1 or 0
    mute_video = request.args.get('mute_video') # 1 or 0
    room_id = request.args.get('room_id')
    session[room_id] = {"name": display_name,
                        "mute_audio": mute_audio, "mute_video": mute_video}
    return render_template("join.html", room_id=room_id, display_name=session[room_id]["name"], mute_audio=session[room_id]["mute_audio"], mute_video=session[room_id]["mute_video"])

@socketio.on("join-room")
def on_join_room(data):
    sid = request.sid
    room_id = data["room_id"]
    display_name = session[room_id]["name"]

    # register sid to the room
    join_room(room_id)
    rooms_sid[sid] = room_id
    names_sid[sid] = display_name

    # broadcast to others in the room
    print("[{}] New member joined: {}<{}>".format(room_id, display_name, sid))
    emit("user-connect", {"sid": sid, "name": display_name},
         broadcast=True, include_self=False, room=room_id)

    # add to user list maintained on server
    if room_id not in users_in_room:
        users_in_room[room_id] = [sid]
        emit("user-list", {"my_id": sid})  # send own id only
    else:
        usrlist = {u_id: names_sid[u_id]
                   for u_id in users_in_room[room_id]}
        # send list of existing users to the new member
        emit("user-list", {"list": usrlist, "my_id": sid})
        # add new member to user list maintained on server
        users_in_room[room_id].append(sid)

    print("\nusers: ", users_in_room, "\n")



@socketio.on("data")
def on_data(data):
    sender_sid = data['sender_id']
    target_sid = data['target_id']
    if sender_sid != request.sid:
        print("[Not supposed to happen!] request.sid and sender_id don't match!!!")

    if data["type"] != "new-ice-candidate":
        print('{} message from {} to {}'.format(
            data["type"], sender_sid, target_sid))
    socketio.emit('data', data, room=target_sid)


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

@socketio.on('message')
def handle_message(data):
    logging.info(f"Received message: {data}")
    # Emit to all clients except the sender
    emit('message', data, room=request.sid, include_self=False)


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
    app.run(debug=True,host='127.0.0.1', port=5000)
