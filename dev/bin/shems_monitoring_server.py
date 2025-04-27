#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import logging
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import json
import pymysql
from pymysql.cursors import DictCursor
from pymysql import MySQLError
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort
import requests

# ===== Get Current Values =====
current_pid = os.getpid()

# ===== Configuration =====
HTML_DIR = '/app/smarthome/dev/templates/'
SCRIPT_DIR = '/app/smarthome/dev/bin'
DB_DIR = '/app/smarthome/data/'
LOG_DIR = '/app/smarthome/data/logs/'
DASHBOARD_IMPORT_DELAY = 30  # seconds to wait before dashboard import

# ===== Environment Variables =====
GRAFANA_USER = os.getenv("GRAFANA_USER","admin")
GRAFANA_PASS = os.getenv("GRAFANA_PASS","Pass@abcd")


# Ensure directories exist
os.makedirs(HTML_DIR, exist_ok=True)
os.makedirs(SCRIPT_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ===== Logging Configuration =====
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'shems_server.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SHEMS-Server')

# ===== Application Setup =====
app = Flask(__name__, template_folder=HTML_DIR)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ===== Database Configuration =====
class DatabaseManager:
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    
    def __init__(self):
        self.db_user = os.getenv('DB_USER', 'shems_mis')
        self.db_pass = os.getenv('DB_PASS', 'RAS@23')
        self.db_name = os.getenv('DB_NAME', 'shems_db')
        
    def get_connection(self):
        """Get a database connection with retry logic"""
        attempts = 0
        last_error = None
        
        while attempts < self.MAX_RETRIES:
            try:
                conn = pymysql.connect(
                    host='localhost',
                    user=self.db_user,
                    password=self.db_pass,
                    database=self.db_name,
                    cursorclass=DictCursor,
                    connect_timeout=5,
                    autocommit=False
                )
                logger.info("Database connection established")
                return conn
            except MySQLError as e:
                last_error = e
                attempts += 1
                logger.warning(f"DB connection failed (attempt {attempts}/{self.MAX_RETRIES}): {str(e)}")
                time.sleep(self.RETRY_DELAY)
        
        logger.error(f"Failed to establish DB connection after {self.MAX_RETRIES} attempts")
        raise ConnectionError(f"Could not connect to database: {str(last_error)}")

db_manager = DatabaseManager()

# ===== Helper Functions =====


def get_pi_ip():
    """Get Raspberry Pi IP address with fallback"""
    try:
        ip = subprocess.getoutput("hostname -I | awk '{print $1}'").strip()
        return ip if ip else '127.0.0.1'
    except:
        return '127.0.0.1'

def is_service_running(service_name):
    """Check if a systemd service is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip() == 'active'
    except Exception as e:
        logger.error(f"Service check failed for {service_name}: {str(e)}")
        return False

# ===== Enhanced Network Helper Functions =====
def get_network_interfaces():
    """Get all available network interfaces and their IPs"""
    interfaces = {
        'localhost': 'http://localhost:3000',
        'local_ip': None,
        'tailscale_ip': None
    }
    
    try:
        # Get local IP (Raspberry Pi)
        ip_output = subprocess.getoutput("hostname -I").strip()
        if ip_output:
            interfaces['local_ip'] = f"http://{ip_output.split()[0]}:3000"
        
        # Get Tailscale IP if available
        tailscale_ip = subprocess.getoutput("tailscale ip -4").strip()
        if tailscale_ip:
            interfaces['tailscale_ip'] = f"http://{tailscale_ip}:3000"
            
    except Exception as e:
        logger.warning(f"Network interface detection failed: {str(e)}")
    
    return interfaces

def detect_grafana_url():
    """Detect the most appropriate Grafana URL based on request origin"""
    try:
        if not request:
            return "http://localhost:3000"  # Fallback
        
        # Get client's accessing IP
        client_ip = request.remote_addr
        
        # Get all available interfaces
        interfaces = get_network_interfaces()
        
        # Determine which URL the client should use
        if client_ip in ['127.0.0.1', 'localhost']:
            return interfaces['localhost']
        
        # If client is on local network
        if interfaces['local_ip'] and (client_ip.startswith('192.168.') or client_ip.startswith('10.')):
            return interfaces['local_ip']
        
        # If client is coming through Tailscale
        if interfaces['tailscale_ip'] and ('.ts.net' in request.host or client_ip.startswith('100.')):
            return interfaces['tailscale_ip']
        
        # Fallback logic
        if interfaces['local_ip']:
            return interfaces['local_ip']
        if interfaces['tailscale_ip']:
            return interfaces['tailscale_ip']
        
        return interfaces['localhost']
    
    except Exception as e:
        logger.error(f"URL detection failed: {str(e)}")
        return "http://localhost:3000"

def grafana_dashboard_url(uid):
    """Generate complete Grafana dashboard URL with UID"""
    base_url = detect_grafana_url()
    return f"{base_url}/d/{uid}?orgId=1&refresh=10s&theme=light" if uid else None

def get_dashboard_uid_from_title(title):
    """Get dashboard UID from Grafana API"""
    try:
        base_url = detect_grafana_url()
        url = f"{base_url}/api/search?query={title}"
        response = requests.get(url, auth=(GRAFANA_USER, GRAFANA_PASS), timeout=5)
        if response.status_code == 200:
            dashboards = response.json()
            for dash in dashboards:
                if dash.get("title", "").strip().lower() == title.strip().lower():
                    uid = dash.get("uid")
                    logger.debug(f"Found UID '{uid}' for dashboard titled '{title}'")
                    return uid
            logger.warning(f"No dashboard matched title '{title}'")
        else:
            logger.error(f"Failed to fetch dashboard list: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Exception during Grafana dashboard UID fetch: {e}")
    return None

def validate_submission(form_data):
    """Validate user submission data"""
    required_fields = ['username', 'password', 'numDevices', 'numDays']
    errors = []
    
    # Check required fields
    for field in required_fields:
        if field not in form_data or not form_data[field]:
            errors.append(f"Missing required field: {field}")
    
    # Validate numeric fields
    try:
        num_devices = int(form_data.get('numDevices', 0))
        if num_devices <= 0:
            errors.append("Number of devices must be positive")
    except ValueError:
        errors.append("Invalid number of devices")
    
    try:
        num_days = int(form_data.get('numDays', 0))
        if num_days <= 0:
            errors.append("Number of days must be positive")
    except ValueError:
        errors.append("Invalid number of days")
    
    return errors if errors else None

def setup_grafana_dashboards(user_id):
    """Import Grafana dashboards after data exists and ensure dashboards exist"""
    max_retries = 5
    retry_delay = 10
    dashboards_expected = {
        "SHEMS Overview": "overview-dashboard.json",
        "Power Analysis": "power-analysis.json",
        "Energy Analysis": "energy-analysis.json",
        "Device Details": "device-details.json"
    }
    dashboard_dir = "/app/smarthome/grafana/grafana_dashboards"
    base_url = detect_grafana_url()

    for attempt in range(max_retries):
        try:
            with db_manager.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM DeviceInfo WHERE UserId = %s", (user_id,))
                    if cursor.fetchone()["COUNT(*)"] > 0:
                        logger.info("Device data available, verifying Grafana dashboards...")

                        for title, filename in dashboards_expected.items():
                            uid = get_dashboard_uid_from_title(title)
                            if uid:
                                logger.info(f"Dashboard '{title}' already exists (UID: {uid})")
                                continue

                            logger.warning(f"Dashboard '{title}' missing, importing...")
                            dashboard_path = os.path.join(dashboard_dir, filename)
                            if not os.path.exists(dashboard_path):
                                logger.error(f"Dashboard file missing: {dashboard_path}")
                                continue

                            with open(dashboard_path, 'r') as f:
                                dashboard_json = json.load(f)

                            import_payload = {
                                "dashboard": dashboard_json,
                                "overwrite": True,
                                "folderId": 0
                            }

                            response = requests.post(
                                f"{base_url}/api/dashboards/db",
                                auth=(GRAFANA_USER, GRAFANA_PASS),
                                headers={"Content-Type": "application/json"},
                                json=import_payload,
                                timeout=10
                            )

                            if response.status_code == 200 and '"status":"success"' in response.text:
                                logger.info(f"Successfully imported '{title}'")
                            else:
                                logger.error(f"Failed to import '{title}': {response.status_code} - {response.text}")

                        return True  # Success after verifying/importing all dashboards

                    logger.info(f"No device data found (attempt {attempt+1}/{max_retries})")
                    time.sleep(retry_delay)

        except Exception as e:
            logger.warning(f"Dashboard setup failed on attempt {attempt+1}: {e}")
            time.sleep(retry_delay)

    logger.error("Dashboard import timeout - no data generated or dashboards failed to import")
    return False

def check_grafana_dashboards_exist():
    """Check if dashboards exist using Grafana API"""
    try:
        base_url = detect_grafana_url()	
        grafana_url = f"http://{base_url}:3000/api/dashboards"
        response = requests.get(
            grafana_url,
            auth=('admin', 'admin'),
            timeout=5
        )
        return response.status_code == 200
    except Exception as e:
        logger.warning(f"Grafana API check failed: {str(e)}")
        return False

def verify_dashboard_data(user_id):
    """Check if data exists for dashboard rendering"""
    try:
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                # Check if user has any device data
                cursor.execute(
                    "SELECT COUNT(*) FROM DeviceUtilData WHERE DeviceId IN "
                    "(SELECT DeviceId FROM DeviceInfo WHERE UserId = %s)",
                    (user_id,)
                )
                return cursor.fetchone()[0] > 0
    except Exception as e:
        logger.error(f"Data verification failed: {str(e)}")
        return False

# ===== Decorators =====
def login_required(f):
    """Decorator to ensure user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            logger.warning("Unauthorized access attempt")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def handle_db_errors(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except MySQLError as e:
            logger.error(f"Database error in {f.__name__}: {str(e)}")
            abort(500, description="Database operation failed")
        except Exception as e:
            logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            abort(500)
    return decorated_function

# ===== Routes =====
@app.route('/')
def index():
    try:
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('shems_dashboard_input.html')
    except Exception as e:
        logger.error(f"Index route error: {str(e)}")
        return render_template('error.html'), 500

@app.route('/api/access-points')
def access_points():
    pi_ip = get_pi_ip()
    access_points = [f"http://{pi_ip}:5000"]
    
    try:
        tailscale_ip = subprocess.getoutput("tailscale ip -4").strip()
        if tailscale_ip:
            access_points.append(f"http://{tailscale_ip}:5000")
    except:
        pass
        
    return jsonify({
        'access_points': access_points,
        'tailscale_ip': tailscale_ip if 'tailscale_ip' in locals() else None
    })

@app.route('/submit', methods=['POST'])
@handle_db_errors
def submit():
    try:
        # Validate input
        if errors := validate_submission(request.form):
            logger.warning(f"Invalid submission: {errors}")
            return jsonify({"errors": errors}), 400

        username = request.form['username']
        password = request.form['password']
        num_devices = int(request.form['numDevices'])
        num_days = int(request.form['numDays'])

        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                # Check existing user
                cursor.execute(
                    "SELECT UserId, PasswordHash FROM Users WHERE Username = %s",
                    (username,)
                )
                user = cursor.fetchone()

                if user:
                    if not check_password_hash(user['PasswordHash'], password):
                        logger.warning("Invalid password attempt")
                        return jsonify({"error": "Invalid credentials"}), 401
                    user_id = user['UserId']
                else:
                    # Create new user
                    password_hash = generate_password_hash(password)
                    cursor.execute(
                        "INSERT INTO Users (Username, PasswordHash) VALUES (%s, %s)",
                        (username, password_hash)
                    )
                    user_id = cursor.lastrowid
                    conn.commit()
                    logger.info(f"Created new user {user_id}")

                # Store session
                session.permanent = True
                session['user_id'] = user_id
                session['username'] = username
                logger.debug(f"Session created for {user_id}")

                # Start data simulation
                try:
                    subprocess.Popen([
                        sys.executable,
                        os.path.join(SCRIPT_DIR, 'shems_data_simulation.py'),
                        str(user_id),
                        str(num_devices),
                        str(num_days)
                    ])
                    logger.info(f"Started simulation for user {user_id}")
                except Exception as e:
                    logger.error(f"Simulation startup failed: {str(e)}")
                    return jsonify({"error": "Data generation failed"}), 500

                # Setup dashboards after delay
                time.sleep(DASHBOARD_IMPORT_DELAY)
                setup_grafana_dashboards(user_id)

                return redirect(url_for('dashboard'))

    except Exception as e:
        logger.critical(f"Submit error: {str(e)}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user_id = session['user_id']
        grafana_url = detect_grafana_url()
        
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as count FROM DeviceInfo WHERE UserId=%s", (user_id,))
                if cursor.fetchone()['count'] == 0:
                    return render_template('error.html', message="No device data found for your account.")
        
        dashboard_uids = {
            "overview": get_dashboard_uid_from_title("SHEMS Overview"),
            "power": get_dashboard_uid_from_title("Power Analysis"),
            "energy": get_dashboard_uid_from_title("Energy Analysis"),
            "devices": get_dashboard_uid_from_title("Device Details")
        }
        if not all(dashboard_uids.values()):
            logger.error(f"Dashboard UIDs missing: {dashboard_uids}")
            return render_template("error.html", message="Dashboards are not ready. Please try again later.")
        
        def grafana_dashboard_url(uid):
            return f"{grafana_url}/d/{uid}?orgId=1&refresh=10s&theme=light" if uid else None
         # Prepare dashboard URLs with proper access method
        dashboards = {
            'grafana_overview_url': grafana_dashboard_url(dashboard_uids["overview"]),
            'grafana_power_url': grafana_dashboard_url(dashboard_uids["power"]),
            'grafana_energy_url': grafana_dashboard_url(dashboard_uids["energy"]),
            'grafana_devices_url': grafana_dashboard_url(dashboard_uids["devices"]),
            'available_urls': get_network_interfaces()  # For debugging
        }                           
        return render_template('shems_dashboard_visuals.html', **dashboards)

    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        return render_template('error.html', message="Dashboard failed to load."), 500

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/api/user-data')
@login_required
def api_user_data():
    try:
        user_id = session['user_id']
        username = session['username']
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) as count FROM DeviceInfo WHERE UserId=%s", (user_id,))
                total_devices = cursor.fetchone()['count']

                cursor.execute("SELECT SEC_TO_TIME(TIMESTAMPDIFF(SECOND, MIN(dud.Timestamp), MAX(dud.Timestamp))) AS active FROM DeviceUtilData dud JOIN DeviceInfo di ON dud.DeviceId = di.DeviceId WHERE di.UserId=%s AND dud.Status = 'ON'", (user_id,))
                active_devices = cursor.fetchone()['active']
                if isinstance(active_devices,timedelta) :
                    active_devices =str(active_devices)

                cursor.execute("SELECT SUM(Power_Consmpt) as power, SUM(Energy) as energy FROM DeviceUtilData dud JOIN DeviceInfo di ON dud.DeviceId=di.DeviceId WHERE di.UserId=%s", (user_id,))
                result = cursor.fetchone()

        return jsonify({
            "username": username,
            "total_devices": total_devices,
            "active_devices": active_devices,
            "total_power": result['power'] or 0,
            "total_energy": result['energy'] or 0,
            "grafana_overview_url": grafana_dashboard_url(get_dashboard_uid_from_title("SHEMS Overview")),
            "grafana_power_url": grafana_dashboard_url(get_dashboard_uid_from_title("Power Analysis")),
            "grafana_energy_url": grafana_dashboard_url(get_dashboard_uid_from_title("Energy Analysis")),
            "grafana_devices_url": grafana_dashboard_url(get_dashboard_uid_from_title("Device Details"))
        })
    except Exception as e:
        logger.error(f"User data fetch failed: {str(e)}")
        return jsonify({"error": "Data unavailable"}), 500

# ===== Main Execution =====
def safe_shutdown(signum, frame):
    """Handle shutdown signals gracefully"""
    logger.info("Received shutdown signal, terminating...")
    sys.exit(0)

def main():
    try:
        import signal
        signal.signal(signal.SIGINT, safe_shutdown)
        signal.signal(signal.SIGTERM, safe_shutdown)

        try:
            subprocess.run(
                ['pkill', '-f', f'python.*shems_monitoring_server.py', f'--exclude={current_pid}'],
                stderr=subprocess.DEVNULL,
                timeout=5
            )
        except subprocess.TimeoutExpired:
            logger.warning("Process cleanup timed out")
        except Exception as e:
            logger.warning(f"Process cleanup failed: {str(e)}")

        try:
            test_conn = db_manager.get_connection()
            test_conn.close()
        except Exception as e:
            logger.critical(f"Startup database test failed: {str(e)}")
            sys.exit(1)

        logger.info(f"Starting SHEMS server on port 5000 (PID: {current_pid})")
        app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)

    except Exception as e:
        logger.critical(f"Fatal startup error: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()

