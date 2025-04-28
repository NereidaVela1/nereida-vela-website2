import os
import json
import time
from datetime import datetime, timedelta
import random
from collections import defaultdict
import requests
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
from firebase_admin import credentials, db, initialize_app, messaging
import threading
import queue
from concurrent.futures import ThreadPoolExecutor
import numpy as np
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from scapy.all import sniff, IP
import ipaddress
import re
# import json
# try:
#     with open("serviceAccountKey.json", "r") as f:
#         data = json.load(f)
#     print("JSON is valid:", data["project_id"])
# except json.JSONDecodeError as e:
#     print("JSON error:", str(e))
# except FileNotFoundError:
#     print("File not found: serviceAccountKey.json")
# Load environment variables
load_dotenv()
from dotenv import load_dotenv
import os
try:
    load_dotenv()
    print("SERVER_NAME:", os.getenv("SERVER_NAME"))
    print("FLASK_DEBUG:", os.getenv("FLASK_DEBUG"))
    print("ABUSEIPDB_API_KEY:", os.getenv("ABUSEIPDB_API_KEY"))
    print("IPINFO_API_KEY:", os.getenv("IPINFO_API_KEY"))
    print("FIREBASE_DATABASE_URL:", os.getenv("FIREBASE_DATABASE_URL"))
    print("APP_SECRET:", os.getenv("APP_SECRET"))
except Exception as e:
    print("Error loading .env:", str(e))
# Flask Setup
app = Flask(__name__)
CORS(app, resources={r"/fraud_data": {"origins": "*"}, r"/paysim_analysis": {"origins": "*"}, r"/leaderboard": {"origins": "*"}},
     supports_credentials=True)

# Logging Setup
logging.basicConfig(filename="nsfr.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

# Firebase Setup
try:
    if not os.path.exists("serviceAccountKey.json"):
        logger.error("serviceAccountKey.json not found")
        raise FileNotFoundError("serviceAccountKey.json not found")
    cred = credentials.Certificate("serviceAccountKey.json")
    initialize_app(cred, {"databaseURL": os.getenv("FIREBASE_DATABASE_URL", "https://nsfr-fraud-tracker-default-rtdb.firebaseio.com/")})
    logger.info("Firebase initialized successfully")
except Exception as e:
    logger.error(f"Firebase initialization failed: {e}")
    raise SystemExit(f"Firebase initialization failed: {e}")

firebase_ref = db.reference("fraud_events")
training_ref = db.reference("training_data")
authority_ref = db.reference("authority_reports")
retry_ref = db.reference("retry_queue")
ip_locations_ref = db.reference("ip_locations")

# Configuration
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
GEO_API_KEY = os.getenv("IPINFO_API_KEY")
if not API_KEY or not GEO_API_KEY:
    logger.error("Missing API keys for AbuseIPDB or IPinfo")
    raise ValueError("ABUSEIPDB_API_KEY and IPINFO_API_KEY must be set in .env")
APP_SECRET = os.getenv("APP_SECRET", "nsfr-secret-2025")
APP_SECRET_HASH = generate_password_hash(APP_SECRET)
URL = "https://api.abuseipdb.com/api/v2/check"
LOG_PATH = "nsfr.log"
MODEL_PATH = "fraud_model.pkl"
ACCESS_LOG_PATH = "access.log"
CACHE_PATH = "ip_cache.json"
BLOCKED_IPS_FILE = "blocked_ips.json"

SATELLITE_LOCATIONS = {
    "North America": {"lat": 37.0902, "lon": -95.7129},
    "Europe": {"lat": 54.5260, "lon": 15.2551},
    "Asia": {"lat": 34.0479, "lon": 100.6197},
    "South America": {"lat": -8.7832, "lon": -55.4915},
    "Africa": {"lat": 6.6111, "lon": 20.9394},
    "Australia": {"lat": -25.2744, "lon": 133.7751},
    "Germany": {"lat": 51.1657, "lon": 10.4515},
    "Unknown": {"lat": 0.0, "lon": 0.0}
}
MEMES = [
    "https://i.imgflip.com/1g8my4.jpg",
    "https://i.imgflip.com/2fm6x.jpg",
    "https://i.imgflip.com/1ur9b0.jpg",
    "https://i.imgflip.com/4/3ggw.jpg"
]
FRAUDSTER_IPS = [
    "65.25.30.171", "23.244.98.115", "75.188.143.217", "174.207.99.249",
    "174.207.105.89", "187.72.178.126", "107.72.179.126", "168.149.160.68",
    "168.149.133.172", "208.184.162.167", "48.24.144.38", "107.115.108.62",
    "107.115.112.61", "107.115.112.23", "107.115.108.25"
]

logger.info("NSFR 2.0 started! Ready to squash those frequent flyer fraudsters!")

# Rate Limiting Setup
request_counts = defaultdict(list)
RATE_LIMIT = 100
RATE_WINDOW = 15 * 60
cache_lock = threading.Lock()  # Lock for cache file access

def rate_limit(f):
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        now = time.time()
        request_counts[ip] = [t for t in request_counts[ip] if now - t < RATE_WINDOW]
        if len(request_counts[ip]) >= RATE_LIMIT:
            logger.warning(f"Rate limit exceeded for IP {ip}")
            return jsonify({"error": "Rate limit exceeded"}), 429
        request_counts[ip].append(now)
        return f(*args, **kwargs)
    # Preserve the original function's name as the endpoint
    decorated_function.__name__ = f.__name__
    return decorated_function

def authenticate_request():
    auth_header = request.headers.get("X-API-Key")
    if not auth_header or not check_password_hash(APP_SECRET_HASH, auth_header):
        logger.warning(f"Unauthorized access attempt from {request.remote_addr}")
        return False
    return True

def sanitize_input(value):
    if not isinstance(value, str):
        return value
    return ''.join(c for c in value if c.isalnum() or c in ' .-,:')

def is_valid_ip(ip):
    """Validate IP address format."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def train_ml_model():
    try:
        training_data = training_ref.get()
        if not training_data:
            logger.warning("No training data in Firebase, using default data")
            data = pd.DataFrame({
                "score": [80, 10, 60, 5],
                "frequency": [5, 1, 3, 1],
                "location": ["North America", "Europe", "Asia", "Europe"],
                "total_reports": [10, 0, 5, 0],
                "hourly_freq": [3, 1, 2, 0],
                "label": [1, 0, 1, 0]
            })
        else:
            data = pd.DataFrame(training_data.values())

        X = data[["score", "frequency", "location", "total_reports", "hourly_freq"]].copy()
        X.loc[:, "location"] = LabelEncoder().fit_transform(data["location"])
        y = data["label"]

        model = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
        model.fit(X, y)
        joblib.dump(model, MODEL_PATH)
        logger.info("ML model trained and saved")
        return model
    except Exception as e:
        logger.error(f"ML training failed: {e}")
        return None

def load_ml_model():
    try:
        if os.path.exists(MODEL_PATH):
            model = joblib.load(MODEL_PATH)
            logger.info("ML model loaded from file")
            return model
        logger.info("No ML model found, training new model")
        return train_ml_model()
    except Exception as e:
        logger.error(f"Failed to load ML model: {e}")
        return None

def retrain_model_periodically():
    while True:
        train_ml_model()
        time.sleep(24 * 3600)  # Retrain daily

def get_location(ip):
    if not is_valid_ip(ip):
        logger.warning(f"Invalid IP format: {ip}")
        return "Unknown", 0.0, 0.0
    try:
        cached = ip_locations_ref.child(ip.replace(".", "_")).get()
        if cached:
            logger.info(f"Using cached geolocation for IP {ip}")
            return cached["name"], cached["lat"], cached["lon"]

        response = requests.get(f"https://ipinfo.io/{ip}/json?token={GEO_API_KEY}", timeout=5)
        response.raise_for_status()
        data = response.json()
        country = data.get('country', 'Unknown')
        loc = data.get('loc', '0,0').split(',')
        lat = float(loc[0]) if loc[0] else 0.0
        lon = float(loc[1]) if loc[1] else 0.0
        if country == "AU":
            name = "Australia"
        elif country == "DE":
            name = "Germany"
        elif country == "US":
            name = "North America"
        else:
            name = f"{data.get('city', 'Unknown')}, {country}"

        ip_locations_ref.child(ip.replace(".", "_")).set({"name": name, "lat": lat, "lon": lon})
        logger.info(f"Geolocation saved for IP {ip}: {name}")
        return name, lat, lon
    except Exception as e:
        logger.warning(f"Geolocation failed for IP {ip}: {e}")
        return "Unknown", 0.0, 0.0

def load_blocked_ips():
    if os.path.exists(BLOCKED_IPS_FILE):
        with open(BLOCKED_IPS_FILE, "r") as f:
            return json.load(f)
    return []

def save_blocked_ips(ips):
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(ips, f)

def block_ip(ip, platform="linux"):
    if not is_valid_ip(ip):
        logger.error(f"Invalid IP for blocking: {ip}")
        return
    try:
        blocked_ips = load_blocked_ips()
        if ip not in blocked_ips:
            blocked_ips.append(ip)
            save_blocked_ips(blocked_ips)
            if platform == "linux":
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                os.system(f"iptables -A INPUT -s {ip} -j LOG --log-prefix 'NSFR_FRAUD_BLOCK: '")
                logger.info(f"Blocked IP {ip} with iptables: Priority fraudster grounded!")
            elif platform == "windows":
                # Sanitize IP to prevent command injection
                safe_ip = re.sub(r'[^\d.]', '', ip)
                os.system(f"netsh advfirewall firewall add rule name='NSFR_Block_{safe_ip}' dir=in action=block remoteip={safe_ip}")
                logger.info(f"Blocked IP {ip} with Windows Firewall: Priority fraudster locked out!")
            else:
                logger.warning(f"Unsupported platform for firewall rules: {platform}")
    except Exception as e:
        logger.error(f"Failed to block IP {ip}: {e}")

def send_fcm_notification(ip, risk_level, location):
    try:
        message = messaging.Message(
            notification=messaging.Notification(
                title=f"New Fraudster Detected: {ip}",
                body=f"Risk: {risk_level}, Location: {location}"
            ),
            topic="fraud_alerts"
        )
        messaging.send(message)
        logger.info(f"FCM notification sent for IP {ip}")
    except Exception as e:
        logger.error(f"Failed to send FCM notification for IP {ip}: {e}")

def cleanup_old_events():
    try:
        cutoff = datetime.now() - timedelta(days=30)
        # Use query to limit data retrieval
        events = firebase_ref.order_by_child("timestamp").end_at(cutoff.isoformat()).get()
        if events:
            for key, event in events.items():
                firebase_ref.child(key).delete()
                logger.info(f"Deleted old event for IP {event['ip']}")
    except Exception as e:
        logger.error(f"Failed to clean up old events: {e}")

class FraudTracker:
    def __init__(self):
        self.ip_history = defaultdict(list)
        self.ip_locations = {}
        self.ml_model = load_ml_model()
        if self.ml_model is None:
            logger.error("ML model initialization failed")
            raise SystemExit("ML model initialization failed")
        self.ip_queue = queue.Queue(maxsize=100)
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.known_ips = set(load_blocked_ips())

    def capture_ips(self, interface=None, count=100):
        if not interface:
            from scapy.config import conf
            interface = conf.iface  # Use default interface
        try:
            packets = sniff(iface=interface, count=count, timeout=10)
            return [pkt[IP].src for pkt in packets if IP in pkt and pkt[IP].src not in self.known_ips]
        except Exception as e:
            logger.error(f"Failed to capture IPs on interface {interface}: {e}")
            return []

    def fetch_ips_from_log(self, log_path=ACCESS_LOG_PATH):
        ips = []
        logger.info(f"Fetching IPs from {log_path}")
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logger.warning("access.log is empty, adding fraudster IPs")
                    with open(log_path, 'a') as f:
                        for ip in FRAUDSTER_IPS:
                            f.write(
                                f"{ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET / HTTP/1.1\" 200 -\n")
                    content = open(log_path).read()
                for line in content.splitlines():
                    parts = line.split()
                    if parts and is_valid_ip(parts[0]):
                        ip = parts[0]
                        ips.append(ip)
                        location, lat, lon = get_location(ip)
                        self.ip_locations[ip] = {"name": location, "lat": lat, "lon": lon}
                        try:
                            self.ip_queue.put(ip, timeout=1)
                        except queue.Full:
                            logger.warning(f"Queue full, skipping IP: {ip}")
            network_ips = self.capture_ips()
            ips.extend(network_ips)
            return list(set(ips))
        except FileNotFoundError:
            logger.warning(f"{log_path} not found, creating with fraudster IPs")
            with open(log_path, 'w') as f:
                for ip in FRAUDSTER_IPS:
                    f.write(
                        f"{ip} - - [{datetime.now().strftime('%d/%b/%Y:%H:%M:%S +0000')}] \"GET / HTTP/1.1\" 200 -\n")
            return self.fetch_ips_from_log(log_path)
        except Exception as e:
            logger.error(f"Failed to read {log_path}: {e}")
            return []

    def _fetch_ip_from_api(self, ip):
        if not is_valid_ip(ip):
            logger.warning(f"Invalid IP for API check: {ip}")
            return {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}
        headers = {"Key": API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        retries = 3
        backoff = 2
        for attempt in range(retries):
            try:
                response = requests.get(URL, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                result = response.json()
                logger.info(f"API response for {ip}: {result}")
                return result
            except requests.RequestException as e:
                if hasattr(e.response, 'status_code') and e.response.status_code == 429:
                    logger.warning(f"429 Too Many Requests for IP {ip}, retrying in {backoff}s...")
                    time.sleep(backoff)
                    backoff *= 2
                else:
                    logger.error(f"Error checking IP {ip}: {e}")
                    break
        return {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}

    def check_ip(self, ip):
        try:
            if not os.path.exists(CACHE_PATH):
                logger.info(f"Creating {CACHE_PATH}")
                with cache_lock:
                    with open(CACHE_PATH, 'w') as f:
                        json.dump({}, f)
            with cache_lock:
                with open(CACHE_PATH, 'r') as f:
                    cache = json.load(f)
                if ip in cache and time.time() - cache[ip]["timestamp"] < 86400:
                    logger.info(f"Using cached result for IP: {ip}")
                    return cache[ip]["data"]
                result = self._fetch_ip_from_api(ip)
                cache[ip] = {"data": result, "timestamp": time.time()}
                with open(CACHE_PATH, 'w') as f:
                    json.dump(cache, f)
            return result
        except Exception as e:
            logger.error(f"Failed to check IP {ip}: {e}")
            return {"data": {"abuseConfidenceScore": 0, "totalReports": 0}}

    def process_queue(self):
        logger.info(f"Processing queue, size: {self.ip_queue.qsize()}")
        high_risk_ips = []
        try:
            while not self.ip_queue.empty():
                ip = self.ip_queue.get()
                result = self.check_ip(ip)
                risk, fraud_types, meme = self.detect_fraud(ip, result)
                if risk in ["high_risk", "medium_risk"]:
                    location_info = self.ip_locations.get(ip, {"name": "Unknown", "lat": 0.0, "lon": 0.0})
                    score = result["data"].get("abuseConfidenceScore", 0)
                    self.save_to_firebase(ip, risk, fraud_types, location_info["name"], meme, score, result)
                    high_risk_ips.append({
                        "ip": ip,
                        "location": location_info["name"],
                        "meme": meme or "",
                        "lat": location_info["lat"],
                        "lon": location_info["lon"],
                        "victim_note": f"Priority Fraudster {ip} caught!" if ip in FRAUDSTER_IPS else "",
                        "risk_level": risk,
                        "fraud_types": fraud_types  # Store fraud_types for /fraud_data
                    })
                    if ip in FRAUDSTER_IPS or len([t for t in self.ip_history[ip] if time.time() - t < 86400]) > 3:
                        block_ip(ip, platform="windows" if os.name == "nt" else "linux")
                self.ip_queue.task_done()
        except Exception as e:
            logger.error(f"Queue processing failed: {e}")
        return high_risk_ips

    def detect_fraud(self, ip, ip_data):
        try:
            if not ip_data or "data" not in ip_data:
                logger.warning(f"No valid data for IP {ip}")
                return "low_risk", {"xss": 0, "sms": 0, "email": 0, "wechat": 0, "upi": 0}, None

            score = ip_data["data"].get("abuseConfidenceScore", 0)
            total_reports = ip_data["data"].get("totalReports", 0)
            current_time = time.time()
            self.ip_history[ip].append(current_time)
            self.ip_history[ip] = [t for t in self.ip_history[ip] if current_time - t < 300]
            frequency = len(self.ip_history[ip])
            hourly_freq = sum(1 for t in self.ip_history[ip] if current_time - t < 3600)
            location = self.ip_locations.get(ip, {"name": "Unknown"})["name"]

            input_data = pd.DataFrame([{
                "score": score,
                "frequency": frequency,
                "location": location,
                "total_reports": total_reports,
                "hourly_freq": hourly_freq
            }]).copy()
            input_data.loc[:, "location"] = LabelEncoder().fit_transform([location])
            prediction = self.ml_model.predict_proba(input_data)[0][1] if self.ml_model else 0.0

            fraud_types = {"xss": 0, "sms": 0, "email": 0, "wechat": 0, "upi": 0}
            meme = None
            if ip in FRAUDSTER_IPS:
                fraud_types["xss"] = 1
                fraud_types["sms"] = 1
                fraud_types["email"] = 1
                meme = random.choice(MEMES)
                self.executor.submit(self.report_to_authorities, ip, location, f"Priority Fraudster {ip} caught by NSFR: {meme}")
                send_fcm_notification(ip, "high_risk", location)
                return "high_risk", fraud_types, meme
            elif prediction > 0.5 or score > 50:
                fraud_types["xss"] = 1 if random.random() > 0.5 else 0
                fraud_types["sms"] = 1 if (hourly_freq > 4 or location in ["Asia", "Africa"]) else 0
                fraud_types["email"] = 1 if (prediction > 0.6 or location in ["North America", "Europe"]) else 0
                fraud_types["wechat"] = 1 if (frequency > 3 and location == "Asia") else 0
                fraud_types["upi"] = 1 if (prediction > 0.7 and location == "India") else 0
                meme = random.choice(MEMES)
                self.executor.submit(self.report_to_authorities, ip, location, f"Fraud detected by NSFR: {meme}")
                if prediction > 0.7:
                    send_fcm_notification(ip, "high_risk", location)
                return "high_risk", fraud_types, meme
            elif prediction > 0.3:
                fraud_types["xss"] = 1 if random.random() > 0.7 else 0
                fraud_types["sms"] = 1 if frequency > 3 else 0
                return "medium_risk", fraud_types, None
            return "low_risk", fraud_types, None
        except Exception as e:
            logger.error(f"Fraud detection failed for IP {ip}: {e}")
            return "low_risk", {"xss": 0, "sms": 0, "email": 0, "wechat": 0, "upi": 0}, None

    def report_to_authorities(self, ip, location, comment):
        if not is_valid_ip(ip):
            logger.error(f"Invalid IP for reporting: {ip}")
            return False
        try:
            headers = {"Key": API_KEY, "Accept": "application/json"}
            data = {"ip": ip, "categories": "18", "comment": comment}
            retries = 5
            backoff = 5
            for attempt in range(retries):
                try:
                    response = requests.post("https://api.abuseipdb.com/api/v2/report", headers=headers, data=data, timeout=10)
                    response.raise_for_status()
                    logger.info(f"Reported IP {ip} to AbuseIPDB: {response.json()}")
                    authority_ref.child(ip.replace(".", "_")).set({
                        "ip": ip,
                        "location": location,
                        "timestamp": datetime.now().isoformat(),
                        "comment": comment
                    })
                    return True
                except requests.RequestException as e:
                    if hasattr(e.response, 'status_code') and e.response.status_code == 429:
                        logger.warning(f"429 Too Many Requests for IP {ip}, retrying in {backoff}s...")
                        time.sleep(backoff)
                        backoff *= 2
                    else:
                        logger.error(f"Failed to report IP {ip}: {e}")
                        raise
            logger.warning(f"Max retries reached for IP {ip}, adding to retry queue")
            retry_ref.child(ip.replace(".", "_")).set({
                "ip": ip,
                "location": location,
                "timestamp": datetime.now().isoformat()
            })
            logger.info(f"Added IP {ip} to Firebase retry queue")
            return False
        except Exception as e:
            logger.error(f"Failed to process IP {ip} report: {e}")
            return False

    def save_to_firebase(self, ip, risk, fraud_types, location, meme, score, ip_data, victim_note=None):
        try:
            timestamp = datetime.now().isoformat()
            data = {
                "ip": sanitize_input(ip),
                "risk_level": risk,
                "xss": fraud_types["xss"],
                "sms": fraud_types["sms"],
                "email": fraud_types["email"],
                "wechat": fraud_types["wechat"],
                "upi": fraud_types["upi"],
                "location": sanitize_input(location),
                "lat": self.ip_locations.get(ip, {"lat": 0.0})["lat"],
                "lon": self.ip_locations.get(ip, {"lon": 0.0})["lon"],
                "timestamp": timestamp,
                "meme": meme or "",
                "victim_note": sanitize_input(victim_note) if victim_note else f"Priority Fraudster {ip} caught!" if ip in FRAUDSTER_IPS else "Frequent flyer caught by NSFR 2.0!",
                "status": "pending"
            }
            firebase_ref.child(ip.replace(".", "_")).set(data)
            training_ref.push({
                "score": score,
                "frequency": len(self.ip_history[ip]),
                "location": location,
                "total_reports": ip_data["data"].get("totalReports", 0),
                "hourly_freq": sum(1 for t in self.ip_history[ip] if time.time() - t < 3600),
                "label": 1 if risk in ["high_risk", "medium_risk"] else 0
            })
            logger.info(f"Saved IP {ip} to Firebase: Fraudster tears collected!")
        except Exception as e:
            logger.error(f"Failed to save IP {ip} to Firebase: {e}")

    def process_paysim_datasets(self):
        try:
            # Placeholder for PaySim dataset processing
            logger.info("Processing PaySim datasets for DAT 223 fraud analysis")
            # TODO: Implement PaySim dataset processing logic
            return {"status": "success"}
        except Exception as e:
            logger.error(f"PaySim processing failed: {e}")
            return {"status": "error"}

# Flask Routes
@app.route("/fraud_data")
@rate_limit
def get_fraud_data():
    if not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    tracker = FraudTracker()
    high_risk_ips = tracker.process_queue()
    response = {
        "total": len(high_risk_ips),
        "xss": sum(1 for ip in high_risk_ips if ip["fraud_types"]["xss"]),
        "sms_xss": sum(1 for ip in high_risk_ips if ip["fraud_types"]["sms"]),
        "email_xss": sum(1 for ip in high_risk_ips if ip["fraud_types"]["email"]),
        "wechat_xss": sum(1 for ip in high_risk_ips if ip["fraud_types"]["wechat"]),
        "upi_fraud": sum(1 for ip in high_risk_ips if ip["fraud_types"]["upi"]),
        "live_trapped": len(high_risk_ips),
        "high_risk_ips": high_risk_ips,
        "top_fraud": "xss" if high_risk_ips and any(ip["fraud_types"]["xss"] for ip in high_risk_ips) else "none",
        "top_region": high_risk_ips[0]["location"] if high_risk_ips else "Unknown"
    }
    return jsonify(response)

@app.route("/leaderboard")
@rate_limit
def get_leaderboard():
    if not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    events = firebase_ref.order_by_child("ip").limit_to_last(100).get()  # Limit to 100 events
    if not events:
        return jsonify({"entries": []})
    ip_counts = defaultdict(int)
    ip_locations = {}
    for key, event in events.items():
        ip_counts[event["ip"]] += 1
        ip_locations[event["ip"]] = event["location"]
    leaderboard = [
        {"ip": ip, "count": count, "location": ip_locations[ip]}
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    ]
    return jsonify({"entries": leaderboard})

@app.route("/paysim_analysis")
@rate_limit
def paysim_analysis():
    if not authenticate_request():
        return jsonify({"error": "Unauthorized"}), 401
    tracker = FraudTracker()
    result = tracker.process_paysim_datasets()
    return jsonify(result)

# Initialize background tasks
def start_background_tasks():
    threading.Thread(target=retrain_model_periodically, daemon=True).start()
    threading.Thread(target=cleanup_old_events, daemon=True).start()

if __name__ == "__main__":
    blocked_ips = load_blocked_ips()
    for ip in blocked_ips:
        block_ip(ip, platform="windows" if os.name == "nt" else "linux")
    start_background_tasks()
    app.run(host="0.0.0.0", port=5000, debug=False)