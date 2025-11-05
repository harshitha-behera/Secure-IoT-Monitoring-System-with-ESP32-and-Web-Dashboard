import os, base64, json, time, threading
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import bcrypt
import requests

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ------------------------ App Setup ------------------------
load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///iot.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

# --------------- Models ---------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary, nullable=False)
    role = db.Column(db.String(20), default='User')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Reading(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), nullable=False)
    # Stored encrypted payload and IV (base64)
    ciphertext_b64 = db.Column(db.Text, nullable=False)
    iv_b64 = db.Column(db.String(64), nullable=False)
    ts = db.Column(db.Integer, default=lambda:int(time.time()))

class Threshold(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), nullable=False)
    value = db.Column(db.Float, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# --------------- Auth helpers ---------------
def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return _wrap

def hash_pw(pw:str)->bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_pw(pw:str, hashed:bytes)->bool:
    try:
        return bcrypt.checkpw(pw.encode(), hashed)
    except Exception:
        return False

# --------------- Crypto helpers ---------------
KEY_B64 = os.environ.get('AES256_KEY_B64', '')
if KEY_B64:
    AES_KEY = base64.b64decode(KEY_B64)
else:
    # fallback dev key
    AES_KEY = b'0123456789abcdef0123456789abcdef'

def encrypt_dict(d:dict):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = json.dumps(d).encode()
    # PKCS7 pad
    pad = 16 - (len(pt) % 16)
    pt += bytes([pad])*pad
    ct = cipher.encrypt(pt)
    return base64.b64encode(ct).decode(), base64.b64encode(iv).decode()

def decrypt_payload(ciphertext_b64:str, iv_b64:str)->dict:
    ct = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    pad = pt[-1]
    pt = pt[:-pad]
    return json.loads(pt.decode())

# --------------- Socket.IO connection tracking ---------------
active_sids = set()
@socketio.on('connect')
def on_connect():
    active_sids.add(request.sid)

@socketio.on('disconnect')
def on_disconnect():
    active_sids.discard(request.sid)

# --------------- Routes: Auth ---------------
@app.get('/')
def home():
    if session.get('user_id'):
        return redirect('/dashboard/live')
    return redirect('/login')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        u = request.form.get('username','').strip()
        p = request.form.get('password','')
        if not u or not p:
            return render_template('signup.html', error='Missing fields')
        if User.query.filter_by(username=u).first():
            return render_template('signup.html', error='User already exists')
        role = 'Super Admin' if User.query.count()==0 else 'User'
        user = User(username=u, password_hash=hash_pw(p), role=role)
        db.session.add(user); db.session.commit()
        session['user_id']=user.id
        return redirect('/dashboard/live')
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u = request.form.get('username','')
        p = request.form.get('password','')
        user = User.query.filter_by(username=u).first()
        if not user or not check_pw(p, user.password_hash):
            return render_template('login.html', error='Invalid credentials')
        session['user_id']=user.id
        return redirect('/dashboard/live')
    return render_template('login.html')

@app.get('/logout')
def logout():
    session.clear()
    return redirect('/login')

def current_user():
    if not session.get('user_id'): return None
    return User.query.get(session['user_id'])

# --------------- Views: Dashboards ---------------
@app.get('/dashboard/live')
@login_required
def dashboard_live():
    return render_template('dashboard_live.html')

@app.get('/dashboard/analytics')
@login_required
def dashboard_analytics():
    return render_template('dashboard_analytics.html')

# --------------- Device ingestion ---------------
@app.post('/ingest')
def ingest():
    j = request.get_json(force=True, silent=True) or {}
    device_id = j.get('device_id', 'esp32-01')
    ciphertext_b64 = j.get('ciphertext')
    iv_b64 = j.get('iv')
    if not ciphertext_b64 or not iv_b64:
        return jsonify(ok=False, error='missing ciphertext/iv'), 400

    # store encrypted
    r = Reading(device_id=device_id, ciphertext_b64=ciphertext_b64, iv_b64=iv_b64, ts=int(time.time()))
    db.session.add(r); db.session.commit()

    # decrypt for broadcasting
    try:
        data = decrypt_payload(ciphertext_b64, iv_b64)
        data['ts'] = data.get('ts', int(time.time()))
    except Exception as e:
        data = {'temp': None, 'hum': None, 'ts': int(time.time())}
    socketio.emit('reading', {'temp': data.get('temp', 0), 'hum': data.get('hum',0), 'ts': data.get('ts', int(time.time()))})

    # threshold logic
    th = Threshold.query.filter_by(device_id=device_id).first()
    blink = False
    if th and th.value is not None and data.get('temp') is not None:
        if float(data['temp']) > float(th.value):
            blink = True

    return jsonify(ok=True, blink=blink)

# --------------- APIs used by UI ---------------
@app.get('/api/search')
@login_required
def api_search():
    op = request.args.get('op', 'above')
    val = float(request.args.get('val', '0'))
    q = Reading.query.order_by(Reading.id.desc()).limit(500).all()

    items, skipped = [], 0
    for row in reversed(q):
        try:
            d = decrypt_payload(row.ciphertext_b64, row.iv_b64)
            temp = float(d.get('temp'))
            hum  = float(d.get('hum'))
            ts   = int(d.get('ts', row.ts))
        except Exception:
            skipped += 1
            continue

        cond = (temp > val) if op == 'above' else (temp < val)
        if cond:
            items.append({'ts': ts, 'temp': temp, 'hum': hum, 'device_id': row.device_id})

    return jsonify(items=items[:100], skipped=skipped)


@app.route('/api/threshold', methods=['POST','DELETE'])
@login_required
def api_threshold():
    device_id = request.json.get('device_id','esp32-01') if request.method=='POST' else 'esp32-01'
    th = Threshold.query.filter_by(device_id=device_id).first()
    if request.method=='DELETE':
        if th: 
            th.value=None; db.session.commit()
        return jsonify(ok=True)
    value = float(request.json.get('value'))
    if not th:
        th = Threshold(device_id=device_id, value=value, user_id=session.get('user_id'))
        db.session.add(th)
    else:
        th.value = value; th.user_id=session.get('user_id')
    db.session.commit()
    return jsonify(ok=True, value=value)

# Weather proxy with simple caching
_weather_cache = {}
@app.get('/api/weather')
@login_required
def api_weather():
    city = request.args.get('city', 'Hyderabad')
    now = time.time()
    if city in _weather_cache and now - _weather_cache[city]['ts'] < 600:
        return jsonify(ok=True, data=_weather_cache[city]['data'])
    key = os.environ.get('WEATHER_API_KEY', '')
    if not key:
        return jsonify(ok=False, error='API key missing')

    try:
        resp = requests.get(
            'https://api.weatherapi.com/v1/current.json',
            params={'key': key, 'q': city, 'aqi': 'no'},
            timeout=8
        )
        if resp.status_code != 200:
            return jsonify(ok=False, error=f"HTTP {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        _weather_cache[city] = {'ts': now, 'data': data}
        return jsonify(ok=True, data=data)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.get('/api/analytics')
@login_required
def api_analytics():
    last = Reading.query.order_by(Reading.id.desc()).first()
    last_pack = None
    if last:
        try:
            dec = decrypt_payload(last.ciphertext_b64, last.iv_b64)
            last_pack = {
                'ciphertext': last.ciphertext_b64,
                'decrypted': dec
            }
        except Exception:
            last_pack = {'ciphertext': last.ciphertext_b64, 'decrypted': {}}
    return jsonify(total_records=Reading.query.count(), active_connections=len(active_sids), last=last_pack)

@app.get('/api/profile')
@login_required
def api_profile():
    u = current_user()
    return jsonify(username=u.username, role=u.role)

# --------------- CLI helper ---------------
@app.cli.command('init-db')
def init_db():
    db.create_all()
    print('DB initialized')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    print('Starting Secure IoT server on http://127.0.0.1:8888')
    socketio.run(app, host='0.0.0.0', port=8888)
