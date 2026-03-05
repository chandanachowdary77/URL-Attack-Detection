from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import os
from URLidentification.backend.attack_detector import URLAttackDetector
from URLidentification.backend.database import AttackDatabase
from URLidentification.backend.dataset_generator import AttackDatasetGenerator
import json
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'your-secret-key-change-in-production'  # Change this in production!

# Initialize components
detector = URLAttackDetector()
db = AttackDatabase()
generator = AttackDatasetGenerator()

# Simple in-memory user storage (in production, use a proper database)
users_db = {
    'admin': {'password': generate_password_hash('admin123'), 'email': 'admin@example.com'},
    'user1': {'password': generate_password_hash('user123'), 'email': 'user1@example.com'}
}

# Create uploads folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ===== AUTHENTICATION DECORATORS & HELPERS =====

def login_required(f):
    """Decorator to check if user is logged in"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Get current logged-in user"""
    return session.get('username', None)

# ===== AUTHENTICATION ROUTES =====

@app.route('/landing')
def landing():
    """Landing page with Login and Sign Up buttons"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/')
def index():
    """Home route - redirects to landing or dashboard"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('landing'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        error = None
        
        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'
        elif username not in users_db:
            error = 'Invalid username'
        elif not check_password_hash(users_db[username]['password'], password):
            error = 'Invalid password'
        
        if error is None:
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        
        return render_template('login.html', error=error)
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        error = None
        
        if not username:
            error = 'Username is required'
        elif len(username) < 3:
            error = 'Username must be at least 3 characters'
        elif username in users_db:
            error = 'Username already exists'
        elif not email:
            error = 'Email is required'
        elif not password:
            error = 'Password is required'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters'
        elif password != confirm_password:
            error = 'Passwords do not match'
        
        if error is None:
            # Create new user
            users_db[username] = {
                'password': generate_password_hash(password),
                'email': email
            }
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        
        return render_template('signup.html', error=error, username=username, email=email)
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    return redirect(url_for('landing'))

# ===== PROTECTED DASHBOARD & ANALYSIS ROUTES =====

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        stats = db.get_statistics()
        recent_attacks = db.get_attacks(limit=10)
    except:
        stats = {'total_attacks': 0, 'malicious_attacks': 0, 'successful_attacks': 0, 'attack_types': {}, 'severity_distribution': {}}
        recent_attacks = []
    return render_template('dashboard.html', stats=stats, recent_attacks=recent_attacks)

@app.route('/analyze', methods=['GET', 'POST'])
@login_required
def analyze():
    """Analyze URL page"""
    result = None
    url = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            result = detector.analyze_url(url)
            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'attack_type': result['attacks_detected'][0]['type'] if result['attacks_detected'] else 'none',
                'is_malicious': result['is_malicious'],
                'severity': result['severity'],
                'confidence': result['confidence']
            }
            db.insert_attack(attack_data)
    return render_template('analyze.html', result=result, url=url)

@app.route('/attacks', methods=['GET'])
@login_required
def attacks():
    """View attacks page"""
    try:
        attacks_list = db.get_attacks(limit=100)
    except:
        attacks_list = []
    return render_template('attacks.html', attacks=attacks_list, page=1)

@app.route('/export', methods=['GET', 'POST'])
@login_required
def export():
    """Export data page"""
    return render_template('export.html')

@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint to analyze a URL"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    try:
        # Analyze the URL
        result = detector.analyze_url(url)
        
        # Store in database
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'attack_type': result['attacks_detected'][0]['type'] if result['attacks_detected'] else 'none',
            'is_malicious': result['is_malicious'],
            'severity': result['severity'],
            'confidence': result['confidence']
        }
        attack_id = db.insert_attack(attack_data)
        
        return jsonify({
            'success': True,
            'attack_id': attack_id,
            'url': url,
            'is_malicious': result['is_malicious'],
            'severity': result['severity'],
            'confidence': result['confidence'],
            'attacks_detected': result['attacks_detected']
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def api_statistics():
    """Get attack statistics"""
    try:
        stats = db.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/attacks', methods=['GET'])
def api_get_attacks():
    """Get list of attacks with optional filtering"""
    try:
        limit = request.args.get('limit', 100, type=int)
        offset = request.args.get('offset', 0, type=int)
        attack_type = request.args.get('attack_type', None)
        is_malicious = request.args.get('is_malicious', None)
        
        filters = {}
        if attack_type and attack_type != 'all':
            filters['attack_type'] = attack_type
        if is_malicious is not None:
            filters['is_malicious'] = is_malicious.lower() == 'true'
        
        attacks = db.get_attacks(limit=limit, offset=offset, filters=filters)
        return jsonify({'attacks': attacks, 'total': len(attacks)}), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/generate-dataset', methods=['POST'])
def api_generate_dataset():
    """Generate sample dataset"""
    try:
        data = request.get_json()
        num_records = data.get('num_records', 100)
        malicious_ratio = data.get('malicious_ratio', 0.3)
        
        if num_records > 10000:
            return jsonify({'error': 'Maximum 10000 records allowed'}), 400
        
        # Generate dataset
        dataset = generator.generate_dataset(num_records=num_records, malicious_ratio=malicious_ratio)
        
        # Insert into database
        count = db.insert_batch(dataset)
        
        # Get updated statistics
        stats = db.get_statistics()
        
        return jsonify({
            'success': True,
            'records_generated': count,
            'statistics': stats
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export', methods=['POST'])
def api_export():
    """Export data to file"""
    try:
        data = request.get_json()
        export_format = data.get('format', 'json')
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"attacks_{timestamp}.{export_format}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if export_format == 'json':
            db.export_to_json(filepath)
        elif export_format == 'csv':
            db.export_to_csv(filepath)
        else:
            return jsonify({'error': 'Invalid format'}), 400
        
        return jsonify({
            'success': True,
            'filename': filename,
            'filepath': filepath
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/download/<filename>', methods=['GET'])
def api_download(filename):
    """Download exported file"""
    try:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'File not found'}), 404
        
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
