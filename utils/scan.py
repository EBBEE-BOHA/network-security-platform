from flask import Blueprint, request, jsonify, current_app
from src.models.user import db, ScanResult
from src.routes.auth import token_required
import requests
import os
import hashlib
import json
from datetime import datetime

scan_bp = Blueprint('scan', __name__)

VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2'

def calculate_file_hash(file_content):
    """Calculate SHA256 hash of file content"""
    return hashlib.sha256(file_content).hexdigest()

def scan_file_with_virustotal(file_content, filename):
    """Scan file with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        # Return mock data for demo purposes
        return {
            'response_code': 1,
            'scan_id': f'mock-scan-{hashlib.md5(filename.encode()).hexdigest()}',
            'permalink': f'https://www.virustotal.com/file/{hashlib.sha256(file_content).hexdigest()}/analysis/',
            'resource': hashlib.sha256(file_content).hexdigest(),
            'sha256': hashlib.sha256(file_content).hexdigest()
        }
    
    try:
        url = f'{VIRUSTOTAL_BASE_URL}/file/scan'
        files = {'file': (filename, file_content)}
        params = {'apikey': VIRUSTOTAL_API_KEY}
        
        response = requests.post(url, files=files, params=params)
        return response.json()
    except Exception as e:
        raise Exception(f'VirusTotal API error: {str(e)}')

def scan_url_with_virustotal(url):
    """Scan URL with VirusTotal API"""
    if not VIRUSTOTAL_API_KEY:
        # Return mock data for demo purposes
        return {
            'response_code': 1,
            'scan_id': f'mock-url-scan-{hashlib.md5(url.encode()).hexdigest()}',
            'permalink': f'https://www.virustotal.com/url/{hashlib.sha256(url.encode()).hexdigest()}/analysis/',
            'resource': url
        }
    
    try:
        api_url = f'{VIRUSTOTAL_BASE_URL}/url/scan'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
        
        response = requests.post(api_url, params=params)
        return response.json()
    except Exception as e:
        raise Exception(f'VirusTotal API error: {str(e)}')

def get_scan_report(resource):
    """Get scan report from VirusTotal"""
    if not VIRUSTOTAL_API_KEY:
        # Return mock data for demo purposes
        import random
        malicious_count = random.randint(0, 3)
        suspicious_count = random.randint(0, 2)
        clean_count = 70 + random.randint(0, 10)
        
        return {
            'response_code': 1,
            'resource': resource,
            'scan_date': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'positives': malicious_count,
            'total': malicious_count + suspicious_count + clean_count,
            'permalink': f'https://www.virustotal.com/file/{resource}/analysis/',
            'scans': {
                'Microsoft': {'detected': malicious_count > 0, 'result': 'Trojan.Generic' if malicious_count > 0 else None},
                'Kaspersky': {'detected': False, 'result': None},
                'Norton': {'detected': False, 'result': None},
                'McAfee': {'detected': False, 'result': None},
                'Avast': {'detected': False, 'result': None}
            }
        }
    
    try:
        url = f'{VIRUSTOTAL_BASE_URL}/file/report'
        params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': resource}
        
        response = requests.get(url, params=params)
        return response.json()
    except Exception as e:
        raise Exception(f'VirusTotal API error: {str(e)}')

@scan_bp.route('/scan/file', methods=['POST'])
@token_required
def scan_file(current_user):
    try:
        if 'file' not in request.files:
            return jsonify({'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'message': 'No file selected'}), 400
        
        # Read file content
        file_content = file.read()
        file_hash = calculate_file_hash(file_content)
        
        # Check if file was already scanned recently
        existing_scan = ScanResult.query.filter_by(
            user_id=current_user.id,
            file_hash=file_hash,
            scan_status='completed'
        ).first()
        
        if existing_scan:
            return jsonify({
                'message': 'File already scanned',
                'scan_id': existing_scan.id,
                'data': existing_scan.to_dict()
            }), 200
        
        # Create new scan record
        scan_record = ScanResult(
            user_id=current_user.id,
            scan_type='file',
            target_name=file.filename,
            file_hash=file_hash,
            scan_status='scanning'
        )
        db.session.add(scan_record)
        db.session.commit()
        
        try:
            # Scan with VirusTotal
            vt_response = scan_file_with_virustotal(file_content, file.filename)
            
            if vt_response.get('response_code') == 1:
                scan_record.virustotal_id = vt_response.get('scan_id')
                scan_record.scan_status = 'completed'
                
                # Get detailed report (in real implementation, you might need to wait)
                report = get_scan_report(vt_response.get('resource', file_hash))
                
                if report.get('response_code') == 1:
                    scan_record.threats_found = report.get('positives', 0)
                    scan_record.engines_count = report.get('total', 0)
                    scan_record.result_status = 'threat' if report.get('positives', 0) > 0 else 'clean'
                    scan_record.scan_results = json.dumps(report)
                    scan_record.completed_at = datetime.utcnow()
                
                db.session.commit()
                
                return jsonify({
                    'message': 'File scan completed',
                    'data': {
                        'id': scan_record.virustotal_id or f'scan-{scan_record.id}',
                        'scan_id': scan_record.id,
                        'status': 'completed',
                        'result': scan_record.to_dict()
                    }
                }), 200
            else:
                scan_record.scan_status = 'error'
                db.session.commit()
                return jsonify({'message': 'Scan failed', 'error': vt_response}), 500
                
        except Exception as e:
            scan_record.scan_status = 'error'
            db.session.commit()
            return jsonify({'message': 'Scan failed', 'error': str(e)}), 500
            
    except Exception as e:
        return jsonify({'message': 'File upload failed', 'error': str(e)}), 500

@scan_bp.route('/scan/url', methods=['POST'])
@token_required
def scan_url(current_user):
    try:
        data = request.get_json()
        if not data or not data.get('url'):
            return jsonify({'message': 'URL is required'}), 400
        
        url = data['url']
        
        # Create new scan record
        scan_record = ScanResult(
            user_id=current_user.id,
            scan_type='url',
            target_name=url,
            scan_status='scanning'
        )
        db.session.add(scan_record)
        db.session.commit()
        
        try:
            # Scan with VirusTotal
            vt_response = scan_url_with_virustotal(url)
            
            if vt_response.get('response_code') == 1:
                scan_record.virustotal_id = vt_response.get('scan_id')
                scan_record.scan_status = 'completed'
                
                # Get detailed report
                report = get_scan_report(url)
                
                if report.get('response_code') == 1:
                    scan_record.threats_found = report.get('positives', 0)
                    scan_record.engines_count = report.get('total', 0)
                    scan_record.result_status = 'threat' if report.get('positives', 0) > 0 else 'clean'
                    scan_record.scan_results = json.dumps(report)
                    scan_record.completed_at = datetime.utcnow()
                
                db.session.commit()
                
                return jsonify({
                    'message': 'URL scan completed',
                    'data': {
                        'id': scan_record.virustotal_id or f'scan-{scan_record.id}',
                        'scan_id': scan_record.id,
                        'status': 'completed',
                        'result': scan_record.to_dict()
                    }
                }), 200
            else:
                scan_record.scan_status = 'error'
                db.session.commit()
                return jsonify({'message': 'Scan failed', 'error': vt_response}), 500
                
        except Exception as e:
            scan_record.scan_status = 'error'
            db.session.commit()
            return jsonify({'message': 'Scan failed', 'error': str(e)}), 500
            
    except Exception as e:
        return jsonify({'message': 'URL scan failed', 'error': str(e)}), 500

@scan_bp.route('/analysis/<analysis_id>', methods=['GET'])
@token_required
def get_analysis(current_user, analysis_id):
    try:
        # Try to find by virustotal_id first, then by scan_id
        scan_record = ScanResult.query.filter_by(virustotal_id=analysis_id).first()
        if not scan_record:
            try:
                scan_id = int(analysis_id.replace('scan-', ''))
                scan_record = ScanResult.query.filter_by(id=scan_id).first()
            except:
                pass
        
        if not scan_record:
            return jsonify({'message': 'Analysis not found'}), 404
        
        # Check if user owns this scan
        if scan_record.user_id != current_user.id:
            return jsonify({'message': 'Access denied'}), 403
        
        result_data = {
            'data': {
                'id': analysis_id,
                'type': 'analysis',
                'attributes': {
                    'status': scan_record.scan_status,
                    'stats': {
                        'malicious': scan_record.threats_found if scan_record.result_status == 'threat' else 0,
                        'suspicious': 0,
                        'undetected': scan_record.engines_count - scan_record.threats_found if scan_record.engines_count else 0,
                        'harmless': 0
                    },
                    'results': json.loads(scan_record.scan_results) if scan_record.scan_results else {}
                }
            },
            'meta': {
                'file_info': {
                    'name': scan_record.target_name,
                    'size': 0,  # Would need to store file size
                    'type': scan_record.scan_type
                }
            }
        }
        
        return jsonify(result_data), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get analysis', 'error': str(e)}), 500

@scan_bp.route('/scans/recent', methods=['GET'])
@token_required
def get_recent_scans(current_user):
    try:
        # Get recent scans for the user
        scans = ScanResult.query.filter_by(user_id=current_user.id)\
                              .order_by(ScanResult.created_at.desc())\
                              .limit(10).all()
        
        # Calculate stats
        total_scans = ScanResult.query.filter_by(user_id=current_user.id).count()
        threats_detected = ScanResult.query.filter_by(user_id=current_user.id, result_status='threat').count()
        clean_files = ScanResult.query.filter_by(user_id=current_user.id, result_status='clean').count()
        pending_scans = ScanResult.query.filter_by(user_id=current_user.id, scan_status='scanning').count()
        
        # Convert scans to the format expected by frontend
        scan_list = []
        for scan in scans:
            scan_data = {
                'id': str(scan.id),
                'type': scan.scan_type,
                'name': scan.target_name,
                'status': scan.scan_status,
                'result': scan.result_status,
                'timestamp': scan.created_at.isoformat() if scan.created_at else None,
                'threatsFound': scan.threats_found,
                'engines': scan.engines_count
            }
            if scan.scan_type == 'file' and scan.file_hash:
                # Mock file size for demo
                scan_data['fileSize'] = 1024 * 1024  # 1MB default
            scan_list.append(scan_data)
        
        return jsonify({
            'scans': scan_list,
            'stats': {
                'totalScans': total_scans,
                'threatsDetected': threats_detected,
                'cleanFiles': clean_files,
                'pendingScans': pending_scans
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Failed to get recent scans', 'error': str(e)}), 500

