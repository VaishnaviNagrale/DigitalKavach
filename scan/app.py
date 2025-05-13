from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import threading
import time
import json
import traceback
# Import from our updated scanner.py
from scanner import get_running_exe_files, scan_with_model, load_model, scan_running_exes

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
DEBUG = True
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
SCAN_RESULTS_FILE = 'scan_results.json'
SCAN_INTERVAL = 60 * 5  # Scan running processes every 5 minutes

# Make sure the upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Global variables for tracking process status
process_status = {}
last_scan_time = 0
background_scanner_running = False

def debug_print(message):
    """Helper function for consistent debug output"""
    if DEBUG:
        print(f"[DEBUG] {message}")


def initialize():
    """Initialize the application before the first request is processed"""
    debug_print("Initializing application...")
    
    # Load the malware detection model
    success= load_model()
    if not success:
        debug_print(f"Failed to load model:")
    else:
        debug_print("Model loaded successfully")
    
    # Start the background scanning thread
    start_background_scanner()

def start_background_scanner():
    """Start the background thread that periodically scans running processes"""
    global background_scanner_running
    
    if background_scanner_running:
        debug_print("Background scanner already running")
        return
    
    debug_print("Starting background process scanner...")
    background_scanner_running = True
    scanner_thread = threading.Thread(target=background_scan_loop, daemon=True)
    scanner_thread.start()
    debug_print("Background scanner started")

def background_scan_loop():
    """Continuously scan running processes in the background"""
    global process_status, last_scan_time
    
    debug_print("Background scanner running")
    while background_scanner_running:
        try:
            current_time = time.time()
            
            # Only scan if enough time has passed since the last scan
            if current_time - last_scan_time >= SCAN_INTERVAL:
                debug_print("Starting scheduled scan of running processes...")
                scan_running_processes()
                last_scan_time = current_time
                
                # Save results to disk
                try:
                    with open(SCAN_RESULTS_FILE, 'w') as f:
                        json.dump(process_status, f)
                    debug_print(f"Saved scan results to disk: {SCAN_RESULTS_FILE}")
                except Exception as e:
                    debug_print(f"Failed to save scan results: {e}")
            
            # Sleep before checking again
            time.sleep(10)
        except Exception as e:
            debug_print(f"Error in background scanner: {e}")
            debug_print(traceback.format_exc())
            time.sleep(30)  # Sleep longer after an error

def scan_running_processes():
    """Scan all running executable files for malware"""
    global process_status
    
    debug_print("Scanning running processes for malware...")
    
    # Use our updated scan_running_exes() function to get all results at once
    results = scan_running_exes()
    
    # Update the process status with the new results
    new_status = {}
    for path, result in results.items():
        if os.path.exists(path):
            try:
                # Add file modification time for caching purposes
                result['file_mtime'] = os.path.getmtime(path)
                new_status[path] = result
            except Exception as e:
                debug_print(f"Error processing result for {path}: {e}")
                new_status[path] = {
                    'status': 'error',
                    'message': str(e),
                    'filepath': path
                }
    
    process_status = new_status
    debug_print(f"Scan complete. Scanned {len(process_status)} executables.")

# New API endpoint to retrieve saved scan results
@app.route('/api/saved_results', methods=['GET'])
def get_saved_results():
    """API endpoint to retrieve the saved scan results from file"""
    try:
        if os.path.exists(SCAN_RESULTS_FILE):
            with open(SCAN_RESULTS_FILE, 'r') as f:
                raw_data = json.load(f)
                
            # Process the data to match the format expected by the frontend
            organized_results = {
                'malicious': [],
                'benign': [],
                'error': []
            }
            
            for path, result in raw_data.items():
                if 'prediction' in result and result['prediction'] == 'malicious':
                    organized_results['malicious'].append({
                        'filepath': path,
                        'result': result
                    })
                elif 'prediction' in result and result['prediction'] == 'benign':
                    organized_results['benign'].append({
                        'filepath': path,
                        'result': result
                    })
                else:
                    organized_results['error'].append({
                        'filepath': path,
                        'result': result
                    })
            
            return jsonify({
                'last_scan_time': os.path.getmtime(SCAN_RESULTS_FILE),
                'results': organized_results,
                'summary': {
                    'total': len(raw_data),
                    'malicious': len(organized_results['malicious']),
                    'benign': len(organized_results['benign']),
                    'error': len(organized_results['error'])
                }
            })
        else:
            return jsonify({
                'message': 'No saved scan results found',
                'results': {'malicious': [], 'benign': [], 'error': []},
                'summary': {'total': 0, 'malicious': 0, 'benign': 0, 'error': 0}
            })
    
    except Exception as e:
        debug_print(f"Error retrieving saved scan results: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/process_status', methods=['GET'])
def get_process_status():
    """API endpoint to get the status of all scanned processes"""
    global process_status
    
    # Force a scan if this is the first time or it's been a while
    if not process_status or (time.time() - last_scan_time > SCAN_INTERVAL):
        scan_running_processes()
    
    # Organize results by status
    organized_results = {
        'malicious': [],
        'benign': [],
        'error': []
    }
    
    for path, result in process_status.items():
        if 'prediction' in result and result['prediction'] == 'malicious':
            organized_results['malicious'].append({
                'filepath': path,
                'result': result
            })
        elif 'prediction' in result and result['prediction'] == 'benign':
            organized_results['benign'].append({
                'filepath': path,
                'result': result
            })
        else:
            organized_results['error'].append({
                'filepath': path,
                'result': result
            })
    
    return jsonify({
        'last_scan_time': last_scan_time,
        'results': organized_results,
        'summary': {
            'total': len(process_status),
            'malicious': len(organized_results['malicious']),
            'benign': len(organized_results['benign']),
            'error': len(organized_results['error'])
        }
    })

@app.route('/api/scan', methods=['POST'])
def scan_file():
    """API endpoint to scan a specific file for malware"""
    debug_print("==== /api/scan endpoint called ====")
    
    # Check for file in request
    if 'file' not in request.files:
        debug_print("ERROR: No file part in request")
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    debug_print(f"Received file: {file.filename}")
    
    if file.filename == '':
        debug_print("ERROR: Empty filename")
        return jsonify({"error": "No selected file"}), 400
    
    try:
        # Create a safe filename - replace problematic characters and spaces
        original_filename = file.filename
        safe_filename = ''.join(c if c.isalnum() or c in ['', '-', '.'] else '' for c in original_filename)
        file_path = os.path.join(UPLOAD_FOLDER, safe_filename)
        
        # Save the uploaded file
        debug_print(f"Saving file to: {file_path}")
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)
            debug_print(f"File saved successfully. Size: {os.path.getsize(file_path)} bytes")
        except Exception as e:
            debug_print(f"Error saving file: {e}")
            debug_print(traceback.format_exc())
            return jsonify({"error": f"Error saving file: {str(e)}"}), 500
        
        # Scan the file
        result = scan_with_model(file_path)
        
        return jsonify(result), 200
            
    except Exception as e:
        debug_print(f"Unhandled error in scan endpoint: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan_running', methods=['GET'])
def scan_running_endpoint():
    """API endpoint to scan all currently running executable files"""
    try:
        debug_print("Starting scan of running executables...")
        results = scan_running_exes()
        
        # Count malicious, benign, and error results
        malicious_count = sum(1 for result in results.values() if result.get('prediction') == 'malicious')
        benign_count = sum(1 for result in results.values() if result.get('prediction') == 'benign')
        error_count = sum(1 for result in results.values() if result.get('status') == 'error')
        
        # Save the results to file
        try:
            with open(SCAN_RESULTS_FILE, 'w') as f:
                json.dump(results, f)
            debug_print(f"Saved scan results to disk: {SCAN_RESULTS_FILE}")
        except Exception as e:
            debug_print(f"Failed to save scan results: {e}")
        
        return jsonify({
            "timestamp": time.time(),
            "results": results,
            "summary": {
                "total": len(results),
                "malicious": malicious_count,
                "benign": benign_count,
                "error": error_count
            }
        }), 200

    except Exception as e:
        debug_print(f"Error in /api/scan_running: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    initialize()
    app.run(debug=True, port=8000)