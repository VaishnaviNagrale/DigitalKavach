import os
import urllib.parse
import sys
from flask import Flask, request, jsonify
from flask_cors import CORS  # Add CORS support for cross-origin requests
import pefile
import numpy as np
import pickle
import pandas as pd
import traceback

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Enhanced debugging
DEBUG = True

def debug_print(message):
    """Helper function for consistent debug output"""
    if DEBUG:
        print(f"[DEBUG] {message}")
        sys.stdout.flush()  # Force output to be displayed immediately

# List of PE-specific features to extract (ordered to match model's expected feature names)
FEATURES = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
    'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
    'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion',
    'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
    'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
    'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy',
    'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize',
    'SectionMaxRawsize', 'SectionMaxVirtualsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
    'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal', 'ExportNb',
    'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
    'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
    'VersionInformationSize'
]

# Ensure uploads directory exists
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
    debug_print(f"Created upload directory: {UPLOAD_FOLDER}")
else:
    debug_print(f"Upload directory exists: {UPLOAD_FOLDER}")

# Function to extract features from the EXE (PE) file
def extract_exe_features(filepath):
    debug_print(f"Starting feature extraction from: {filepath}")
    
    if not os.path.exists(filepath):
        debug_print(f"ERROR: File does not exist at path: {filepath}")
        return None
        
    debug_print(f"File size: {os.path.getsize(filepath)} bytes")
    
    features = {}
    
    # Initialize all features with 0 as default value
    for feature in FEATURES:
        features[feature] = 0
    
    try:
        debug_print(f"Opening file with pefile: {filepath}")
        pe = pefile.PE(filepath)
        debug_print("Successfully opened PE file")
        
        # Extract basic features
        debug_print("Extracting FILE_HEADER features")
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # Extract optional header features
        if hasattr(pe, 'OPTIONAL_HEADER'):
            debug_print("Extracting OPTIONAL_HEADER features")
            features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            features['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
            features['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
            features['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
            features['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            features['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
            
            # BaseOfData doesn't exist in PE32+ files
            if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData'):
                features['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
                debug_print("BaseOfData found: 32-bit PE")
            else:
                debug_print("No BaseOfData: likely 64-bit PE (PE32+)")
                
            features['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
            features['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
            features['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
            features['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
            features['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
            features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
            features['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
            features['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
            features['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
            features['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
            features['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
            features['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
            features['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
            features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
            features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
            features['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
            features['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
            features['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
            features['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
            features['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        else:
            debug_print("WARNING: No OPTIONAL_HEADER found in PE file")
        
        # Extract sections information
        if hasattr(pe, 'sections') and len(pe.sections) > 0:
            section_count = len(pe.sections)
            debug_print(f"Extracting sections features. Found {section_count} sections")
            features['SectionsNb'] = section_count
            
            # Calculate entropy-related features
            try:
                entropies = [section.get_entropy() for section in pe.sections]
                features['SectionsMeanEntropy'] = sum(entropies) / len(entropies)
                features['SectionsMinEntropy'] = min(entropies)
                features['SectionsMaxEntropy'] = max(entropies)
                debug_print(f"Section entropy ranges: {min(entropies):.2f} - {max(entropies):.2f}")
            except Exception as e:
                debug_print(f"Error calculating section entropies: {e}")
                features['SectionsMeanEntropy'] = 0
                features['SectionsMinEntropy'] = 0
                features['SectionsMaxEntropy'] = 0
            
            # Calculate size-related features
            try:
                raw_sizes = [section.SizeOfRawData for section in pe.sections]
                virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
                
                features['SectionsMeanRawsize'] = sum(raw_sizes) / len(raw_sizes)
                features['SectionsMinRawsize'] = min(raw_sizes)
                features['SectionMaxRawsize'] = max(raw_sizes)
                
                features['SectionsMeanVirtualsize'] = sum(virtual_sizes) / len(virtual_sizes)
                features['SectionsMinVirtualsize'] = min(virtual_sizes)
                features['SectionMaxVirtualsize'] = max(virtual_sizes)
                debug_print(f"Raw size ranges: {min(raw_sizes)} - {max(raw_sizes)}")
                debug_print(f"Virtual size ranges: {min(virtual_sizes)} - {max(virtual_sizes)}")
            except Exception as e:
                debug_print(f"Error calculating section sizes: {e}")
        else:
            debug_print("WARNING: No sections found in PE file")
        
        # Extract imports information
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            debug_print("Extracting imports information")
            features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            total_imports = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
            features['ImportsNb'] = total_imports
            ordinal_count = sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT 
                              for imp in entry.imports if imp.ordinal is not None)
            features['ImportsNbOrdinal'] = ordinal_count
            debug_print(f"Found {features['ImportsNbDLL']} DLLs with {total_imports} imports ({ordinal_count} ordinals)")
        else:
            debug_print("No imports found")
        
        # Extract exports information
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            debug_print("Extracting exports information")
            features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            debug_print(f"Found {features['ExportNb']} exports")
        else:
            debug_print("No exports found")
        
        # Extract resources information
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries'):
            debug_print("Extracting resources information")
            features['ResourcesNb'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            debug_print(f"Found {features['ResourcesNb']} resource entries")
            
            # More detailed resource analysis would go here
            # For now, setting default values for resource entropy and size features
            features['ResourcesMeanEntropy'] = 0
            features['ResourcesMinEntropy'] = 0
            features['ResourcesMaxEntropy'] = 0
            features['ResourcesMeanSize'] = 0
            features['ResourcesMinSize'] = 0
            features['ResourcesMaxSize'] = 0
        else:
            debug_print("No resources found")
        
        # Load configuration and version information
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and pe.DIRECTORY_ENTRY_LOAD_CONFIG and hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct'):
            debug_print("Found load configuration directory")
            # Don't use len() on Structure objects
            features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        else:
            features['LoadConfigurationSize'] = 0
            
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            debug_print("Found version information")
            # Use a non-zero value to indicate presence of version info
            features['VersionInformationSize'] = 1
        else:
            features['VersionInformationSize'] = 0
            
        debug_print("Feature extraction completed successfully")
        
    except Exception as e:
        debug_print(f"ERROR reading {filepath}: {str(e)}")
        debug_print(traceback.format_exc())
    
    # Check for any missing features
    missing = set(FEATURES) - set(features.keys())
    if missing:
        debug_print(f"WARNING: Missing features after extraction: {missing}")
        # Set missing features to 0
        for feature in missing:
            features[feature] = 0
    
    # Quick sanity check on features
    debug_print(f"Feature extraction complete. Feature count: {len(features)}")
    return features

# Global variable for the model
MODEL = None

# Load the pre-trained model
def load_pickle(file_name, possible_paths):
    for path in possible_paths:
        # Join the path only if the current item is a directory
        full_path = path if path.endswith(file_name) else os.path.join(path, file_name)
        if os.path.exists(full_path):
            with open(full_path, "rb") as f:
                print(f"Loaded {file_name} from: {full_path}")
                return pickle.load(f)
    raise FileNotFoundError(f"{file_name} not found in any of the provided paths.")

def load_model():
    global MODEL, SCALER, FEATURE_NAMES

    debug_print("Attempting to load malware detection model...")

    possible_paths = [
        '../assets/random_forest_improved.pkl',
        './assets/random_forest_improved.pkl',
        'random_forest_improved.pkl',
        './random_forest_improved.pkl',
        'assets/random_forest_improved.pkl',
        os.path.join(os.path.dirname(__file__), 'random_forest_improved.pkl'),
        os.path.join(os.path.dirname(__file__), 'assets', 'random_forest_improved.pkl')
    ]

    debug_print(f"Current working directory: {os.getcwd()}")
    debug_print(f"Checking these locations for model file: {possible_paths}")

    for model_path in possible_paths:
        try:
            if os.path.exists(model_path):
                debug_print(f"Found model at: {model_path}")
                with open(model_path, 'rb') as file:
                    MODEL = pickle.load(file)
                debug_print("Model loaded successfully!")

                # ✅ Determine the directory where this model was found
                model_dir = os.path.dirname(model_path) or '.'

                # ✅ Try loading scaler and feature_names from the same directory
                SCALER = load_pickle("scaler.pkl", [model_dir])
                FEATURE_NAMES = load_pickle("feature_names.pkl", [model_dir])


                # ✅ Print model features if available
                if hasattr(MODEL, 'feature_names_in_'):
                    debug_print(f"Model expected feature count: {len(MODEL.feature_names_in_)}")
                    if len(MODEL.feature_names_in_) > 10:
                        debug_print(f"First 5 features: {MODEL.feature_names_in_[:5].tolist()}")
                        debug_print(f"Last 5 features: {MODEL.feature_names_in_[-5:].tolist()}")
                    else:
                        debug_print(f"All model features: {MODEL.feature_names_in_.tolist()}")
                else:
                    debug_print("WARNING: Model doesn't have feature_names_in_ attribute")

                return True
        except Exception as e:
            debug_print(f"Failed to load model from {model_path}: {e}")
            debug_print(traceback.format_exc())
            continue

    debug_print("ERROR: Could not find or load model from any location")
    return False

# Convert features to a DataFrame with proper order
def process_features(features):
    debug_print("Processing features for model input")
    print('Feature',features)
    
    if features is None:
        debug_print("ERROR: Features dictionary is None")
        return None
        
    # Create a DataFrame with features in the correct order
    try:
        features_df = pd.DataFrame([features], columns=FEATURE_NAMES)

        debug_print(f"Created DataFrame with {len(features_df.columns)} features")
        
        # Fill any missing values with 0
        null_before = features_df.isnull().sum().sum()
        if null_before > 0:
            debug_print(f"Found {null_before} null values, filling with 0")
            features_df = features_df.fillna(0)
        
        # Print feature columns to help debug
        debug_print(f"Feature columns count: {len(features_df.columns)}")
        
        # If the model has feature_names_in_ attribute, ensure our DataFrame matches it
        features_df = features_df[FEATURE_NAMES]
        features_df = SCALER.transform(features_df)

        return features_df
        
    except Exception as e:
        debug_print(f"Error processing features: {e}")
        debug_print(traceback.format_exc())
        return None
# Modify the predict route in your Flask application
# Find and replace the predict function in your backend file:

@app.route('/predict', methods=['POST'])
def predict():
    debug_print("==== /predict API endpoint called ====")
    debug_print(f"Request content type: {request.content_type}")
    
    # Check if model is loaded
    global MODEL
    if MODEL is None:
        debug_print("Model not loaded, attempting to load...")
        if not load_model():
            return jsonify({"error": "Model not loaded properly"}), 500
    
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
        
        # Extract features from the PE file
        debug_print("Starting feature extraction...")
        features = extract_exe_features(file_path)
        
        if features is None:
            debug_print("Feature extraction failed")
            return jsonify({"error": "Failed to extract features from file"}), 400
        
        # Process features for prediction
        debug_print("Processing features for prediction...")
        processed_features = process_features(features)
        
        if processed_features is None:
            debug_print("Feature processing failed")
            return jsonify({"error": "Failed to process features for prediction"}), 400
        
        # Make prediction
        debug_print("Making prediction...")
        try:
            prediction = MODEL.predict(processed_features)
            debug_print(f"Raw prediction result: {prediction}")
            
            prediction_result = int(prediction[0]) if isinstance(prediction[0], (int, np.integer)) else str(prediction[0])
            debug_print(f"Processed prediction result: {prediction_result}")
            
            # Get prediction probabilities if available
            prediction_proba = None
            if hasattr(MODEL, 'predict_proba'):
                try:
                    probas = MODEL.predict_proba(processed_features)
                    debug_print(f"Prediction probabilities: {probas}")
                    if len(probas[0]) >= 2:
                        # Probability for the positive class (usually at index 1)
                        prediction_proba = float(probas[0][1])
                        debug_print(f"Malicious probability: {prediction_proba:.4f}")
                except Exception as e:
                    debug_print(f"Error getting prediction probabilities: {e}")
            
            # IMPORTANT CHANGE: Convert numeric prediction to string format expected by frontend
            prediction_str = "malicious" if prediction_result == 0 else "benign"
            debug_print(f"Converted prediction string: {prediction_str}")
            
            # Return prediction result
            result = {
                "prediction": prediction_str,  # CHANGED: Now returns "malicious" or "benign"
                "raw_prediction": prediction_result  # Also include the raw value for reference
            }
            
            if prediction_proba is not None:
                result["probability"] = prediction_proba
                
            if prediction_result == 1:
                result["message"] = "This file is potentially malicious."
            else:
                result["message"] = "This file appears to be benign."
                
            debug_print(f"Returning prediction result: {result}")
            return jsonify(result), 200
            
        except Exception as e:
            debug_print(f"Error during prediction: {e}")
            debug_print(traceback.format_exc())
            return jsonify({"error": f"Error during prediction: {str(e)}"}), 500

    except Exception as e:
        debug_print(f"Unhandled error in prediction endpoint: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500
    
@app.route('/status', methods=['GET'])
def status():
    debug_print("Status endpoint called")
    
    # Check if model is loaded
    global MODEL
    if MODEL is None:
        loaded = load_model()
        model_status = "Loaded successfully" if loaded else "Failed to load"
    else:
        model_status = "Already loaded"
    
    # Check upload directory
    upload_dir_exists = os.path.exists(UPLOAD_FOLDER)
    
    response = {
        "status": "API is running",
        "model_status": model_status,
        "upload_directory": f"{UPLOAD_FOLDER} ({'exists' if upload_dir_exists else 'missing'})",
        "debug_mode": DEBUG
    }
    
    debug_print(f"Returning status: {response}")
    return jsonify(response), 200

# Add a route to list files in upload directory
@app.route('/list_uploads', methods=['GET'])
def list_uploads():
    debug_print("List uploads endpoint called")
    
    try:
        if not os.path.exists(UPLOAD_FOLDER):
            return jsonify({"error": "Upload directory does not exist"}), 404
            
        files = os.listdir(UPLOAD_FOLDER)
        file_details = []
        
        for filename in files:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                file_details.append({
                    "name": filename,
                    "size": os.path.getsize(file_path),
                    "last_modified": os.path.getmtime(file_path)
                })
                
        return jsonify({
            "directory": UPLOAD_FOLDER,
            "file_count": len(file_details),
            "files": file_details
        }), 200
        
    except Exception as e:
        debug_print(f"Error listing uploads: {e}")
        return jsonify({"error": str(e)}), 500

# Initialize the app
if __name__ == '__main__':
    debug_print("Starting Flask application...")
    
    # Load model at startup
    load_model()
    
    debug_print(f"Current working directory: {os.getcwd()}")
    debug_print(f"Upload directory: {os.path.abspath(UPLOAD_FOLDER)}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)