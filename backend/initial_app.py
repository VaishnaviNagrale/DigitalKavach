import os
import sys
import traceback
from typing import Dict, List, Union, Optional, Tuple
import urllib.parse

# Flask imports
from flask import Flask, request, jsonify
from flask_cors import CORS

# Data processing imports
import numpy as np
import pandas as pd
import pickle
import pefile

# For sampling/balancing
from sklearn.utils import resample

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

# Global variable for the model
MODEL = None

def safely_get_attribute(obj, attr_name, default_value=0):
    """Safely get attribute value with proper error handling and default value"""
    try:
        return getattr(obj, attr_name) if hasattr(obj, attr_name) else default_value
    except Exception as e:
        debug_print(f"Error getting attribute {attr_name}: {str(e)}")
        return default_value

def safely_get_entropy(section) -> float:
    """Safely get entropy for a PE section with proper error handling"""
    try:
        return section.get_entropy()
    except Exception as e:
        debug_print(f"Error calculating entropy: {str(e)}")
        return 0.0

def calculate_statistics(values: List[Union[int, float]]) -> Tuple[float, float, float]:
    """Calculate mean, min, max of a list of values with proper error handling"""
    if not values:
        return 0.0, 0.0, 0.0
    
    try:
        mean_val = sum(values) / len(values)
        min_val = min(values)
        max_val = max(values)
        return mean_val, min_val, max_val
    except Exception as e:
        debug_print(f"Error calculating statistics: {str(e)}")
        return 0.0, 0.0, 0.0

def extract_exe_features(filepath: str) -> Optional[Dict[str, Union[int, float]]]:
    debug_print(f"Starting feature extraction from: {filepath}")
    if not os.path.exists(filepath):
        debug_print(f"ERROR: File does not exist at path: {filepath}")
        return None   
    debug_print(f"File size: {os.path.getsize(filepath)} bytes")
    features = {feature: 0 for feature in FEATURES}
    try:
        debug_print(f"Opening file with pefile: {filepath}")
        pe = pefile.PE(filepath)
        debug_print("Successfully opened PE file")
        debug_print("Extracting FILE_HEADER features")
        features['Machine'] = safely_get_attribute(pe.FILE_HEADER, 'Machine')
        features['SizeOfOptionalHeader'] = safely_get_attribute(pe.FILE_HEADER, 'SizeOfOptionalHeader')
        features['Characteristics'] = safely_get_attribute(pe.FILE_HEADER, 'Characteristics')
        if hasattr(pe, 'OPTIONAL_HEADER'):
            debug_print("Extracting OPTIONAL_HEADER features")
            opt_header = pe.OPTIONAL_HEADER
            optional_header_mappings = {
                'MajorLinkerVersion': 'MajorLinkerVersion',
                'MinorLinkerVersion': 'MinorLinkerVersion',
                'SizeOfCode': 'SizeOfCode',
                'SizeOfInitializedData': 'SizeOfInitializedData',
                'SizeOfUninitializedData': 'SizeOfUninitializedData',
                'AddressOfEntryPoint': 'AddressOfEntryPoint',
                'BaseOfCode': 'BaseOfCode',
                'ImageBase': 'ImageBase',
                'SectionAlignment': 'SectionAlignment',
                'FileAlignment': 'FileAlignment',
                'MajorOperatingSystemVersion': 'MajorOperatingSystemVersion',
                'MinorOperatingSystemVersion': 'MinorOperatingSystemVersion',
                'MajorImageVersion': 'MajorImageVersion',
                'MinorImageVersion': 'MinorImageVersion',
                'MajorSubsystemVersion': 'MajorSubsystemVersion',
                'MinorSubsystemVersion': 'MinorSubsystemVersion',
                'SizeOfImage': 'SizeOfImage',
                'SizeOfHeaders': 'SizeOfHeaders',
                'CheckSum': 'CheckSum',
                'Subsystem': 'Subsystem',
                'DllCharacteristics': 'DllCharacteristics',
                'SizeOfStackReserve': 'SizeOfStackReserve',
                'SizeOfStackCommit': 'SizeOfStackCommit',
                'SizeOfHeapReserve': 'SizeOfHeapReserve',
                'SizeOfHeapCommit': 'SizeOfHeapCommit',
                'LoaderFlags': 'LoaderFlags',
                'NumberOfRvaAndSizes': 'NumberOfRvaAndSizes'
            }
            for feature_name, attr_name in optional_header_mappings.items():
                features[feature_name] = safely_get_attribute(opt_header, attr_name)
            features['BaseOfData'] = safely_get_attribute(opt_header, 'BaseOfData')
            if hasattr(opt_header, 'BaseOfData'):
                debug_print("BaseOfData found: 32-bit PE")
            else:
                debug_print("No BaseOfData: likely 64-bit PE (PE32+)")
        else:
            debug_print("WARNING: No OPTIONAL_HEADER found in PE file")
        if hasattr(pe, 'sections') and pe.sections:
            section_count = len(pe.sections)
            debug_print(f"Extracting sections features. Found {section_count} sections")
            features['SectionsNb'] = section_count
            entropies = [safely_get_entropy(section) for section in pe.sections]
            if entropies:
                features['SectionsMeanEntropy'], features['SectionsMinEntropy'], features['SectionsMaxEntropy'] = calculate_statistics(entropies)
                debug_print(f"Section entropy ranges: {features['SectionsMinEntropy']:.2f} - {features['SectionsMaxEntropy']:.2f}")
            raw_sizes = [safely_get_attribute(section, 'SizeOfRawData') for section in pe.sections]
            if raw_sizes:
                features['SectionsMeanRawsize'], features['SectionsMinRawsize'], features['SectionMaxRawsize'] = calculate_statistics(raw_sizes)
                debug_print(f"Raw size ranges: {features['SectionsMinRawsize']} - {features['SectionMaxRawsize']}")
            
            virtual_sizes = [safely_get_attribute(section, 'Misc_VirtualSize') for section in pe.sections]
            if virtual_sizes:
                features['SectionsMeanVirtualsize'], features['SectionsMinVirtualsize'], features['SectionMaxVirtualsize'] = calculate_statistics(virtual_sizes)
                debug_print(f"Virtual size ranges: {features['SectionsMinVirtualsize']} - {features['SectionMaxVirtualsize']}")   
        else:
            debug_print("WARNING: No sections found in PE file")
        
        # Extract imports information with improved error handling
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT:
            debug_print("Extracting imports information")
            features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            
            # Count all imports across all DLLs
            total_imports = sum(
                len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT 
                if hasattr(entry, 'imports') and entry.imports
            )
            features['ImportsNb'] = total_imports
            
            # Count ordinal imports
            ordinal_count = sum(
                1 for entry in pe.DIRECTORY_ENTRY_IMPORT 
                if hasattr(entry, 'imports') and entry.imports
                for imp in entry.imports 
                if imp and hasattr(imp, 'ordinal') and imp.ordinal is not None
            )
            features['ImportsNbOrdinal'] = ordinal_count
            
            debug_print(f"Found {features['ImportsNbDLL']} DLLs with {total_imports} imports ({ordinal_count} ordinals)")
        else:
            debug_print("No imports found")
        
        # Extract exports information with improved error handling
        if (hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and 
            pe.DIRECTORY_ENTRY_EXPORT and 
            hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols') and 
            pe.DIRECTORY_ENTRY_EXPORT.symbols):
            debug_print("Extracting exports information")
            features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            debug_print(f"Found {features['ExportNb']} exports")
        else:
            debug_print("No exports found")
            features['ExportNb'] = 0
        
        # Extract resources information with improved error handling
        if (hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and 
            pe.DIRECTORY_ENTRY_RESOURCE and 
            hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries') and 
            pe.DIRECTORY_ENTRY_RESOURCE.entries):
            
            debug_print("Extracting resources information")
            features['ResourcesNb'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            debug_print(f"Found {features['ResourcesNb']} resource entries")
            
            features['ResourcesMeanEntropy'] = 0
            features['ResourcesMinEntropy'] = 0
            features['ResourcesMaxEntropy'] = 0
            features['ResourcesMeanSize'] = 0
            features['ResourcesMinSize'] = 0
            features['ResourcesMaxSize'] = 0
        else:
            debug_print("No resources found")
            features['ResourcesNb'] = 0
        
        # Load configuration with improved error handling
        if (hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and 
            pe.DIRECTORY_ENTRY_LOAD_CONFIG and 
            hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct')):
            debug_print("Found load configuration directory")
            features['LoadConfigurationSize'] = safely_get_attribute(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct, 'Size')
        else:
            features['LoadConfigurationSize'] = 0
            
        # Version information with improved error handling
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            debug_print("Found version information")
            features['VersionInformationSize'] = 1
        else:
            features['VersionInformationSize'] = 0
            
        debug_print("Feature extraction completed successfully")
        
    except Exception as e:
        debug_print(f"ERROR reading {filepath}: {str(e)}")
        debug_print(traceback.format_exc())
    
    # Verify all features are present
    missing = set(FEATURES) - set(features.keys())
    if missing:
        debug_print(f"WARNING: Missing features after extraction: {missing}")
        # Set missing features to 0
        for feature in missing:
            features[feature] = 0
    
    # Quick sanity check on features
    debug_print(f"Feature extraction complete. Feature count: {len(features)}")
    return features

def load_model() -> bool:
    """
    Load the pre-trained malware detection model with improved error handling
    
    Returns:
        Boolean indicating success/failure
    """
    global MODEL
    
    debug_print("Attempting to load malware detection model...")
    
    # Try multiple possible locations for the model file
    possible_paths = [
        '../assets/random_forest_model2.pkl',
        os.path.join(os.path.dirname(__file__), 'random_forest_model2.pkl'),
        os.path.join(os.path.dirname(__file__), 'assets', 'random_forest_model2.pkl'),
        # Add more potential paths if needed
    ]
    
    # Log all possible paths we're checking
    debug_print(f"Current working directory: {os.getcwd()}")
    debug_print(f"Checking these locations for model file: {possible_paths}")
    
    for model_path in possible_paths:
        try:
            if os.path.exists(model_path):
                debug_print(f"Found model at: {model_path}")
                with open(model_path, 'rb') as file:
                    MODEL = pickle.load(file)
                debug_print("Model loaded successfully!")
                
                # Extract and print the feature names expected by the model
                if hasattr(MODEL, 'feature_names_in_'):
                    debug_print(f"Model expected feature count: {len(MODEL.feature_names_in_)}")
                    # Print first few and last few features for debugging
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

def process_features(features: Dict[str, Union[int, float]]) -> Optional[pd.DataFrame]:
    """
    Process extracted features for model input with improved error handling and feature ordering
    
    Args:
        features: Dictionary of features extracted from PE file
        
    Returns:
        DataFrame of processed features or None if processing failed
    """
    debug_print("Processing features for model input")
    
    if features is None:
        debug_print("ERROR: Features dictionary is None")
        return None
        
    # Create a DataFrame with features in the correct order
    try:
        features_df = pd.DataFrame([features], columns=FEATURES)
        debug_print(f"Created DataFrame with {len(features_df.columns)} features")
        
        # Fill any missing values with 0
        null_before = features_df.isnull().sum().sum()
        if null_before > 0:
            debug_print(f"Found {null_before} null values, filling with 0")
            features_df = features_df.fillna(0)
        
        # If the model has feature_names_in_ attribute, ensure our DataFrame matches it
        if MODEL is not None and hasattr(MODEL, 'feature_names_in_'):
            expected_columns = MODEL.feature_names_in_.tolist()
            
            # Check if columns match
            if sorted(features_df.columns.tolist()) != sorted(expected_columns):
                debug_print("WARNING: Feature columns don't match model's expected features!")
                debug_print(f"Missing features: {set(expected_columns) - set(features_df.columns.tolist())}")
                debug_print(f"Extra features: {set(features_df.columns.tolist()) - set(expected_columns)}")
                
                # Reorder columns to match model's expected order
                try:
                    # Create a new DataFrame with the exact columns needed
                    new_df = pd.DataFrame(columns=expected_columns)
                    
                    # Copy over existing features
                    for col in expected_columns:
                        if col in features_df.columns:
                            new_df[col] = features_df[col]
                        else:
                            # Default to 0 for missing features
                            new_df[col] = 0
                            
                    features_df = new_df
                    debug_print("Features reordered to match model's expectations")
                except Exception as e:
                    debug_print(f"Error reordering features: {e}")
                    debug_print(traceback.format_exc())
            else:
                debug_print("Feature columns match model's expected features")
                
            # Explicitly reorder columns to match model's expected order
            features_df = features_df[expected_columns]
            debug_print("Features explicitly reordered to match exact model sequence")
        
        # Check for any remaining null values
        null_after = features_df.isnull().sum().sum()
        if null_after > 0:
            debug_print(f"WARNING: {null_after} null values still present after processing")
            # Force replace any remaining nulls
            features_df = features_df.fillna(0)
            
        return features_df
        
    except Exception as e:
        debug_print(f"Error processing features: {e}")
        debug_print(traceback.format_exc())
        return None



def sample_features(features_df: pd.DataFrame) -> pd.DataFrame:
    """
    Apply sampling techniques to balance the feature set before prediction
    
    Args:
        features_df: DataFrame of processed features
        
    Returns:
        DataFrame of sampled features
    """
    debug_print("Applying sampling to features...")
    
    # For a single sample, we don't need to balance classes
    # This function would be more useful when processing multiple samples
    # But we'll keep it for future extensions
    
    # Apply feature scaling/normalization if needed
    # This is important for many ML algorithms
    try:
        # For numerical features that might need scaling
        # Here we could apply StandardScaler or MinMaxScaler
        # But we'll assume the model was trained on raw features
        
        # Check for extreme outliers and cap if necessary
        for column in features_df.columns:
            if features_df[column].dtype in [np.int64, np.float64]:
                # Check for extremely large values
                if features_df[column].max() > 1e9:  # Arbitrary threshold
                    debug_print(f"Capping extreme values in column {column}")
                    features_df[column] = features_df[column].clip(upper=1e9)
        
        debug_print("Sampling/processing complete")
        return features_df
        
    except Exception as e:
        debug_print(f"Error during sampling: {e}")
        debug_print(traceback.format_exc())
        # Return original data if sampling fails
        return features_df

@app.route('/predict', methods=['POST'])
def predict():
    """API endpoint for malware prediction with improved error handling and response format"""
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
        
        # Apply sampling techniques
        debug_print("Applying sampling techniques...")
        sampled_features = sample_features(processed_features)
        
        # Make prediction
        debug_print("Making prediction with sampled features...")
        try:
            prediction = MODEL.predict(sampled_features)
            debug_print(f"Raw prediction result: {prediction}")
            
            prediction_result = int(prediction[0]) if isinstance(prediction[0], (int, np.integer)) else str(prediction[0])
            debug_print(f"Processed prediction result: {prediction_result}")
            
            # Get prediction probabilities if available
            prediction_proba = None
            if hasattr(MODEL, 'predict_proba'):
                try:
                    probas = MODEL.predict_proba(sampled_features)
                    debug_print(f"Prediction probabilities: {probas}")
                    if len(probas[0]) >= 2:
                        # Probability for the malicious class
                        # Note: sklearn models typically use class 1 for the positive class
                        # But we need to verify this assumption
                        prediction_proba = float(probas[0][1])
                        debug_print(f"Malicious probability: {prediction_proba:.4f}")
                except Exception as e:
                    debug_print(f"Error getting prediction probabilities: {e}")
            
            # Convert numeric prediction to string format
            # IMPORTANT: Assuming 1 = malicious and 0 = benign
            # This is a common convention but may need to be verified
            prediction_str = "malicious" if prediction_result == 1 else "benign"
            debug_print(f"Converted prediction string: {prediction_str}")
            
            # Return prediction result with consistent messaging
            result = {
                "prediction": prediction_str,
                "raw_prediction": prediction_result,
                "filename": original_filename
            }
            
            if prediction_proba is not None:
                result["probability"] = prediction_proba
                
            # Ensure message is consistent with prediction
            if prediction_str == "malicious":
                result["message"] = "This file appears to be malicious."
                result["recommendation"] = "Exercise caution with this file. It contains patterns consistent with malware."
            else:
                result["message"] = "This file appears to be benign."
                result["recommendation"] = "No malicious patterns detected, but always exercise caution with executable files."
                
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
    """API endpoint to check system status"""
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
    
    # Check model details
    model_info = {}
    if MODEL is not None:
        try:
            # Get model type
            model_info["type"] = type(MODEL).__name__
            
            # Get feature count if available
            if hasattr(MODEL, 'feature_names_in_'):
                model_info["feature_count"] = len(MODEL.feature_names_in_)
                
            # Get other model attributes
            if hasattr(MODEL, 'n_estimators'):
                model_info["n_estimators"] = MODEL.n_estimators
                
            if hasattr(MODEL, 'classes_'):
                model_info["classes"] = MODEL.classes_.tolist()
        except Exception as e:
            debug_print(f"Error getting model info: {e}")
            model_info["error"] = str(e)
    
    response = {
        "status": "API is running",
        "model_status": model_status,
        "model_info": model_info,
        "upload_directory": f"{UPLOAD_FOLDER} ({'exists' if upload_dir_exists else 'missing'})",
        "debug_mode": DEBUG,
        "version": "1.1.0"  # Added for version tracking
    }
    
    debug_print(f"Returning status: {response}")
    return jsonify(response), 200

@app.route('/list_uploads', methods=['GET'])
def list_uploads():
    """API endpoint to list uploaded files"""
    debug_print("List uploads endpoint called")
    
    try:
        if not os.path.exists(UPLOAD_FOLDER):
            return jsonify({"error": "Upload directory does not exist"}), 404
            
        files = os.listdir(UPLOAD_FOLDER)
        file_details = []
        
        for filename in files:
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(file_path):
                try:
                    # Get more detailed file information
                    file_details.append({
                        "name": filename,
                        "size": os.path.getsize(file_path),
                        "last_modified": os.path.getmtime(file_path),
                        "created": os.path.getctime(file_path)
                    })
                except Exception as e:
                    debug_print(f"Error getting details for {filename}: {e}")
                    file_details.append({
                        "name": filename,
                        "error": str(e)
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