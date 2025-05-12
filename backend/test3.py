import os
import sys
import traceback
from typing import Dict, List, Union, Optional, Tuple
import json

# Flask imports
from flask import Flask, request, jsonify
from flask_cors import CORS

# Data processing imports
import numpy as np
import pandas as pd
import pickle

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

# List of PE-specific features expected by the model
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

# Global variable for the model
MODEL = None

# Example malware features (placeholder - you should replace with actual known malware features)
EXAMPLE_MALWARE_FEATURES = {
    "simple_malware": {
        'Machine': 332,
        'SizeOfOptionalHeader': 224,
        'Characteristics': 258,
        'MajorLinkerVersion': 2,
        'MinorLinkerVersion': 25,
        'SizeOfCode': 512000,
        'SizeOfInitializedData': 512000,
        'SizeOfUninitializedData': 0,
        'AddressOfEntryPoint': 4096,
        'BaseOfCode': 4096,
        'BaseOfData': 516096,
        'ImageBase': 4194304,
        'SectionAlignment': 4096,
        'FileAlignment': 512,
        'MajorOperatingSystemVersion': 4,
        'MinorOperatingSystemVersion': 0,
        'MajorImageVersion': 0,
        'MinorImageVersion': 0,
        'MajorSubsystemVersion': 4,
        'MinorSubsystemVersion': 0,
        'SizeOfImage': 1044480,
        'SizeOfHeaders': 1024,
        'CheckSum': 0,
        'Subsystem': 2,
        'DllCharacteristics': 0,
        'SizeOfStackReserve': 1048576,
        'SizeOfStackCommit': 4096,
        'SizeOfHeapReserve': 1048576,
        'SizeOfHeapCommit': 4096,
        'LoaderFlags': 0,
        'NumberOfRvaAndSizes': 16,
        'SectionsNb': 3,
        'SectionsMeanEntropy': 7.1,
        'SectionsMinEntropy': 6.5,
        'SectionsMaxEntropy': 7.8,
        'SectionsMeanRawsize': 512000,
        'SectionsMinRawsize': 512000,
        'SectionMaxRawsize': 512000,
        'SectionMaxVirtualsize': 512000,
        'SectionsMeanVirtualsize': 512000,
        'SectionsMinVirtualsize': 512000,
        'ImportsNbDLL': 3,
        'ImportsNb': 30,
        'ImportsNbOrdinal': 0,
        'ExportNb': 0,
        'ResourcesNb': 0,
        'ResourcesMeanEntropy': 0,
        'ResourcesMinEntropy': 0,
        'ResourcesMaxEntropy': 0,
        'ResourcesMeanSize': 0,
        'ResourcesMinSize': 0,
        'ResourcesMaxSize': 0,
        'LoadConfigurationSize': 0,
        'VersionInformationSize': 0
    },
    "ransomware_sample": {
        'Machine': 332,
        'SizeOfOptionalHeader': 224,
        'Characteristics': 258,
        'MajorLinkerVersion': 11,
        'MinorLinkerVersion': 0,
        'SizeOfCode': 819200,
        'SizeOfInitializedData': 1433600,
        'SizeOfUninitializedData': 0,
        'AddressOfEntryPoint': 150784,
        'BaseOfCode': 4096,
        'BaseOfData': 823296,
        'ImageBase': 4194304,
        'SectionAlignment': 4096,
        'FileAlignment': 512,
        'MajorOperatingSystemVersion': 5,
        'MinorOperatingSystemVersion': 1,
        'MajorImageVersion': 5,
        'MinorImageVersion': 1,
        'MajorSubsystemVersion': 5,
        'MinorSubsystemVersion': 1,
        'SizeOfImage': 2277376,
        'SizeOfHeaders': 1024,
        'CheckSum': 2273953,
        'Subsystem': 2,
        'DllCharacteristics': 0,
        'SizeOfStackReserve': 1048576,
        'SizeOfStackCommit': 16384,
        'SizeOfHeapReserve': 1048576,
        'SizeOfHeapCommit': 4096,
        'LoaderFlags': 0,
        'NumberOfRvaAndSizes': 16,
        'SectionsNb': 5,
        'SectionsMeanEntropy': 7.4,
        'SectionsMinEntropy': 6.2,
        'SectionsMaxEntropy': 7.98,
        'SectionsMeanRawsize': 450560,
        'SectionsMinRawsize': 0,
        'SectionMaxRawsize': 1433600,
        'SectionMaxVirtualsize': 1433600,
        'SectionsMeanVirtualsize': 450560,
        'SectionsMinVirtualsize': 0,
        'ImportsNbDLL': 8,
        'ImportsNb': 193,
        'ImportsNbOrdinal': 0,
        'ExportNb': 0,
        'ResourcesNb': 23,
        'ResourcesMeanEntropy': 4.3,
        'ResourcesMinEntropy': 0.0,
        'ResourcesMaxEntropy': 7.98,
        'ResourcesMeanSize': 11946,
        'ResourcesMinSize': 24,
        'ResourcesMaxSize': 104344,
        'LoadConfigurationSize': 72,
        'VersionInformationSize': 1
    },
    "trojan_sample": {
        'Machine': 332,
        'SizeOfOptionalHeader': 224,
        'Characteristics': 270,
        'MajorLinkerVersion': 9,
        'MinorLinkerVersion': 0,
        'SizeOfCode': 65536,
        'SizeOfInitializedData': 131072,
        'SizeOfUninitializedData': 0,
        'AddressOfEntryPoint': 108096,
        'BaseOfCode': 69632,
        'BaseOfData': 135168,
        'ImageBase': 4194304,
        'SectionAlignment': 4096,
        'FileAlignment': 512,
        'MajorOperatingSystemVersion': 5,
        'MinorOperatingSystemVersion': 1,
        'MajorImageVersion': 0,
        'MinorImageVersion': 0,
        'MajorSubsystemVersion': 5,
        'MinorSubsystemVersion': 1,
        'SizeOfImage': 266240,
        'SizeOfHeaders': 1024,
        'CheckSum': 0,
        'Subsystem': 2,
        'DllCharacteristics': 512,
        'SizeOfStackReserve': 1048576,
        'SizeOfStackCommit': 4096,
        'SizeOfHeapReserve': 1048576,
        'SizeOfHeapCommit': 4096,
        'LoaderFlags': 0,
        'NumberOfRvaAndSizes': 16,
        'SectionsNb': 5,
        'SectionsMeanEntropy': 6.5,
        'SectionsMinEntropy': 3.8,
        'SectionsMaxEntropy': 7.95,
        'SectionsMeanRawsize': 31744,
        'SectionsMinRawsize': 512,
        'SectionMaxRawsize': 65536,
        'SectionMaxVirtualsize': 127488,
        'SectionsMeanVirtualsize': 43520,
        'SectionsMinVirtualsize': 1024,
        'ImportsNbDLL': 5,
        'ImportsNb': 104,
        'ImportsNbOrdinal': 0,
        'ExportNb': 0,
        'ResourcesNb': 11,
        'ResourcesMeanEntropy': 4.9,
        'ResourcesMinEntropy': 2.2,
        'ResourcesMaxEntropy': 6.8,
        'ResourcesMeanSize': 5818,
        'ResourcesMinSize': 376,
        'ResourcesMaxSize': 23120,
        'LoadConfigurationSize': 0,
        'VersionInformationSize': 1
    },
    "benign_sample": {
        'Machine': 332,
        'SizeOfOptionalHeader': 224,
        'Characteristics': 8226,
        'MajorLinkerVersion': 14,
        'MinorLinkerVersion': 0,
        'SizeOfCode': 143360,
        'SizeOfInitializedData': 57344,
        'SizeOfUninitializedData': 0,
        'AddressOfEntryPoint': 59104,
        'BaseOfCode': 4096,
        'BaseOfData': 147456,
        'ImageBase': 4194304,
        'SectionAlignment': 4096,
        'FileAlignment': 512,
        'MajorOperatingSystemVersion': 6,
        'MinorOperatingSystemVersion': 0,
        'MajorImageVersion': 0,
        'MinorImageVersion': 0,
        'MajorSubsystemVersion': 6,
        'MinorSubsystemVersion': 0,
        'SizeOfImage': 208896,
        'SizeOfHeaders': 512,
        'CheckSum': 0,
        'Subsystem': 3,
        'DllCharacteristics': 33088,
        'SizeOfStackReserve': 1048576,
        'SizeOfStackCommit': 4096,
        'SizeOfHeapReserve': 1048576,
        'SizeOfHeapCommit': 4096,
        'LoaderFlags': 0,
        'NumberOfRvaAndSizes': 16,
        'SectionsNb': 3,
        'SectionsMeanEntropy': 5.8,
        'SectionsMinEntropy': 4.9,
        'SectionsMaxEntropy': 6.4,
        'SectionsMeanRawsize': 66560,
        'SectionsMinRawsize': 1536,
        'SectionMaxRawsize': 143360,
        'SectionMaxVirtualsize': 143360,
        'SectionsMeanVirtualsize': 68096,
        'SectionsMinVirtualsize': 4096,
        'ImportsNbDLL': 3,
        'ImportsNb': 34,
        'ImportsNbOrdinal': 0,
        'ExportNb': 5,
        'ResourcesNb': 1,
        'ResourcesMeanEntropy': 3.0,
        'ResourcesMinEntropy': 3.0,
        'ResourcesMaxEntropy': 3.0,
        'ResourcesMeanSize': 752,
        'ResourcesMinSize': 752,
        'ResourcesMaxSize': 752,
        'LoadConfigurationSize': 112,
        'VersionInformationSize': 1
    }
}

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
            # Add your code logic here
            pass
        except Exception as e:
            debug_print(f"Error occurred: {e}")
            debug_print(traceback.format_exc())
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
    
    try:
        # For numerical features that might need scaling
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

@app.route('/analyze_features', methods=['POST'])
def analyze_features():
    """API endpoint for analyzing predefined malware features"""
    debug_print("==== /analyze_features API endpoint called ====")
    
    # Check if model is loaded
    global MODEL
    if MODEL is None:
        debug_print("Model not loaded, attempting to load...")
        if not load_model():
            return jsonify({"error": "Model not loaded properly"}), 500
    
    try:
        # Get request data
        data = request.get_json()
        debug_print(f"Received request data: {data}")
        
        # Check if valid feature set name is provided
        if not data or 'feature_set' not in data:
            # If no specific feature set is provided, return all available feature sets
            return jsonify({
                "available_feature_sets": list(EXAMPLE_MALWARE_FEATURES.keys()),
                "message": "Please specify a feature_set from the available options"
            }), 200
            
        feature_set_name = data['feature_set']
        debug_print(f"Requested feature set: {feature_set_name}")
        
        # Check if the requested feature set exists
        if feature_set_name not in EXAMPLE_MALWARE_FEATURES:
            return jsonify({
                "error": f"Feature set '{feature_set_name}' not found",
                "available_feature_sets": list(EXAMPLE_MALWARE_FEATURES.keys())
            }), 400
            
        # Get the requested feature set
        features = EXAMPLE_MALWARE_FEATURES[feature_set_name]
        debug_print(f"Using feature set: {feature_set_name} with {len(features)} features")
        
        # Allow custom features to be passed directly
        if 'custom_features' in data and isinstance(data['custom_features'], dict):
            debug_print("Using custom features provided in request")
            # Merge custom features with the base feature set
            features.update(data['custom_features'])
            debug_print(f"Updated with custom features, now has {len(features)} features")
        
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
                        prediction_proba = float(probas[0][1])
                        debug_print(f"Malicious probability: {prediction_proba:.4f}")
                except Exception as e:
                    debug_print(f"Error getting prediction probabilities: {e}")
            
            # Convert numeric prediction to string format
            prediction_str = "malicious" if prediction_result == 1 else "benign"
            debug_print(f"Converted prediction string: {prediction_str}")
            
            # Return detailed analysis including all features and prediction
            result = {
                "prediction": prediction_str,
                "raw_prediction": prediction_result,
                "feature_set": feature_set_name,
                "analyzed_features": features
            }
            
            if prediction_proba is not None:
                result["probability"] = prediction_proba
                
            # Add the model's feature importance if available
            if hasattr(MODEL, 'feature_importances_'):
                # Create a dictionary of feature importances
                importances = MODEL.feature_importances_
                feature_importances = {}
                
                if hasattr(MODEL, 'feature_names_in_'):
                    feature_names = MODEL.feature_names_in_
                    # Sort features by importance
                    sorted_indices = importances.argsort()[::-1]
                    
                    # Get top 10 important features
                    top_features = [(feature_names[i], float(importances[i])) 
                                   for i in sorted_indices[:10]]
                    
                    # Format for JSON response
                    feature_importances = dict(top_features)
                    
                    # Also identify which features contributed most to this specific prediction
                    # For this sample we'll just use the feature values multiplied by importance
                    # A more sophisticated approach would use SHAP values or similar
                    feature_contributions = {}
                    for i, name in enumerate(feature_names):
                        if name in features:
                            contribution = features[name] * importances[i]
                            feature_contributions[name] = float(contribution)
                    
                    # Sort and get top contributors
                    top_contributors = dict(sorted(feature_contributions.items(), 
                                                 key=lambda x: abs(x[1]), 
                                                 reverse=True)[:10])
                    
                    result["feature_importance"] = feature_importances
                    result["top_contributors"] = top_contributors
                
            # Ensure message is consistent with prediction
            if prediction_str == "malicious":
                result["message"] = "This feature set appears to be malicious."
                result["recommendation"] = "The model has detected patterns consistent with malware."
            else:
                result["message"] = "This feature set appears to be benign."
                result["recommendation"] = "No malicious patterns detected in these features."
                
            debug_print(f"Returning analysis result")
            return jsonify(result), 200
            
        except Exception as e:
            debug_print(f"Error during prediction: {e}")
            debug_print(traceback.format_exc())
            return jsonify({"error": f"Error during prediction: {str(e)}"}), 500

    except Exception as e:
        debug_print(f"Unhandled error in analyze_features endpoint: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/add_malware_features', methods=['POST'])
def add_malware_features():
    """API endpoint to add new malware feature sets to the example database"""
    debug_print("==== /add_malware_features API endpoint called ====")
    
    try:
        # Get request data
        data = request.get_json()
        debug_print(f"Received request data: {data}")
        
        if not data or 'name' not in data or 'features' not in data:
            return jsonify({"error": "Missing required fields: 'name' and 'features'"}), 400
            
        name = data['name']
        features = data['features']
        
        # Validate features
        missing_features = set(FEATURES) - set(features.keys())
        if missing_features:
            debug_print(f"Warning: Missing features in submitted data: {missing_features}")
            # We'll still accept it but add a warning to the response
        
        # Add to our example database
        EXAMPLE_MALWARE_FEATURES[name] = features
        debug_print(f"Added new feature set '{name}' with {len(features)} features")
        
        return jsonify({
            "success": True,
            "message": f"Added feature set '{name}' successfully",
            "available_feature_sets": list(EXAMPLE_MALWARE_FEATURES.keys()),
            "warnings": f"Missing features: {list(missing_features)}" if missing_features else None
        }), 201
        
    except Exception as e:
        debug_print(f"Error adding malware features: {e}")
        debug_print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route('/list_malware_features', methods=['GET'])
def list_malware_features():
    """API endpoint to list all available malware feature sets"""
    debug_print("==== /list_malware_features API endpoint called ====")
    
    try:
        # Get query parameters
        include_details = request.args.get('include_details', 'false').lower() == 'true'
        
        if include_details:
            # Return full feature details for each set
            result = EXAMPLE_MALWARE_FEATURES
        else:
            # Return just the names and feature counts
            result = {name: len(features) for name, features in EXAMPLE_MALWARE_FEATURES.items()}
            
        return jsonify({
            "feature_sets": result,
            "count": len(EXAMPLE_MALWARE_FEATURES)
        }), 200
        
    except Exception as e:
        debug_print(f"Error listing malware features: {e}")
        debug_print(traceback.format_exc())

        @app.route('/batch_analyze', methods=['POST'])
        def batch_analyze():
            """API endpoint to analyze multiple feature sets in one request"""
            debug_print("==== /batch_analyze API endpoint called ====")
            
            # Check if model is loaded
            global MODEL
            if MODEL is None:
                debug_print("Model not loaded, attempting to load...")
                if not load_model():
                    return jsonify({"error": "Model not loaded properly"}), 500
            
            try:
                # Get request data
                data = request.get_json()
                debug_print(f"Received batch request")
                
                if not data or 'feature_sets' not in data:
                    # If no specific feature sets provided, analyze all available ones
                    feature_sets = list(EXAMPLE_MALWARE_FEATURES.keys())
                    debug_print(f"No feature sets specified, analyzing all {len(feature_sets)} available sets")
                else:
                    feature_sets = data['feature_sets']
                    debug_print(f"Analyzing {len(feature_sets)} specified feature sets")
                
                results = {}
                
                for feature_set_name in feature_sets:
                    # Check if the requested feature set exists
                    if feature_set_name not in EXAMPLE_MALWARE_FEATURES:
                        debug_print(f"Feature set '{feature_set_name}' not found, skipping")
                        results[feature_set_name] = {"error": "Feature set not found"}
                        continue
                        
                    # Get the requested feature set
                    features = EXAMPLE_MALWARE_FEATURES[feature_set_name]
                    debug_print(f"Processing feature set: {feature_set_name}")
                    
                    # Process features for prediction
                    processed_features = process_features(features)
                    
                    if processed_features is None:
                        debug_print(f"Feature processing failed for {feature_set_name}")
                        results[feature_set_name] = {"error": "Failed to process features"}
                        continue
                    else:
                        debug_print(f"Feature processing succeeded for {feature_set_name}")
                    
                        # Apply sampling techniques
                        sampled_features = sample_features(processed_features)
                        debug_print(f"Sampling succeeded for {feature_set_name}")
                        
                        # Make prediction
                        try:
                            prediction = MODEL.predict(sampled_features)
                            prediction_result = int(prediction[0]) if isinstance(prediction[0], (int, np.integer)) else str(prediction[0])
                            prediction_str = "malicious" if prediction_result == 1 else "benign"
                            
                            # Get prediction probabilities if available
                            prediction_proba = None
                            if hasattr(MODEL, 'predict_proba'):
                                probas = MODEL.predict_proba(sampled_features)
                                if len(probas[0]) >= 2:
                                    prediction_proba = float(probas[0][1])
                            
                            results[feature_set_name] = {
                                "prediction": prediction_str,
                                "raw_prediction": prediction_result,
                                "probability": prediction_proba
                            }
                            debug_print(f"Prediction for {feature_set_name}: {results[feature_set_name]}")
                        except Exception as e:
                            debug_print(f"Error during prediction for {feature_set_name}: {e}")
                            debug_print(traceback.format_exc())
                            results[feature_set_name] = {"error": f"Prediction error: {str(e)}"}
                
                return jsonify({"results": results}), 200
            
            except Exception as e:
                debug_print(f"Unhandled error in batch_analyze endpoint: {e}")
                debug_print(traceback.format_exc())
                return jsonify({"error": str(e)}), 500
            
    return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
     loaded = load_model()

