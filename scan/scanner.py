from email import message
import os
import sys
import psutil
import traceback
import pandas as pd
import numpy as np
import pefile
import pickle
import joblib

# Enhanced debugging
DEBUG = True

def debug_print(message):
    """Helper function for consistent debug output"""
    if DEBUG:
        print(f"[DEBUG] {message}")
        sys.stdout.flush()

# Define the features we need to extract from PE files
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

# Global model variable
MODEL = None

def get_running_exe_files():
    """Get a list of all running executable files"""
    exe_files = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            path = proc.info['exe']
            name = proc.info['name']
            if path:
                exe_lower = path.lower()
                if exe_lower.endswith('.exe') and os.path.exists(path):
                    if not exe_lower.startswith('c:\\windows') and 'programdata' not in exe_lower:
                      exe_files.append(path)
            # Fallback: match by name if exe path is missing
            elif name and name.endswith('.exe'):
                for p in psutil.process_iter(['pid', 'name', 'exe']):
                    if p.info['name'] == name and p.info['exe']:
                        if os.path.exists(p.info['exe']):
                            exe_files.append(p.info['exe'])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return list(set(exe_files))  # Remove duplicates

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

def extract_exe_features(filepath):
    """Extract features from an executable file for malware prediction"""
    
    if not os.path.exists(filepath):
        debug_print(f"ERROR: File does not exist at path: {filepath}")
        return None
        
    features = {}
    
    # Initialize all features with 0 as default value
    for feature in FEATURES:
        features[feature] = 0
    
    try:
        pe = pefile.PE(filepath)
        
        # Extract basic features
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics
        
        # Extract optional header features
        if hasattr(pe, 'OPTIONAL_HEADER'):
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
            features['SectionsNb'] = section_count
            
            # Calculate entropy-related features
            try:
                entropies = [section.get_entropy() for section in pe.sections]
                features['SectionsMeanEntropy'] = sum(entropies) / len(entropies)
                features['SectionsMinEntropy'] = min(entropies)
                features['SectionsMaxEntropy'] = max(entropies)
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
            except Exception as e:
                debug_print(f"Error calculating section sizes: {e}")
        else:
            debug_print("WARNING: No sections found in PE file")
        
        # Extract imports information
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            total_imports = sum(len(entry.imports) for entry in pe.DIRECTORY_ENTRY_IMPORT)
            features['ImportsNb'] = total_imports
            ordinal_count = sum(1 for entry in pe.DIRECTORY_ENTRY_IMPORT 
                              for imp in entry.imports if imp.ordinal is not None)
            features['ImportsNbOrdinal'] = ordinal_count
        else:
            debug_print("No imports found")
        
        # Extract exports information
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        
        # Extract resources information
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and pe.DIRECTORY_ENTRY_RESOURCE and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries'):
            features['ResourcesNb'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            
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
            # Don't use len() on Structure objects
            features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
        else:
            features['LoadConfigurationSize'] = 0
            
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            # Use a non-zero value to indicate presence of version info
            features['VersionInformationSize'] = 1
        else:
            features['VersionInformationSize'] = 0
                    
    except Exception as e:
        debug_print(f"ERROR reading {filepath}: {str(e)}")
        debug_print(traceback.format_exc())
        return None
    
    # Check for any missing features
    missing = set(FEATURES) - set(features.keys())
    if missing:
        debug_print(f"WARNING: Missing features after extraction: {missing}")
        # Set missing features to 0
        for feature in missing:
            features[feature] = 0
    
    # Quick sanity check on features
    return features

def process_features(features):
    
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

def scan_with_model(filepath):
    """Scan a file with the malware detection model and return results
    
    Returns a dict with prediction result and details.
    """
    debug_print(f"====== Scanning file: {filepath} ======")
    
    # Check if model is loaded
    global MODEL
    if MODEL is None:
        success = load_model()

        if not success:
            return {
                "status": "error",
                "filepath": filepath
            }
    
    try:
        # Extract features from the PE file
        features = extract_exe_features(filepath)
        
        if features is None:
            return {
                "status": "error",
                "message": "Failed to extract features from file",
                "filepath": filepath
            }
        
        # Process features for prediction
        processed_features = process_features(features)
        
        if processed_features is None:
            return {
                "status": "error",
                "message": "Failed to process features for prediction",
                "filepath": filepath
            }
        
        # Make prediction
        try:
            print(processed_features)
            prediction = MODEL.predict(processed_features)
            print("[DEBUG] Prediction:", prediction)
            
            prediction_result = int(prediction[0]) if isinstance(prediction[0], (int, np.integer)) else str(prediction[0])
            
            # Get prediction probabilities if available
            prediction_proba = None
            if hasattr(MODEL, 'predict_proba'):
                try:
                    probas = MODEL.predict_proba(processed_features)
                    if len(probas[0]) >= 2:
                        # Probability for the positive class (usually at index 1)
                        prediction_proba = float(probas[0][1])
                except Exception as e:
                    debug_print(f"Error getting prediction probabilities: {e}")
            
            # Convert numeric prediction to human-readable string
            print("[DEBUG] Prediction result:", prediction_result)
            prediction_str = "malicious" if prediction_result == 0.0 else "benign"
            print("[DEBUG] Prediction string:", prediction_str)  
            
            # Return prediction result
            result = {
                "status": "success",
                "prediction": prediction_str,
                "raw_prediction": prediction_result,
                "filepath": filepath
            }
            
            if prediction_proba is not None:
                result["probability"] = prediction_proba
            
            # FIXED: Make sure message matches the prediction_str
            if prediction_str == "malicious":
                result["message"] = "This file is potentially malicious."
            else:
                result["message"] = "This file appears to be benign."
                
            return result
            
        except Exception as e:
            debug_print(f"Error during prediction: {e}")
            debug_print(traceback.format_exc())
            return {
                "status": "error",
                "message": f"Error during prediction: {str(e)}",
                "filepath": filepath
            }

    except Exception as e:
        debug_print(f"Unhandled error in scan_with_model: {e}")
        debug_print(traceback.format_exc())
        return {
            "status": "error", 
            "message": str(e),
            "filepath": filepath
        }
def scan_running_exes():
    """Scan all currently running executable files for malware
    
    Returns a dict mapping filenames to scan results.
    """
    debug_print("Scanning currently running executable files")
    results = {}
    
    # Get all running executable files
    running_exes = get_running_exe_files()
    
    if not running_exes:
        print("No running executable files found.")
        return results
    
    print(f"Found {len(running_exes)} running executable files.")
    
    # Scan each executable file
    for filepath in running_exes:
        print(f"Scanning: {filepath}")
        result = scan_with_model(filepath)
        results[filepath] = result
    
    return results

def display_results(results):
    """Display the scan results in a formatted way"""
    print("\n===== SCAN RESULTS =====")
    print(f"Total files scanned: {len(results)}")
    
    malicious_count = 0
    benign_count = 0
    error_count = 0
    
    # Count results by category
    for filepath, result in results.items():
        if result["status"] == "error":
            error_count += 1
        elif result["prediction"] == "malicious":
            malicious_count += 1
        elif result["prediction"] == "benign":
            benign_count += 1
    
    print(f"Malicious files: {malicious_count}")
    print(f"Benign files: {benign_count}")
    print(f"Errors: {error_count}")
    print("")
    
    # Display details for each file
    for filepath, result in results.items():
        filename = os.path.basename(filepath)
        
        if result["status"] == "error":
            print(f"❌ {filename} - ERROR: {result['message']}")
        elif result["prediction"] == "malicious":
            probability = result.get("probability", 0) * 100
            print(f"🚨 {filename} - MALICIOUS ({probability:.1f}% confidence)")
        else:
            probability = 100 - (result.get("probability", 0) * 100)
            print(f"✅ {filename} - BENIGN ({probability:.1f}% confidence)")
    
    print("\n======================")

# Main function to run the scanner
def main():
    # Load the model
    success = load_model()

    if not success:
        print(f"Failed to load model: {message}")
        return
    
    print("Scanning currently running executable files...")
    results = scan_running_exes()
    
    # Display the results
    display_results(results)

if __name__ == "__main__":
    main()