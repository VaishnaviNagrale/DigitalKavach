import React, { useState } from 'react';
import StatCard from './StatCard';
import FileUpload from './FileUpload';
import ResultCard from './ResultCard';
import LoadingSpinner from './LoadingSpinner';
import { scanFile } from '../services/api';

function Scanner({ stats }) {
  const [file, setFile] = useState(null);
  const [fileInfo, setFileInfo] = useState('No file selected');
  const [isFileValid, setIsFileValid] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  
  const handleFileChange = (selectedFile) => {
    setFile(selectedFile);
    if (selectedFile) {
      if (selectedFile.name.toLowerCase().endsWith('.exe')) {
        setFileInfo(`Selected: ${selectedFile.name} (${formatFileSize(selectedFile.size)})`);
        setIsFileValid(true);
        setError('');
      } else {
        setIsFileValid(false);
        setFileInfo('Invalid file type. Please select an .exe file.');
      }
    } else {
      setFileInfo('No file selected');
    }
    
    // Reset results when a new file is selected
    setResult(null);
  };
  
  const formatFileSize = (size) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    let i = 0;
    while (size >= 1024 && i < sizes.length - 1) {
      size /= 1024;
      i++;
    }
    return `${size.toFixed(2)} ${sizes[i]}`;
  };
  
  const handleAnalyzeClick = async () => {
    if (!file) {
      setError('Please select a file first.');
      return;
    }
    
    setLoading(true);
    setError('');
    setResult(null);
    
    try {
      const scanResult = await scanFile(file);
      setResult(scanResult);
    } catch (err) {
      console.error('Scan failed:', err);
      setError('Error occurred while analyzing the file. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="content-area">
      <h2 className="page-title">File Scanner</h2>
      
      <div className="description">
        <p>
          Our advanced malware detection system uses machine learning algorithms to analyze executable files and detect potential threats. 
          Simply upload an .exe file, and our system will scan its properties to determine if it's safe to use.
        </p>
        <p><strong>Note:</strong> For educational purposes only. Do not use for critical security decisions.</p>
      </div>
      
      <div className="upload-container">
        <FileUpload 
          onFileChange={handleFileChange}
          fileInfo={fileInfo}
          isFileValid={isFileValid}
        />
        
        <button 
          className="analyze-btn" 
          disabled={!file || !isFileValid || loading}
          onClick={handleAnalyzeClick}
        >
          Analyze File
        </button>
      </div>
      
      {loading && <LoadingSpinner message="Analyzing file signature and behavior patterns..." />}
      
      {error && <div className="error">{error}</div>}
      
      {result && (
        <ResultCard
          isSafe={result.prediction === 'benign'}
          title={result.prediction === 'benign' ? 'Safe File Detected' : 'Potentially Harmful File'}
          message={
            result.prediction === 'benign' 
              ? 'Our analysis has determined that this file is safe to use. No malicious patterns or behaviors were detected.'
              : 'Our analysis has detected potentially malicious patterns in this file. We recommend against using it.'
          }
          details={result.details}
        />
      )}
    </div>
  );
}

export default Scanner;
