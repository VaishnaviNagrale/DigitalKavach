import React, { useState, useEffect } from 'react';
import { backgroundScanning, getSavedScanResults } from '../services/api';

const BackgroundScanning = () => {
  const [scanData, setScanData] = useState(null);
  const [savedResults, setSavedResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fetchingSaved, setFetchingSaved] = useState(false);
  const [error, setError] = useState(null);

  // Fetch saved results on component mount
  useEffect(() => {
    fetchSavedResults();
  }, []);

  const fetchSavedResults = async () => {
    try {
      setFetchingSaved(true);
      const data = await getSavedScanResults();
      setSavedResults(data);
    } catch (err) {
      console.error('Error fetching saved results:', err);
    } finally {
      setFetchingSaved(false);
    }
  };

  const startScan = async () => {
    try {
      setLoading(true);
      setError(null);
      setScanData(null);
      const data = await backgroundScanning();
      setScanData(data);
      
      // After completing a scan, fetch the updated saved results
      fetchSavedResults();
    } catch (err) {
      console.error('Error fetching scan data:', err);
      setError('Failed to fetch scan data. Please try again later.');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (timestamp) => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const renderList = (list, label, iconClass) => {
    if (!list || list.length === 0) return null;
    
    return (
      <div className="content-section">
        <h3>
          <span className={`status-icon ${iconClass}`}></span>
          {label} ({list.length})
        </h3>
        <div className="file-list">
          {list.map((item, index) => (
            <div key={index} className="file-item">
              <div className="file-path">{item.filepath}</div>
              <div className={`file-status ${getStatusClass(item.result.prediction || item.result.status)}`}>
                {item.result.prediction || item.result.status}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const getStatusClass = (status) => {
    if (status === 'malicious') return 'status-malicious';
    if (status === 'benign') return 'status-benign';
    return 'status-error';
  };

  return (
    <div className="content-area">
      <h2 className="page-title">System Scanner</h2>
      
      <div className="description">
        <p>
          Our system scanner analyzes files and directories for potential threats.
          It uses machine learning algorithms to detect malicious files and provides detailed reports on the scan results.
        </p>
        <p><strong>Note:</strong> For educational purposes only. Do not use for critical security decisions.</p>
        <button 
          className={`scan-button`} 
          onClick={startScan}
          disabled={loading}
        >
          {loading ? 'Scanning...' : scanData ? 'Scan Again' : 'Start Scan'}
        </button>
      </div>

      {loading && (
        <div className="loading-container">
          <div className="loader"></div>
          <p>Scanning system files. Please wait...</p>
        </div>
      )}

      {error && (
        <div className="error-message">
          <p>{error}</p>
        </div>
      )}

      {scanData && !loading && (
        <div className="scan-results">
          <div className="scan-info">
            <div className="scan-time">
              <span className="info-label">Last Scan:</span>
              <span className="info-value">{formatDate(scanData.last_scan_time)}</span>
            </div>
            <div className="scan-summary">
              <div className="summary-item">
                <span className="summary-count">{scanData.summary.total}</span>
                <span className="summary-label">Total Scanned</span>
              </div>
              <div className="summary-item malicious">
                <span className="summary-count">{scanData.summary.malicious}</span>
                <span className="summary-label">Malicious</span>
              </div>
              <div className="summary-item benign">
                <span className="summary-count">{scanData.summary.benign}</span>
                <span className="summary-label">Benign</span>
              </div>
              <div className="summary-item error">
                <span className="summary-count">{scanData.summary.error}</span>
                <span className="summary-label">Errors</span>
              </div>
            </div>
          </div>

          <div className="scan-details">
            {renderList(scanData.results.malicious, 'Malicious Files', 'icon-malicious')}
            {renderList(scanData.results.benign, 'Benign Files', 'icon-benign')}
            {renderList(scanData.results.error, 'Files with Error', 'icon-error')}
          </div>
        </div>
      )}

      {!scanData && !loading && !error && (
        <div className="no-scan">
          <p>Click the "Start Scan" button to begin scanning your system for potential threats.</p>
        </div>
      )}

      {savedResults && (
  <div className="saved-results">
    <h3>Previous Scan Results</h3>
    <div className="scan-info">
      <div className="scan-time">
        <span className="info-label">Last Scan:</span>
        <span className="info-value">{formatDate(savedResults.last_scan_time)}</span>
      </div>
      <div className="scan-summary">
        <div className="summary-item">
          <span className="summary-count">{savedResults.summary?.total || 0}</span>
          <span className="summary-label">Total Scanned</span>
        </div>
        <div className="summary-item malicious">
          <span className="summary-count">{savedResults.summary?.malicious || 0}</span>
          <span className="summary-label">Malicious</span>
        </div>
        <div className="summary-item benign">
          <span className="summary-count">{savedResults.summary?.benign || 0}</span>
          <span className="summary-label">Benign</span>
        </div>
        <div className="summary-item error">
          <span className="summary-count">{savedResults.summary?.error || 0}</span>
          <span className="summary-label">Errors</span>
        </div>
      </div>
    </div>

    <div className="scan-details">
      {renderList(savedResults.results?.malicious, 'Malicious Files', 'icon-malicious')}
      {renderList(savedResults.results?.benign, 'Benign Files', 'icon-benign')}
      {renderList(savedResults.results?.error, 'Files with Error', 'icon-error')}
    </div>
  </div>
)}
    </div>
  );
};

export default BackgroundScanning;