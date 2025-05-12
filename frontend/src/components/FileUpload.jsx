import React, { useRef } from 'react';

function FileUpload({ onFileChange, fileInfo, isFileValid }) {
  const fileInputRef = useRef(null);
  
  const handleBrowseClick = () => {
    fileInputRef.current.click();
  };
  
  const handleFileSelect = (e) => {
    const selectedFile = e.target.files[0];
    onFileChange(selectedFile);
  };
  
  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  
  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  
  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const dt = e.dataTransfer;
    const files = dt.files;
    
    if (files.length > 0) {
      onFileChange(files[0]);
    }
  };
  
  return (
    <div 
      className="upload-area"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <svg className="upload-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4C9.11 4 6.6 5.64 5.35 8.04C2.34 8.36 0 10.91 0 14C0 17.31 2.69 20 6 20H19C21.76 20 24 17.76 24 15C24 12.36 21.95 10.22 19.35 10.04ZM14 13V17H10V13H7L12 8L17 13H14Z" fill="#2c5364"/>
      </svg>
      
      <h3>Drop your .exe file here</h3>
      <p>or</p>
      
      <input 
        type="file" 
        ref={fileInputRef}
        accept=".exe" 
        style={{ display: 'none' }} 
        onChange={handleFileSelect}
      />
      
      <button 
        className="browse-btn" 
        onClick={handleBrowseClick}
      >
        Browse Files
      </button>
      
      <div className={`file-info ${!isFileValid ? 'error-text' : ''}`}>
        {fileInfo}
      </div>
    </div>
  );
}

export default FileUpload;
