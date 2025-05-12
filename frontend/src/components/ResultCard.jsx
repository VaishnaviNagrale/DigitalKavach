import React, { useState } from 'react';

function ResultCard({ isSafe, title, message, details }) {
  const [showDetails, setShowDetails] = useState(false);
  
  const toggleDetails = () => {
    setShowDetails(!showDetails);
  };
  
  return (
    <div className={`result ${isSafe ? 'safe' : 'danger'}`}>
      <h3>
        <span className="result-icon">{isSafe ? '✅' : '⚠️'}</span>
        {title}
      </h3>
      
      <p>{message}</p>
      
    </div>
  );
}

export default ResultCard;
