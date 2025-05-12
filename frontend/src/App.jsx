import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import Footer from './components/Footer';
import Scanner from './components/Scanner';
import { fetchScanStats } from './services/api';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [stats, setStats] = useState({
    filesScanned: 0,
    threatsDetected: 0,
    detectionRate: 0
  });
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    // Fetch statistics when component mounts
    const getStats = async () => {
      try {
        const data = await fetchScanStats();
        setStats(data);
      } catch (error) {
        console.error('Failed to fetch statistics:', error);
      }
    };
    
    getStats();
  }, []);

  const toggleMobileMenu = () => {
    setIsMobileMenuOpen(!isMobileMenuOpen);
  };

  return (
    <div className="app">
      
      <main className="main-content">
        <div className="dashboard">
          <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
          
          {activeTab === 'scanner' && (
            <Scanner stats={stats} />
          )}
          
          {/* Other components would be conditionally rendered here based on activeTab */}
          {activeTab === 'deepscan' && (
            <div className="content-area">
              <h2 className="page-title">Deep Scan</h2>
              <p>Deep Scan component would be implemented here.</p>
            </div>
          )}
        </div>
      </main>
      
    </div>
  );
}

export default App;