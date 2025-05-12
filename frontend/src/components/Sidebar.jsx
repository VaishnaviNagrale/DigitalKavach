import React from 'react';

function Sidebar({ activeTab, setActiveTab }) {
  const menuItems = [
    { id: 'scanner', icon: '🛡️', label: 'File Scanner' },
    { id: 'deepscan', icon: '🔍', label: 'Deep Scan' },
  ];

  return (
    <div className="sidebar">
      <h3 className="sidebar-title">Protection Tools</h3>
      <ul className="sidebar-menu">
        {menuItems.map(item => (
          <li key={item.id}>
            <a 
              href="#" 
              className={activeTab === item.id ? 'active' : ''}
              onClick={(e) => {
                e.preventDefault();
                setActiveTab(item.id);
              }}
            >
              <span className="icon">{item.icon}</span>
              {item.label}
            </a>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default Sidebar;
