import React from 'react';
import { Link } from 'react-router-dom'; // Import Link from react-router-dom
import About from './About';

function Header({ isMobileMenuOpen, toggleMobileMenu }) {
    return (
        <header className="header">
            <div className="header-container">
                <div className="logo">
                    <svg className="logo-icon" width="40" height="40" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M12 2L4 5v6.09c0 5.05 3.41 9.76 8 10.91 4.59-1.15 8-5.86 8-10.91V5l-8-3z" fill="#4fc3f7"/>
                        <path d="M10.95 15.55L8.4 13l1.41-1.41 1.14 1.14 3.64-3.64 1.41 1.41-5.05 5.05z" fill="white"/>
                    </svg>
                    <h1>DigitalKavach</h1>
                </div>
                
                <button className="mobile-menu-btn" onClick={toggleMobileMenu}>
                    ☰
                </button>
                
                <ul className={`nav-links ${isMobileMenuOpen ? 'active' : ''}`}>
                    <li><Link to="/" className="active">Home</Link></li>
                    <li><Link to="/about">About</Link></li>
                    <li><Link to="/contact">Contact</Link></li>
                </ul>
            </div>
        </header>
    );
}

export default Header;