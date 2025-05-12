import React from 'react';

function Footer() {
  return (
    <footer className="footer">
      <div className="footer-bottom">
        <p>&copy; {new Date().getFullYear()} SecureGuard. All Rights Reserved.</p>
      </div>
    </footer>
  );
}

export default Footer;
