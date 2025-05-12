import React from 'react';
// import { FaInfoCircle, FaLightbulb, FaShieldAlt } from 'react-icons/fa';

const About = () => {
  return (
    <div className="main-content">
      <div className="content-area">
        <h1 className="page-title">About Us</h1>
        <p className="description">
          Welcome to <strong>SafeVision</strong> – your reliable tool for analyzing and safeguarding visual content. We help users scan and assess images for safety, privacy concerns, and content integrity.
        </p>

        <div className="stats-cards">
          <div className="stat-card">
            {/* <FaInfoCircle size={40} color="#2c5364" /> */}
            <h3>Mission</h3>
            <p>
              To empower users with tools that detect image misuse, protect digital identity, and ensure transparency across platforms.
            </p>
          </div>

          <div className="stat-card">
            {/* <FaLightbulb size={40} color="#2c5364" /> */}
            <h3>Vision</h3>
            <p>
              Creating a safer digital world where individuals have full control over how their images are shared and used.
            </p>
          </div>

          <div className="stat-card">
            {/* <FaShieldAlt size={40} color="#2c5364" /> */}
            <h3>Values</h3>
            <p>
              Privacy-first approach, user empowerment, innovation, and integrity at every step of our journey.
            </p>
          </div>
        </div>

        <div className="description">
          <p>
            <strong>SafeVision</strong> uses intelligent detection mechanisms to identify duplicate, manipulated, or misused images. Whether you’re an individual, brand, or creator, our goal is to provide peace of mind and actionable insights.
          </p>
        </div>
      </div>
    </div>
  );
};

export default About;
