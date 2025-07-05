import React, { useState } from 'react';
import './App.css';

// Mock product data
const products = [
  { id: "PROD_001", name: "Wireless Headphones", price: 59.99, inStock: true },
  { id: "PROD_002", name: "Smart Watch", price: 129.99, inStock: true },
  { id: "PROD_003", name: "Tablet Device", price: 249.99, inStock: true },
  { id: "PROD_004", name: "Bluetooth Speaker", price: 89.99, inStock: true },
  { id: "PROD_005", name: "Fitness Tracker", price: 79.99, inStock: true },
  { id: "PROD_006", name: "Gaming Mouse", price: 49.99, inStock: true },
  { id: "PROD_007", name: "Mechanical Keyboard", price: 99.99, inStock: true },
  { id: "PROD_008", name: "External SSD", price: 129.99, inStock: true },
  { id: "PROD_009", name: "Noise Cancelling Earbuds", price: 149.99, inStock: true },
  { id: "PROD_010", name: "Smart Home Hub", price: 199.99, inStock: true }
];

// Security detection logic - Enhanced with more patterns
const detectMaliciousInput = (input) => {
  const PHISHING_KEYWORDS = ['login', 'password', 'account', 'verify', 'bank', 'paypal', 'credit card', 'ssn', 'social security'];
  const MALICIOUS_DOMAINS = ['malicious-phishing.example.com', 'evil-site.com', 'steal-info.net', 'phish-attack.org'];
  const XSS_PATTERNS = [
    /<script.*?>.*?<\/script>/gi,
    /javascript:/gi,
    /onerror\s*=/gi,
    /onload\s*=/gi,
    /onmouseover\s*=/gi,
    /alert\(.*?\)/gi,
    /document\.cookie/gi,
    /eval\(.*?\)/gi,
    /<iframe.*?<\/iframe>/gi
  ];

  // XSS detection
  for (const pattern of XSS_PATTERNS) {
    if (pattern.test(input)) {
      return { 
        isMalicious: true, 
        attackType: 'XSS',
        bypassReason: "DOM-based injection bypassed initial sanitization",
        recommendations: [
          "Implement stricter Content Security Policy (CSP)",
          "Add context-aware output encoding",
          "Enhance input validation regex patterns",
          "Use DOMPurify for HTML sanitization"
        ],
        vulnerableCode: `
          // Vulnerable code
          function renderUserInput(input) {
            return \`<div>\${input}</div>\`;
          }
        `,
        fixedCode: `
          // Fixed code with sanitization
          import DOMPurify from 'dompurify';
          
          function renderUserInput(input) {
            return \`<div>\${DOMPurify.sanitize(input)}</div>\`;
          }
        `,
        filePath: "src/components/UserContent.js",
        lineNumber: 42
      };
    }
  }

  // URL detection
  try {
    const url = new URL(input);
    if (MALICIOUS_DOMAINS.some(domain => url.hostname.includes(domain))) {
      return { 
        isMalicious: true, 
        attackType: 'Malicious Redirect',
        bypassReason: "Domain not in blocklist; new phishing variant",
        recommendations: [
          "Integrate real-time domain reputation service",
          "Implement heuristics-based URL analysis",
          "Add user behavior anomaly detection",
          "Use Safe Browsing API for URL validation"
        ],
        vulnerableCode: `
          // Vulnerable redirect
          function handleRedirect(url) {
            window.location.href = url;
          }
        `,
        fixedCode: `
          // Fixed redirect with validation
          import { validateUrl } from '../security/urlValidator';
          
          function handleRedirect(url) {
            if (validateUrl(url)) {
              window.location.href = url;
            } else {
              logSecurityEvent('Invalid redirect attempt', url);
            }
          }
        `,
        filePath: "src/utils/navigation.js",
        lineNumber: 87
      };
    }
    
    const urlStr = url.toString().toLowerCase();
    if (PHISHING_KEYWORDS.some(keyword => urlStr.includes(keyword))) {
      return { 
        isMalicious: true, 
        attackType: 'Phishing URL',
        bypassReason: "Keyword pattern not detected by current filters",
        recommendations: [
          "Enhance keyword detection with NLP",
          "Implement screenshot analysis of landing pages",
          "Add time-of-click protection",
          "Integrate URL scanning services"
        ],
        vulnerableCode: `
          // Vulnerable URL detection
          function isSafeUrl(url) {
            return !url.includes('malicious');
          }
        `,
        fixedCode: `
          // Fixed URL detection with pattern matching
          const PHISHING_PATTERNS = [
            /login\\?token=[a-z0-9]+/i,
            /verify-account/,
            /bank-update/
          ];
          
          function isSafeUrl(url) {
            return !PHISHING_PATTERNS.some(pattern => pattern.test(url));
          }
        `,
        filePath: "src/security/urlValidator.js",
        lineNumber: 15
      };
    }
  } catch (e) {}

  // Phishing text detection
  const lowerInput = input.toLowerCase();
  if (PHISHING_KEYWORDS.some(keyword => lowerInput.includes(keyword))) {
    return { 
      isMalicious: true, 
      attackType: 'Phishing Content',
      bypassReason: "Contextual analysis missed semantic meaning",
      recommendations: [
        "Implement AI-based semantic analysis",
        "Add user education tooltips for suspicious content",
        "Enhance pattern matching with machine learning",
        "Integrate sentiment analysis for phishing detection"
      ],
      vulnerableCode: `
        // Vulnerable input handling
        function processUserInput(input) {
          saveToDatabase(input);
        }
      `,
      fixedCode: `
        // Fixed input handling with sanitization
        import { sanitizeInput } from '../security/inputSanitizer';
        
        function processUserInput(input) {
          const cleanInput = sanitizeInput(input);
          saveToDatabase(cleanInput);
        }
      `,
      filePath: "src/api/userController.js",
      lineNumber: 63
    };
  }

  return { isMalicious: false };
};

// Simulate email notification
const sendEmailNotification = (incident) => {
  return new Promise((resolve) => {
    setTimeout(() => {
      console.log(`Email sent for incident: ${incident.id}`);
      resolve({
        success: true,
        message: `Notification sent to security team for ${incident.attackType} attack`
      });
    }, 1500);
  });
};

// Product Card Component
const ProductCard = ({ product, updateStock, addIncident }) => {
  const [inputValue, setInputValue] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [emailStatus, setEmailStatus] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setStatusMessage('Processing your review...');
    setEmailStatus('');
    
    const detectionResult = detectMaliciousInput(inputValue);
    
    if (detectionResult.isMalicious) {
      const incident = {
        ...detectionResult,
        id: `INC-${Date.now()}`,
        payload: inputValue,
        timestamp: new Date().toISOString(),
        detectedURL: window.location.href,
        simulatedUserID: 'user_abc_123',
        simulatedUserIP: '192.168.1.100',
        userAgent: navigator.userAgent,
        referrer: document.referrer || '',
        affectedElement: `review-input-${product.id}`,
        actionTriggered: 'Item Out-of-Stock',
        productId: product.id,
        productName: product.name,
        status: 'reported',
        emailSent: false
      };
      
      // Add to incidents
      addIncident(incident);
      
      // Update product stock
      updateStock(product.id, false);
      
      // Send email notification
      setEmailStatus('Sending email notification...');
      try {
        const emailResult = await sendEmailNotification(incident);
        setEmailStatus(`Email sent: ${emailResult.message}`);
        incident.emailSent = true;
        addIncident(incident); // Update with email status
      } catch (error) {
        setEmailStatus('Failed to send email notification');
        console.error('Email error:', error);
      }
      
      setStatusMessage('Security threat detected! Product disabled.');
    } else {
      // For non-malicious submissions
      setStatusMessage('Review submitted successfully!');
    }
    
    setInputValue('');
    setIsSubmitting(false);
  };

  return (
    <div className="product-card">
      <div className="security-shield">
        <i className="fas fa-shield-alt"></i>
      </div>
      
      <div className="product-image-placeholder"></div>
      
      <div className="product-info">
        <h3>{product.name}</h3>
        <p className="product-price">${product.price.toFixed(2)}</p>
        
        <div className={`stock-status ${product.inStock ? 'in-stock' : 'out-of-stock'}`}>
          <i className={`fas fa-${product.inStock ? 'check-circle' : 'times-circle'}`}></i>
          {product.inStock ? ' In Stock' : ' Out of Stock'}
        </div>
        
        <div className="review-form">
          <h3><i className="fas fa-comment-alt"></i> Add a Review</h3>
          <form onSubmit={handleSubmit}>
            <textarea
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Share your thoughts about this product..."
              disabled={isSubmitting}
            />
            <button 
              type="submit" 
              className="submit-btn"
              disabled={isSubmitting || !inputValue.trim()}
            >
              {isSubmitting ? 'Submitting...' : 'Submit Review'}
            </button>
          </form>
          
          {statusMessage && <p className="status-message">{statusMessage}</p>}
          {emailStatus && <p className="email-status">{emailStatus}</p>}
          
          <div className="security-tip">
            <i className="fas fa-info-circle"></i>
            <span>Our security system analyzes all content for potential threats</span>
          </div>
        </div>
      </div>
    </div>
  );
};

// Special Offer Component
const SpecialOffer = ({ addIncident }) => {
  const [offerUrl, setOfferUrl] = useState('');
  const [status, setStatus] = useState('');
  const [emailStatus, setEmailStatus] = useState('');

  const handleRedirectCheck = async (e) => {
    e.preventDefault();
    setStatus('Checking offer...');
    setEmailStatus('');
    
    const detectionResult = detectMaliciousInput(offerUrl);
    
    if (detectionResult.isMalicious) {
      const incident = {
        ...detectionResult,
        id: `INC-${Date.now()}`,
        payload: offerUrl,
        timestamp: new Date().toISOString(),
        detectedURL: window.location.href,
        simulatedUserID: 'user_abc_123',
        simulatedUserIP: '192.168.1.100',
        userAgent: navigator.userAgent,
        referrer: document.referrer || '',
        affectedElement: 'special-offer-redirect',
        actionTriggered: 'Redirect Blocked',
        status: 'reported',
        emailSent: false
      };
      
      // Add to incidents
      addIncident(incident);
      
      // Send email notification
      setEmailStatus('Sending email notification...');
      try {
        const emailResult = await sendEmailNotification(incident);
        setEmailStatus(`Email sent: ${emailResult.message}`);
        incident.emailSent = true;
        addIncident(incident); // Update with email status
      } catch (error) {
        setEmailStatus('Failed to send email notification');
        console.error('Email error:', error);
      }
      
      setStatus('Security threat detected! Offer blocked.');
    } else {
      setStatus('Redirecting to special offer...');
      setTimeout(() => setStatus('Special offer loaded successfully!'), 1500);
    }
  };

  return (
    <div className="special-offer">
      <h3><i className="fas fa-gift"></i> Exclusive Special Offer</h3>
      <p>Enter URL for limited-time discount:</p>
      <form onSubmit={handleRedirectCheck}>
        <input
          type="text"
          value={offerUrl}
          onChange={(e) => setOfferUrl(e.target.value)}
          placeholder="https://example.com/special-offer"
        />
        <button type="submit" className="submit-btn">
          Claim Offer
        </button>
      </form>
      {status && <p className="status-message">{status}</p>}
      {emailStatus && <p className="email-status">{emailStatus}</p>}
      
      <div className="security-notice">
        <i className="fas fa-shield-alt"></i>
        <span>All URLs are scanned for security threats</span>
      </div>
    </div>
  );
};

// Code Vulnerability Modal
const CodeVulnerabilityModal = ({ incident, onClose, updateIncidentStatus }) => {
  if (!incident) return null;
  
  const handleResolve = () => {
    updateIncidentStatus(incident.id, 'resolved');
    onClose();
  };
  
  return (
    <div className="modal-overlay">
      <div className="code-modal">
        <div className="modal-header">
          <h3>
            <i className="fas fa-code"></i> Code Vulnerability Analysis
          </h3>
          <button onClick={onClose} className="close-btn">
            <i className="fas fa-times"></i>
          </button>
        </div>
        
        <div className="modal-body">
          <div className="incident-header">
            <div className="incident-meta">
              <div className="meta-item">
                <label>ID:</label>
                <span>{incident.id}</span>
              </div>
              <div className="meta-item">
                <label>Time:</label>
                <span>{new Date(incident.timestamp).toLocaleString()}</span>
              </div>
              <div className="meta-item">
                <label>Attack Type:</label>
                <span className={`type-badge ${incident.attackType.replace(/\s+/g, '-').toLowerCase()}`}>
                  {incident.attackType}
                </span>
              </div>
              <div className="meta-item">
                <label>Email Status:</label>
                <span className={`email-status ${incident.emailSent ? 'sent' : 'pending'}`}>
                  {incident.emailSent ? 'Sent ✓' : 'Pending'}
                </span>
              </div>
            </div>
            
            <div className="incident-details">
              <div className="detail-item">
                <label>Detected URL:</label>
                <span>{incident.detectedURL}</span>
              </div>
              <div className="detail-item">
                <label>User Agent:</label>
                <span>{incident.userAgent}</span>
              </div>
              <div className="detail-item">
                <label>Affected Element:</label>
                <span>{incident.affectedElement}</span>
              </div>
            </div>
          </div>
          
          <div className="vulnerability-info">
            <div className="info-item">
              <label>File:</label>
              <span>{incident.filePath}</span>
            </div>
            <div className="info-item">
              <label>Line:</label>
              <span>{incident.lineNumber}</span>
            </div>
            <div className="info-item">
              <label>Bypass Reason:</label>
              <span>{incident.bypassReason}</span>
            </div>
          </div>
          
          <div className="payload-section">
            <h4>Malicious Payload</h4>
            <div className="payload-content">
              {incident.payload}
            </div>
          </div>
          
          <div className="code-section">
            <h4>Vulnerable Code</h4>
            <pre className="vulnerable-code">
              {incident.vulnerableCode}
            </pre>
          </div>
          
          <div className="code-section">
            <h4>Fixed Code</h4>
            <pre className="fixed-code">
              {incident.fixedCode}
            </pre>
          </div>
          
          <div className="recommendations">
            <h4>AI Recommendations</h4>
            <ul>
              {incident.recommendations && incident.recommendations.map((rec, index) => (
                <li key={index}><i className="fas fa-check-circle"></i> {rec}</li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="modal-footer">
          <button className="copy-btn">
            <i className="fas fa-copy"></i> Copy Fixed Code
          </button>
          <button className="resolve-btn" onClick={handleResolve}>
            <i className="fas fa-check"></i> Mark as Resolved
          </button>
        </div>
      </div>
    </div>
  );
};

// Admin Dashboard Component
const AdminDashboard = ({ incidents, refreshIncidents, updateIncidentStatus }) => {
  const [activeTab, setActiveTab] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [reportStatus, setReportStatus] = useState({ type: null, generating: false, success: false });
  
  const filteredIncidents = incidents.filter(incident => {
    const statusMatch = statusFilter === 'all' || incident.status === statusFilter;
    const tabMatch = activeTab === 'all' || incident.attackType === activeTab;
    return statusMatch && tabMatch;
  });
  
  // Generate CSV security report
  const generateSecurityReport = () => {
    setReportStatus({ type: 'security', generating: true, success: false });
    
    setTimeout(() => {
      // CSV header
      let csvContent = "Incident ID,Time,Attack Type,Product,Status,Email Sent,Payload Preview\n";
      
      // Add each incident as a row
      filteredIncidents.forEach(incident => {
        csvContent += `"${incident.id}",`;
        csvContent += `"${new Date(incident.timestamp).toLocaleString()}",`;
        csvContent += `"${incident.attackType}",`;
        csvContent += `"${incident.productName || 'N/A'}",`;
        csvContent += `"${incident.status}",`;
        csvContent += `"${incident.emailSent ? 'Yes' : 'No'}",`;
        csvContent += `"${incident.payload.replace(/"/g, '""').substring(0, 100)}"\n`;
      });
      
      // Create and download the file
      const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `security_report_${new Date().toISOString().slice(0, 10)}.csv`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      setReportStatus({ type: 'security', generating: false, success: true });
    }, 1000);
  };
  
  // Generate fixed code report
  const generateFixedCodeReport = () => {
    setReportStatus({ type: 'fixed-code', generating: true, success: false });
    
    setTimeout(() => {
      // Filter incidents with fixed code
      const incidentsWithFix = filteredIncidents.filter(i => i.fixedCode && i.fixedCode.trim());
      
      // Create report content
      let reportContent = `UNIFIED SENTINEL - FIXED CODE REPORT\n`;
      reportContent += `Generated: ${new Date().toLocaleString()}\n`;
      reportContent += `Total Incidents: ${filteredIncidents.length}\n`;
      reportContent += `Incidents with Fixes: ${incidentsWithFix.length}\n\n`;
      reportContent += '='.repeat(80) + '\n\n';
      
      // Add each fixed code section
      incidentsWithFix.forEach((incident, index) => {
        reportContent += `INCIDENT #${index + 1}\n`;
        reportContent += `ID: ${incident.id}\n`;
        reportContent += `Type: ${incident.attackType}\n`;
        reportContent += `File: ${incident.filePath}:${incident.lineNumber}\n`;
        reportContent += `Status: ${incident.status}\n`;
        reportContent += `Detected: ${new Date(incident.timestamp).toLocaleString()}\n\n`;
        
        reportContent += `VULNERABLE CODE:\n${incident.vulnerableCode}\n\n`;
        reportContent += `FIXED CODE:\n${incident.fixedCode}\n\n`;
        
        reportContent += `RECOMMENDATIONS:\n`;
        incident.recommendations.forEach((rec, i) => {
          reportContent += ` ${i + 1}. ${rec}\n`;
        });
        
        reportContent += '\n' + '='.repeat(80) + '\n\n';
      });
      
      // Create and download the file
      const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.setAttribute('href', url);
      link.setAttribute('download', `fixed_code_report_${new Date().toISOString().slice(0, 10)}.txt`);
      link.style.visibility = 'hidden';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      setReportStatus({ type: 'fixed-code', generating: false, success: true });
    }, 1500);
  };
  
  const getStatusColor = (status) => {
    switch(status) {
      case 'reported': return 'status-reported';
      case 'in-progress': return 'status-in-progress';
      case 'resolved': return 'status-resolved';
      default: return '';
    }
  };
  
  const getTypeIcon = (type) => {
    switch(type) {
      case 'XSS': return 'fa-code';
      case 'Malicious Redirect': return 'fa-link';
      case 'Phishing URL': return 'fa-fish';
      case 'Phishing Content': return 'fa-comment-alt';
      default: return 'fa-shield-alt';
    }
  };

  return (
    <div className="admin-dashboard">
      <div className="dashboard-header">
        <h2><i className="fas fa-shield-alt"></i> Unified Sentinel Admin Dashboard</h2>
        <div className="controls">
          <button onClick={refreshIncidents} className="refresh-btn">
            <i className="fas fa-sync-alt"></i> Refresh
          </button>
          
          {/* Report Download Buttons */}
          <div className="report-buttons">
            <button 
              onClick={generateSecurityReport}
              disabled={reportStatus.generating && reportStatus.type === 'security'}
              className={`report-btn ${reportStatus.type === 'security' && reportStatus.success ? 'success' : ''}`}
            >
              {reportStatus.type === 'security' && reportStatus.generating ? (
                <><i className="fas fa-spinner fa-spin"></i> Generating...</>
              ) : (
                <><i className="fas fa-file-csv"></i> Security Report</>
              )}
            </button>
            
            <button 
              onClick={generateFixedCodeReport}
              disabled={reportStatus.generating && reportStatus.type === 'fixed-code'}
              className={`report-btn ${reportStatus.type === 'fixed-code' && reportStatus.success ? 'success' : ''}`}
            >
              {reportStatus.type === 'fixed-code' && reportStatus.generating ? (
                <><i className="fas fa-spinner fa-spin"></i> Generating...</>
              ) : (
                <><i className="fas fa-file-code"></i> Fixed Code Report</>
              )}
            </button>
          </div>
          
          <div className="filters">
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">All Statuses</option>
              <option value="reported">Reported</option>
              <option value="in-progress">In Progress</option>
              <option value="resolved">Resolved</option>
            </select>
          </div>
        </div>
      </div>
      
      {/* Report Status Indicator */}
      {reportStatus.success && (
        <div className="report-success">
          <i className="fas fa-check-circle"></i>
          {reportStatus.type === 'security' 
            ? "Security report downloaded successfully!" 
            : "Fixed code report downloaded successfully!"}
        </div>
      )}
      
      <div className="dashboard-stats">
        <div className="stat-card">
          <h3>Total Incidents</h3>
          <p>{incidents.length}</p>
        </div>
        <div className="stat-card">
          <h3>Active Threats</h3>
          <p>{incidents.filter(i => i.status !== 'resolved').length}</p>
        </div>
        <div className="stat-card">
          <h3>Email Notifications</h3>
          <p>{incidents.filter(i => i.emailSent).length} sent</p>
        </div>
        <div className="stat-card">
          <h3>Resolved Issues</h3>
          <p>{incidents.filter(i => i.status === 'resolved').length}</p>
        </div>
      </div>
      
      <div className="tabs">
        <button 
          className={activeTab === 'all' ? 'active' : ''}
          onClick={() => setActiveTab('all')}
        >
          <i className="fas fa-list"></i> All Incidents
        </button>
        <button 
          className={activeTab === 'XSS' ? 'active' : ''}
          onClick={() => setActiveTab('XSS')}
        >
          <i className="fas fa-code"></i> XSS Attacks
        </button>
        <button 
          className={activeTab === 'Malicious Redirect' ? 'active' : ''}
          onClick={() => setActiveTab('Malicious Redirect')}
        >
          <i className="fas fa-link"></i> Redirects
        </button>
        <button 
          className={activeTab === 'Phishing URL' ? 'active' : ''}
          onClick={() => setActiveTab('Phishing URL')}
        >
          <i className="fas fa-fish"></i> Phishing URLs
        </button>
      </div>
      
      <div className="incidents-list">
        {filteredIncidents.length === 0 ? (
          <div className="no-incidents">
            <i className="fas fa-check-circle"></i>
            <p>No security incidents found</p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Product</th>
                <th>Payload Preview</th>
                <th>Status</th>
                <th>Email</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredIncidents.map((incident) => (
                <tr key={incident.id} className={incident.status}>
                  <td>{new Date(incident.timestamp).toLocaleTimeString()}</td>
                  <td>
                    <div className="type-badge">
                      <i className={`fas ${getTypeIcon(incident.attackType)}`}></i>
                      {incident.attackType}
                    </div>
                  </td>
                  <td>{incident.productName || 'N/A'}</td>
                  <td className="payload-cell">
                    <div className="payload-preview">
                      {incident.payload.substring(0, 30)}{incident.payload.length > 30 ? '...' : ''}
                    </div>
                  </td>
                  <td>
                    <span className={`status-badge ${getStatusColor(incident.status)}`}>
                      {incident.status}
                    </span>
                  </td>
                  <td>
                    <span className={`email-status ${incident.emailSent ? 'sent' : 'pending'}`}>
                      {incident.emailSent ? 'Sent ✓' : 'Pending'}
                    </span>
                  </td>
                  <td>
                    <div className="action-buttons">
                      <select 
                        value={incident.status} 
                        onChange={(e) => updateIncidentStatus(incident.id, e.target.value)}
                        className="status-select"
                      >
                        <option value="reported">Reported</option>
                        <option value="in-progress">In Progress</option>
                        <option value="resolved">Resolved</option>
                      </select>
                      <button 
                        className="view-details"
                        onClick={() => setSelectedIncident(incident)}
                      >
                        <i className="fas fa-search"></i> Details
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      
      {selectedIncident && (
        <CodeVulnerabilityModal 
          incident={selectedIncident} 
          onClose={() => setSelectedIncident(null)}
          updateIncidentStatus={updateIncidentStatus}
        />
      )}
    </div>
  );
};

// Main App Component
function App() {
  const [productList, setProductList] = useState(products);
  const [securityDetection, setSecurityDetection] = useState(false);
  const [incidents, setIncidents] = useState([]);
  const [viewMode, setViewMode] = useState('customer');
  
  // Add a new incident to the list
  const addIncident = (incident) => {
    setIncidents(prevIncidents => {
      // Check if incident already exists
      const existingIndex = prevIncidents.findIndex(i => i.id === incident.id);
      
      if (existingIndex >= 0) {
        // Update existing incident
        const updated = [...prevIncidents];
        updated[existingIndex] = incident;
        return updated;
      } else {
        // Add new incident
        return [incident, ...prevIncidents];
      }
    });
    
    // Visual indicator for security detection
    setSecurityDetection(true);
    setTimeout(() => setSecurityDetection(false), 1000);
  };
  
  // Update incident status
  const updateIncidentStatus = (id, status) => {
    setIncidents(prevIncidents => 
      prevIncidents.map(incident => 
        incident.id === id ? { ...incident, status } : incident
      )
    );
  };

  const updateProductStock = (productId, inStock) => {
    setProductList(prevProducts => 
      prevProducts.map(product => 
        product.id === productId ? { ...product, inStock } : product
      )
    );
  };

  return (
    <div className={`app ${securityDetection ? 'security-detected' : ''}`}>
      <header>
        <div className="logo">
          <i className="fas fa-shield-alt"></i>
          <span>Unified Sentinel Demo</span>
        </div>
        <div className="view-toggle">
          <button 
            className={viewMode === 'customer' ? 'active' : ''}
            onClick={() => setViewMode('customer')}
          >
            <i className="fas fa-shopping-cart"></i> Customer View
          </button>
          <button 
            className={viewMode === 'admin' ? 'active' : ''}
            onClick={() => setViewMode('admin')}
          >
            <i className="fas fa-user-shield"></i> Admin Dashboard
          </button>
        </div>
      </header>
      
      <main className="container">
        {viewMode === 'admin' ? (
          <AdminDashboard 
            incidents={incidents} 
            refreshIncidents={() => setIncidents([...incidents])}
            updateIncidentStatus={updateIncidentStatus}
          />
        ) : (
          <>
            <div className="demo-banner">
              <div className="banner-content">
                <h3><i className="fas fa-flask"></i> Cybersecurity Demonstration</h3>
                <p>Proactive threat detection and mitigation system</p>
                <div className="live-stats">
                  <span><i className="fas fa-shield-alt"></i> {incidents.length} threats detected</span>
                  <span><i className="fas fa-envelope"></i> {incidents.filter(i => i.emailSent).length} notifications sent</span>
                </div>
              </div>
            </div>
            
            <SpecialOffer addIncident={addIncident} />
            
            <h1 className="page-title">Retail Products</h1>
            <p className="page-subtitle">
              Try entering malicious content like &lt;script&gt;alert(1)&lt;/script&gt; 
              or phishing URLs to trigger security detection
            </p>
            
            <div className="products-grid">
              {productList.map(product => (
                <ProductCard 
                  key={product.id} 
                  product={product} 
                  updateStock={updateProductStock}
                  addIncident={addIncident}
                />
              ))}
            </div>
          </>
        )}
      </main>
      
      <footer>
        <div className="footer-content">
          <p><i className="fas fa-shield-alt"></i> Unified Sentinel PWA Demo | Proactive Cybersecurity System</p>
          <p>Real-time threat detection • Automatic incident reporting • AI-powered analysis</p>
          <p className="disclaimer">This is a technical demonstration only - Not a real security system</p>
        </div>
      </footer>
    </div>
  );
}

export default App;