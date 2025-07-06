// content.js

function createPopup(classification, reason, redirectInfo) {
  // Remove existing popup if any
  const existingPopup = document.getElementById('safeSurfPopup');
  if (existingPopup) {
    existingPopup.remove();
  }

  const popup = document.createElement('div');
  popup.id = 'safeSurfPopup';
  popup.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%);
    border: 2px solid #e9ecef; /* Default border, overridden by dynamic classes */
    border-radius: 12px;
    padding: 20px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.12), 0 2px 8px rgba(0, 0, 0, 0.08);
    z-index: 99999;
    max-width: 350px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    font-size: 14px;
    color: #2c3e50;
    backdrop-filter: blur(10px);
    animation: slideIn 0.3s ease-out forwards; /* Added forwards to keep final state */
  `;

  let resultBorderColor = '#e9ecef';
  let classificationTextClass = '';

  switch (classification.toLowerCase()) {
    case 'safe':
      classificationTextClass = 'safe-text';
      resultBorderColor = '#28a745';
      popup.classList.add('safe-popup-border'); // Add specific class for popup border
      break;
    case 'suspicious':
      classificationTextClass = 'suspicious-text';
      resultBorderColor = '#ffc107';
      popup.classList.add('suspicious-popup-border'); // Add specific class for popup border
      break;
    case 'malicious':
      classificationTextClass = 'malicious-text';
      resultBorderColor = '#dc3545';
      popup.classList.add('malicious-popup-border'); // Add specific class for popup border
      break;
    default:
      classificationTextClass = '';
      popup.classList.add('default-popup-border'); // Default border class
      break;
  }

  popup.innerHTML = `
    <div style="
      font-weight: 700;
      font-size: 18px;
      margin-bottom: 15px;
      color: #1a202c;
      display: flex;
      align-items: center;
      gap: 8px;
    ">
      <span style="font-size: 20px;">🛡️</span>
      SafeSurf URL Check
    </div>
    
    <div style="
      background: #f8f9fa;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 15px;
      border-left: 4px solid ${resultBorderColor}; /* Dynamic border based on classification */
    ">
      <div style="
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 8px;
      ">
        <span style="font-size: 16px;">🔍</span>
        <span style="font-weight: 600;">Result:</span>
        <span style="font-weight: 700;" class="${classificationTextClass}">${classification.toUpperCase()}</span>
      </div>
      
      <div style="
        font-size: 13px;
        color: #6c757d;
        line-height: 1.4;
      ">
        <strong>Reason:</strong> ${reason === "No reason provided." ? `<span style="font-style: italic; color: #999;">${reason}</span>` : reason}
      </div>
    </div>
    
    <div style="
      background: #f8f9fa;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 15px;
      border: 1px solid #e0e0e0; /* Subtle border for redirect info block */
    ">
      <div style="
        font-weight: 600;
        margin-bottom: 10px;
        display: flex;
        align-items: center;
        gap: 8px;
        color: #495057;
      ">
        <span style="font-size: 16px;">🔁</span>
        Redirect Information
      </div>
      
      <div style="
        font-size: 13px;
        line-height: 1.5;
        color: #6c757d;
      ">
        <div style="margin-bottom: 6px;">
          <strong>Final URL:</strong> 
          <span style="
            word-break: break-all;
            background: #ffffff;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
          ">${redirectInfo.final_url}</span>
        </div>
        
        <div style="margin-bottom: 6px;">
          <strong>Redirected:</strong> 
          ${redirectInfo.is_suspicious ? `<span class='suspicious-text'>Yes</span>` : `<span class='safe-text'>No</span>`}
        </div>
        
        <div>
          <strong>Reason:</strong> ${redirectInfo.reason === "N/A" ? `<span style="font-style: italic; color: #999;">${redirectInfo.reason}</span>` : redirectInfo.reason}
        </div>
      </div>
    </div>
    
    <button id="closeSafeSurfPopup" title="Close Popup" style=" /* Added title attribute */
      margin-top: 5px;
      padding: 12px 16px;
      cursor: pointer;
      background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
      color: white;
      border: none;
      border-radius: 8px;
      width: 100%;
      font-weight: 600;
      font-size: 14px;
      transition: all 0.2s ease;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    " 
    onmouseover="this.style.transform='translateY(-1px)'; this.style.boxShadow='0 4px 8px rgba(0, 0, 0, 0.15)';"
    onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0, 0, 0, 0.1)';">
      ✕ Close
    </button>
  `;

  document.body.appendChild(popup);

  // Add event listener to close button
  document.getElementById('closeSafeSurfPopup').addEventListener('click', () => {
    popup.remove();
  });

  // Add enhanced styling for classes (now includes popup border classes)
  const style = document.createElement('style');
  style.textContent = `
    @keyframes slideIn {
      from {
        transform: translateX(100%);
        opacity: 0;
      }
      to {
        transform: translateX(0);
        opacity: 1;
      }
    }
    
    .safe-text {
      color: #28a745;
      font-weight: 600;
      text-shadow: 0 1px 2px rgba(40, 167, 69, 0.2);
    }
    
    .suspicious-text {
      color: #ffc107;
      font-weight: 600;
      text-shadow: 0 1px 2px rgba(255, 193, 7, 0.2);
    }
    
    .malicious-text {
      color: #dc3545;
      font-weight: 600;
      text-shadow: 0 1px 2px rgba(220, 53, 69, 0.2);
    }

    /* Popup border colors based on classification */
    .safe-popup-border {
      border-color: #28a745 !important;
      border-left-width: 4px !important;
    }
    .suspicious-popup-border {
      border-color: #ffc107 !important;
      border-left-width: 4px !important;
    }
    .malicious-popup-border {
      border-color: #dc3545 !important;
      border-left-width: 4px !important;
    }
    .default-popup-border {
      border-color: #e9ecef !important;
    }
  `;
  document.head.appendChild(style);
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "showPopup") {
    createPopup(request.classification, request.reason, request.redirectInfo);
  }
});