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
    top: 10px;
    right: 10px;
    background-color: #fff;
    border: 1px solid #ccc;
    border-radius: 8px;
    padding: 15px;
    box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
    z-index: 99999;
    max-width: 300px;
    font-family: Arial, sans-serif;
    font-size: 14px;
    color: #333;
  `;

  let className = '';
  switch (classification.toLowerCase()) {
    case 'safe':
      className = 'safe';
      popup.style.borderColor = 'green';
      break;
    case 'suspicious':
      className = 'suspicious';
      popup.style.borderColor = 'orange';
      break;
    case 'malicious':
      className = 'malicious';
      popup.style.borderColor = 'red';
      break;
    default:
      className = '';
      popup.style.borderColor = '#ccc';
      break;
  }

  popup.innerHTML = `
    <div style="font-weight: bold; font-size: 16px; margin-bottom: 10px;">SafeSurf URL Check</div>
    <div>
      🔍 Result: <span style="font-weight: bold;" class="${className}">${classification.toUpperCase()}</span>
    </div>
    <div style="margin-top: 5px;">
      <b>Reason:</b> ${reason}
    </div>
    <br>
    <div style="font-weight: bold;">🔁 Redirect Info:</div>
    <div><b>Final URL:</b> ${redirectInfo.final_url}</div>
    <div><b>Redirected:</b> ${redirectInfo.is_suspicious ? "<span class='suspicious'>Yes</span>" : "<span class='safe'>No</span>"}</div>
    <div><b>Reason:</b> ${redirectInfo.reason}</div>
    <button id="closeSafeSurfPopup" style="margin-top: 15px; padding: 8px 12px; cursor: pointer; background-color: #f0f0f0; border: 1px solid #ddd; border-radius: 5px; width: 100%;">Close</button>
  `;

  document.body.appendChild(popup);

  // Add event listener to close button
  document.getElementById('closeSafeSurfPopup').addEventListener('click', () => {
    popup.remove();
  });

  // Add basic styling for classes (optional, can be in a CSS file)
  const style = document.createElement('style');
  style.textContent = `
    .safe { color: green; }
    .suspicious { color: orange; }
    .malicious { color: red; }
  `;
  document.head.appendChild(style);
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "showPopup") {
    createPopup(request.classification, request.reason, request.redirectInfo);
  }
});