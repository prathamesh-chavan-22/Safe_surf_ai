// background.js

// Listen for tab updates (when a new URL is loaded)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // We only care about full page loads, not partial updates
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    const url = tab.url;
    console.log(`Checking URL: ${url}`);

    const storedAuth = await chrome.storage.session.get(['authToken', 'userEmail']);
    const authToken = storedAuth.authToken;
    const userEmail = storedAuth.userEmail;

    if (!authToken || !userEmail) {
      console.log('User not logged in. Skipping URL check.');
      // Optionally, you can send a message to content.js to prompt login
      return;
    }

    try {
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Token ' + authToken
      };

      const body = JSON.stringify({ url, email: userEmail });

      // Run both requests in parallel
      const [scanRes, redirectRes] = await Promise.all([
        fetch('http://127.0.0.1:8000/api/check-url/', {
          method: 'POST',
          headers,
          body
        }),
        fetch('http://127.0.0.1:8000/api/redirect-analyzer/', {
          method: 'POST',
          headers,
          body: JSON.stringify({ url }) // only URL needed for redirect analyzer
        })
      ]);

      const scanData = await scanRes.json();
      const redirectData = await redirectRes.json();

      if (!scanRes.ok || !redirectRes.ok) {
        throw new Error(scanData.error || redirectData.error || 'Unknown error');
      }

      const classification = scanData.classification || "unknown";
      const reason = scanData.reason || "No reason provided.";

      const redirectInfo = {
        final_url: redirectData.final_url || "N/A",
        is_suspicious: redirectData.is_suspicious || false,
        reason: redirectData.reason || "N/A"
      };

      // Send the result to content.js
      chrome.tabs.sendMessage(tabId, {
        action: "showPopup",
        classification: classification,
        reason: reason,
        redirectInfo: redirectInfo
      });

    } catch (error) {
      console.error('Error checking URL:', error);
      // Send an error message to content.js
      chrome.tabs.sendMessage(tabId, {
        action: "showPopup",
        classification: "error",
        reason: `Extension Error: ${error.message}`
      });
    }
  }
});

// Listener for messages from popup.js (e.g., token updates after login/logout)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "updateAuthToken") {
    // This part is now handled by popup.js directly writing to storage.
    // The background script just needs to read from storage.
    console.log("Auth token updated in storage. Background script will pick it up.");
  }
});