// background.js

// Listen for tab updates (when a new URL is loaded or updated)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // We only care about full page loads, not partial updates,
    // and only for http/https URLs.
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        const url = tab.url;
        console.log(`Checking URL: ${url}`);

        // Retrieve authentication token and user email from session storage
        const storedAuth = await chrome.storage.session.get(['authToken', 'userEmail']);
        const authToken = storedAuth.authToken;
        const userEmail = storedAuth.userEmail;

        if (!authToken || !userEmail) {
            console.log('User not logged in. Skipping URL check.');
            // Optionally, you could send a message to content.js to prompt the user
            // to log in via the extension's popup.
            return;
        }

        // --- Initial "Scanning URL" message ---
        try {
            await chrome.tabs.sendMessage(tabId, { action: "updateProcessingPopup", message: "Scanning URL..." });
        } catch (e) {
            console.warn("Could not send initial processing message to tab:", e);
            return;
        }

        try {
            const headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Token ' + authToken
            };

            // Body for the URL check API
            const scanBody = JSON.stringify({ url, email: userEmail });
            // Body for the redirect analyzer API (only URL needed)
            const redirectBody = JSON.stringify({ url });

            // --- Update for "Contacting VirusTotal" ---
            await chrome.tabs.sendMessage(tabId, { action: "updateProcessingPopup", message: "Contacting external threat intelligence (VirusTotal)...", playSpeech: true });

            // Make the fetch calls in parallel
            const [scanRes, redirectRes] = await Promise.all([
                fetch('http://127.0.0.1:8000/api/check-url/', {
                    method: 'POST',
                    headers,
                    body: scanBody
                }),
                fetch('http://127.0.0.1:8000/api/redirect-analyzer/', {
                    method: 'POST',
                    headers,
                    body: redirectBody
                })
            ]);

            const scanData = await scanRes.json();
            const redirectData = await redirectRes.json();

            // Check if both responses were successful
            if (!scanRes.ok) {
                console.error('Scan API Error:', scanData.error || scanRes.statusText);
                throw new Error(scanData.error || 'URL Scan Failed');
            }
            if (!redirectRes.ok) {
                console.error('Redirect API Error:', redirectData.error || redirectRes.statusText);
                throw new Error(redirectData.error || 'Redirect Analysis Failed');
            }

            // --- Update for "Predicting by ML Model" ---
            await chrome.tabs.sendMessage(tabId, { action: "updateProcessingPopup", message: "Analyzing with Machine Learning model...", playSpeech: true });

            // Simulate some delay for the ML model analysis (remove in production)
            await new Promise(resolve => setTimeout(resolve, 500)); // Simulate ML processing time

            // Extract classification and reason from scan data
            const classification = scanData.classification || "unknown";
            const reason = scanData.reason || "No reason provided.";

            // Extract redirect information
            const redirectInfo = {
                final_url: redirectData.final_url || "N/A",
                is_suspicious: redirectData.is_suspicious || false,
                reason: redirectData.reason || "N/A"
            };

            // Send the final result to content.js to display the popup
            chrome.tabs.sendMessage(tabId, {
                action: "showPopup",
                classification: classification,
                reason: reason,
                redirectInfo: redirectInfo
            });

        } catch (error) {
            console.error('Error during URL check process:', error);
            // Send an error message to content.js to display in the popup
            chrome.tabs.sendMessage(tabId, {
                action: "showPopup",
                classification: "error", // Indicate an extension-level error
                reason: `Extension Error: ${error.message}`,
                // Provide default/empty redirectInfo for error cases
                redirectInfo: {
                    final_url: "N/A",
                    is_suspicious: false,
                    reason: "N/A"
                }
            }).catch(e => console.error("Could not send error message to tab:", e));
        }
    }
});

// Listener for messages from popup.js (e.g., token updates after login/logout)
// This listener logs when the auth token is updated in storage.
// The background script automatically reads from storage on each tab update.
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "updateAuthToken") {
        console.log("Auth token updated in session storage. Background script will pick it up on next URL check.");
        // No response needed as storage operations are typically asynchronous and direct.
    }
});