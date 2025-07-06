// content.js

// Keep a reference to the current popup element
let currentPopup = null;
let currentUtterance = null; // To manage TTS across updates

function updateProcessingMessage(message, playSpeech = true) {
    const popup = document.getElementById('safeSurfPopup');

    if (!popup) {
        // If no popup exists, create a basic processing one first
        createPopup(null, null, null, message);
        return;
    }

    const processingTextElement = popup.querySelector('.processing-text-message');
    const loaderElement = popup.querySelector('.loader');

    if (processingTextElement) {
        processingTextElement.textContent = message;
    }

    // Update TTS
    if (window.speechSynthesis.speaking) {
        window.speechSynthesis.cancel();
    }
    if (playSpeech) {
        currentUtterance = new SpeechSynthesisUtterance(message);
        currentUtterance.lang = 'en-US';
        currentUtterance.rate = 1.0;
        currentUtterance.pitch = 1.0;
        window.speechSynthesis.speak(currentUtterance);
    }
}

function createPopup(classification, reason, redirectInfo, initialProcessingMessage = null) {
    // Remove existing popup if any
    const existingPopup = document.getElementById('safeSurfPopup');
    if (existingPopup) {
        existingPopup.remove();
        // Stop any ongoing speech if popup is removed
        if (window.speechSynthesis.speaking) {
            window.speechSynthesis.cancel();
        }
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

    // Only apply classification-specific styles if classification is provided
    if (classification) {
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
    } else {
        // Default for processing state
        popup.classList.add('default-popup-border');
    }

    let ttsText = "";
    let popupContent = "";

    if (classification && reason && redirectInfo) {
        // Construct the text to be spoken for final result
        ttsText = `SafeSurf URL Check. Result: ${classification}. Reason: ${reason}. Redirect Information: Final URL is ${redirectInfo.final_url}. Redirected: ${redirectInfo.is_suspicious ? 'Yes' : 'No'}. Redirect reason: ${redirectInfo.reason}.`;

        popupContent = `
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
            
            <div style="display: flex; gap: 10px;">
                <button id="muteSafeSurfPopup" title="Mute/Unmute" style="
                    margin-top: 5px;
                    padding: 12px 16px;
                    cursor: pointer;
                    background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    flex: 1; /* Allow button to take available space */
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                " 
                onmouseover="this.style.transform='translateY(-1px)'; this.style.boxShadow='0 4px 8px rgba(0, 0, 0, 0.15)';"
                onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0, 0, 0, 0.1)';">
                    🔇 Mute
                </button>

                <button id="closeSafeSurfPopup" title="Close Popup" style="
                    margin-top: 5px;
                    padding: 12px 16px;
                    cursor: pointer;
                    background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    flex: 1; /* Allow button to take available space */
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                " 
                onmouseover="this.style.transform='translateY(-1px)'; this.style.boxShadow='0 4px 8px rgba(0, 0, 0, 0.15)';"
                onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 2px 4px rgba(0, 0, 0, 0.1)';">
                    ✕ Close
                </button>
            </div>
        `;
    } else {
        // Processing state
        ttsText = initialProcessingMessage || "SafeSurf is currently checking the URL. Please wait.";
        popupContent = `
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
                padding: 15px;
                margin-bottom: 15px;
                border-left: 4px solid #007bff; /* Blue for processing */
                display: flex;
                align-items: center;
                gap: 10px;
            ">
                <div class="loader" style="
                    border: 4px solid #f3f3f3;
                    border-top: 4px solid #007bff;
                    border-radius: 50%;
                    width: 20px;
                    height: 20px;
                    animation: spin 1s linear infinite;
                "></div>
                <span class="processing-text-message" style="font-weight: 600; color: #007bff;">${initialProcessingMessage || "Processing..."}</span>
            </div>
            
            <div style="
                font-size: 13px;
                color: #6c757d;
                text-align: center;
            ">
                Please wait while SafeSurf analyzes the URL.
            </div>

            <button id="closeSafeSurfPopup" title="Close Popup" style="
                margin-top: 15px;
                width: 100%;
                padding: 12px 16px;
                cursor: pointer;
                background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                color: white;
                border: none;
                border-radius: 8px;
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
    }

    popup.innerHTML = popupContent;
    document.body.appendChild(popup);
    currentPopup = popup; // Store reference to the created popup

    // TTS functionality
    let isMuted = false;
    const synth = window.speechSynthesis;

    // Stop previous speech if any and start new one
    if (synth.speaking) {
        synth.cancel();
    }
    currentUtterance = new SpeechSynthesisUtterance(ttsText);
    currentUtterance.lang = 'en-US';
    currentUtterance.rate = 1.0;
    currentUtterance.pitch = 1.0;
    synth.speak(currentUtterance);


    // Add event listener to mute/unmute button only if it exists (i.e., for final result popup)
    const muteButton = document.getElementById('muteSafeSurfPopup');
    if (muteButton) {
        muteButton.addEventListener('click', () => {
            if (synth.speaking) {
                synth.cancel(); // Stop currently speaking
                isMuted = true;
                muteButton.textContent = '🔊 Unmute';
                muteButton.style.background = 'linear-gradient(135deg, #17a2b8 0%, #138496 100%)'; // Change color for unmute
            } else {
                // If it was explicitly muted, we speak it again
                synth.speak(currentUtterance); // Speak the current message
                isMuted = false;
                muteButton.textContent = '🔇 Mute';
                muteButton.style.background = 'linear-gradient(135deg, #007bff 0%, #0056b3 100%)'; // Original color for mute
            }
        });
    }

    // Add event listener to close button
    document.getElementById('closeSafeSurfPopup').addEventListener('click', () => {
        popup.remove();
        currentPopup = null; // Clear reference
        if (synth.speaking) {
            synth.cancel(); // Stop TTS when popup is closed
        }
    });

    // Add enhanced styling for classes (now includes popup border classes and loader animation)
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
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
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
    } else if (request.action === "updateProcessingPopup") {
        updateProcessingMessage(request.message, request.playSpeech);
    }
});