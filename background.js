// background.js
console.log("Background script is running...");

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === "scanPage") {
        console.log("Background received scanPage message.");
        
        // Send a message to the content script
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            chrome.tabs.sendMessage(tabs[0].id, { action: "scanScripts" }, (response) => {
                if (response && response.scripts) {
                    console.log("Scripts found:", response.scripts);
                    sendResponse({ scripts: response.scripts });
                }
            });
        });

        // Return true to indicate an asynchronous response
        return true;
    }
});