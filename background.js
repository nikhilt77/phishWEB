chrome.runtime.onInstalled.addListener(() => {
  // Initialize storage if not already set
  chrome.storage.sync.get(["blacklist", "whitelist", "threatCount", "sitesChecked"], (data) => {
    const defaults = {
      blacklist: data.blacklist || [],
      whitelist: data.whitelist || [],
      threatCount: data.threatCount || 0,
      sitesChecked: data.sitesChecked || 0
    };
    chrome.storage.sync.set(defaults);
  });
});

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'threatDetected') {
        handleThreat(message.data);
    } else if (message.action === 'checkDomain') {
        checkDomain(message.url, sendResponse);
        return true; // Keep the message channel open for async response
    }
});

// Handle detected threats
function handleThreat(threatData) {
    const domain = extractDomain(threatData.url);

    // Update threat count
    chrome.storage.sync.get(['threatCount', 'blacklist'], ({ threatCount = 0, blacklist = [] }) => {
        // Only count if domain isn't already blacklisted
        if (!blacklist.includes(domain)) {
            chrome.storage.sync.set({ threatCount: threatCount + 1 });

            // Add to blacklist
            blacklist.push(domain);
            chrome.storage.sync.set({ blacklist }, () => {
                showNotification(
                    'Threat Detected',
                    `${domain} has been blocked for your protection.`
                );
            });
        }
    });
}

// Check domain against lists
function checkDomain(url, sendResponse) {
    const domain = extractDomain(url);

    chrome.storage.sync.get(['blacklist', 'whitelist', 'sitesChecked'], (data) => {
        const blacklist = data.blacklist || [];
        const whitelist = data.whitelist || [];
        let sitesChecked = data.sitesChecked || 0;

        // Increment sites checked
        chrome.storage.sync.set({ sitesChecked: sitesChecked + 1 });

        if (blacklist.includes(domain)) {
            sendResponse({ status: 'blocked', message: 'Domain is blacklisted' });
        } else if (whitelist.includes(domain)) {
            sendResponse({ status: 'trusted', message: 'Domain is trusted' });
        } else {
            // Perform additional security checks here
            performSecurityCheck(domain).then(result => {
                sendResponse({ status: result.status, message: result.message });
            });
        }
    });
}

// Monitor navigation to block blacklisted sites
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) { // Only check main frame
        const domain = extractDomain(details.url);

        chrome.storage.sync.get('blacklist', ({ blacklist = [] }) => {
            if (blacklist.includes(domain)) {
                // Block navigation and show warning
                chrome.tabs.update(details.tabId, {
                    url: `blocked.html?domain=${encodeURIComponent(domain)}`
                });
            }
        });
    }
});

// Helper function to extract domain from URL
function extractDomain(url) {
    try {
        const urlObject = new URL(url);
        return urlObject.hostname.replace(/^www\./, '');
    } catch {
        return url;
    }
}

// Show desktop notification
function showNotification(title, message) {
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: title,
        message: message,
        priority: 1
    });
}

// Perform security check on domain
async function performSecurityCheck(domain) {
    // Add your security checking logic here
    // This is a simple example - replace with actual security checks

    // Check for common phishing patterns
    const suspiciousPatterns = [
        /paypal.*\.com(?!\.)[a-zA-Z]/i,
        /amazon.*\.com(?!\.)[a-zA-Z]/i,
        /apple.*\.com(?!\.)[a-zA-Z]/i,
        /google.*\.com(?!\.)[a-zA-Z]/i,
        /microsoft.*\.com(?!\.)[a-zA-Z]/i,
        /netflix.*\.com(?!\.)[a-zA-Z]/i
    ];

    // Check if domain matches any suspicious patterns
    const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(domain));

    if (isSuspicious) {
        return {
            status: 'suspicious',
            message: 'Potential phishing site detected'
        };
    }



    return {
        status: 'unknown',
        message: 'No immediate threats detected'
    };
}

// Listen for tab updates to check new pages
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Check new page
        checkDomain(tab.url, (result) => {
            if (result.status === 'blocked' || result.status === 'suspicious') {
                // Update badge to show warning
                chrome.action.setBadgeText({ text: '⚠️', tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#EF4444', tabId });
            } else if (result.status === 'trusted') {
                // Show trusted indicator
                chrome.action.setBadgeText({ text: '✓', tabId });
                chrome.action.setBadgeBackgroundColor({ color: '#10B981', tabId });
            } else {
                // Clear badge
                chrome.action.setBadgeText({ text: '', tabId });
            }
        });
    }
});