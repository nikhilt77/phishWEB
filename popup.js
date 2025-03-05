document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const powerButton = document.querySelector('.power-button');
    const securityStatus = document.getElementById('securityStatus');
    const currentUrlElement = document.getElementById('currentUrl');
    const threatCount = document.querySelector('.text-2xl'); // First stat counter
    const sitesChecked = document.querySelectorAll('.text-2xl')[1]; // Second stat counter

    // State Management
    let isEnabled = true;

    // Initialize Extension State
    chrome.storage.sync.get(['enabled', 'threatCount', 'sitesChecked'], (data) => {
        isEnabled = data.enabled !== false; // Default to true if not set
        updatePowerButton();

        // Update stats
        threatCount.textContent = data.threatCount || '0';
        sitesChecked.textContent = data.sitesChecked || '0';
    });

    // Power Button Toggle
    powerButton.addEventListener('click', () => {
        isEnabled = !isEnabled;
        chrome.storage.sync.set({ enabled: isEnabled });
        updatePowerButton();
        updateCurrentDomainStatus(); // Recheck current domain with new state
    });

    function updatePowerButton() {
        if (isEnabled) {
            powerButton.classList.remove('bg-red-500');
            powerButton.classList.add('bg-green-500');
            powerButton.setAttribute('title', 'Protection Active');
        } else {
            powerButton.classList.remove('bg-green-500');
            powerButton.classList.add('bg-red-500');
            powerButton.setAttribute('title', 'Protection Disabled');
        }
    }

    // List Management Windows
    document.getElementById('openBlacklist').addEventListener('click', () => {
        chrome.windows.create({
            url: chrome.runtime.getURL('lists.html') + '?type=blacklist',
            type: 'popup',
            width: 600,
            height: 500,
            focused: true
        });
    });

    document.getElementById('openWhitelist').addEventListener('click', () => {
        chrome.windows.create({
            url: chrome.runtime.getURL('lists.html') + '?type=whitelist',
            type: 'popup',
            width: 600,
            height: 500,
            focused: true
        });
    });

    // Current URL Status Check
    function updateCurrentDomainStatus() {
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const currentUrl = tabs[0].url;
            const domain = extractDomain(currentUrl);
            currentUrlElement.textContent = domain;

            if (!isEnabled) {
                updateStatus('disabled', 'Protection Disabled');
                return;
            }

            chrome.storage.sync.get(['blacklist', 'whitelist'], (data) => {
                const blacklist = data.blacklist || [];
                const whitelist = data.whitelist || [];

                if (blacklist.includes(domain)) {
                    updateStatus('blocked', 'Blocked Site');
                } else if (whitelist.includes(domain)) {
                    updateStatus('trusted', 'Trusted Site');
                } else {
                    // Perform real-time check (simplified for example)
                    performSecurityCheck(domain);
                }
            });
        });
    }

    function updateStatus(status, text) {
        securityStatus.textContent = text;

        // Remove all possible status classes
        securityStatus.classList.remove(
            'bg-green-500/20', 'text-green-400', 'border-green-500/30',
            'bg-red-500/20', 'text-red-400', 'border-red-500/30',
            'bg-yellow-500/20', 'text-yellow-400', 'border-yellow-500/30',
            'bg-gray-500/20', 'text-gray-400', 'border-gray-500/30'
        );

        // Add appropriate status classes
        switch (status) {
            case 'trusted':
                securityStatus.classList.add('bg-green-500/20', 'text-green-400', 'border-green-500/30');
                break;
            case 'blocked':
                securityStatus.classList.add('bg-red-500/20', 'text-red-400', 'border-red-500/30');
                break;
            case 'checking':
                securityStatus.classList.add('bg-yellow-500/20', 'text-yellow-400', 'border-yellow-500/30');
                break;
            case 'disabled':
                securityStatus.classList.add('bg-gray-500/20', 'text-gray-400', 'border-gray-500/30');
                break;
            default:
                securityStatus.classList.add('bg-yellow-500/20', 'text-yellow-400', 'border-yellow-500/30');
        }
    }

    async function performSecurityCheck(domain) {
        updateStatus('checking', 'Checking...');

        try {
            // Simulate security check (replace with actual implementation)
            const isSecure = await simulateSecurityCheck(domain);

            // Update stats
            chrome.storage.sync.get(['sitesChecked'], (data) => {
                const newCount = (parseInt(data.sitesChecked) || 0) + 1;
                chrome.storage.sync.set({ sitesChecked: newCount });
                sitesChecked.textContent = newCount;
            });

            if (isSecure) {
                updateStatus('trusted', 'Site Secure');
            } else {
                updateStatus('blocked', 'Suspicious Site');
                // Increment threat count
                chrome.storage.sync.get(['threatCount'], (data) => {
                    const newCount = (parseInt(data.threatCount) || 0) + 1;
                    chrome.storage.sync.set({ threatCount: newCount });
                    threatCount.textContent = newCount;
                });
            }
        } catch (error) {
            console.error('Security check failed:', error);
            updateStatus('error', 'Check Failed');
        }
    }

    // Helper function to simulate security check (replace with actual implementation)
    function simulateSecurityCheck(domain) {
        return new Promise((resolve) => {
            setTimeout(() => {
                // For demonstration, randomly determine if site is secure
                resolve(Math.random() > 0.3);
            }, 1000);
        });
    }

    function extractDomain(url) {
        try {
            const urlObject = new URL(url);
            return urlObject.hostname.replace(/^www\./, '');
        } catch {
            return url;
        }
    }

    // Listen for storage changes to update UI
    chrome.storage.onChanged.addListener((changes) => {
        if (changes.threatCount) {
            threatCount.textContent = changes.threatCount.newValue;
        }
        if (changes.sitesChecked) {
            sitesChecked.textContent = changes.sitesChecked.newValue;
        }
        // Recheck status when lists are updated
        if (changes.blacklist || changes.whitelist) {
            updateCurrentDomainStatus();
        }
    });

    // Initialize
    updateCurrentDomainStatus();

    // Add refresh button functionality if needed
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') {
            updateCurrentDomainStatus();
        }
    });
});