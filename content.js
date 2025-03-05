class PhishingDetector {
    constructor() {
        this.enabled = true;
        this.RISK_FACTORS = {
            SUSPICIOUS_DOMAIN: 30,
            INSECURE_FORM: 25,
            NO_SSL: 20,
            SUSPICIOUS_REDIRECT: 15,
            HIDDEN_ELEMENT: 10,
            BRAND_MISMATCH: 10,
            SUSPICIOUS_INPUT: 5
        };

        this.knownBrands = {
            'paypal.com': ['paypal', 'pay', 'payment'],
            'google.com': ['google', 'gmail', 'gcloud'],
            'facebook.com': ['facebook', 'fb', 'meta'],
            'amazon.com': ['amazon', 'aws', 'prime'],
            'apple.com': ['apple', 'icloud', 'itunes'],
            'microsoft.com': ['microsoft', 'azure', 'office'],
            'netflix.com': ['netflix', 'netfix', 'movies'],
            'bank': ['bank', 'banking', 'account', 'transfer']
        };

        this.suspiciousPatterns = [
            /paypal.*\.com(?!\.)[a-zA-Z]/i,
            /amazon.*\.com(?!\.)[a-zA-Z]/i,
            /apple.*\.com(?!\.)[a-zA-Z]/i,
            /google.*\.com(?!\.)[a-zA-Z]/i,
            /microsoft.*\.com(?!\.)[a-zA-Z]/i,
            /facebook.*\.com(?!\.)[a-zA-Z]/i,
            /netflix.*\.com(?!\.)[a-zA-Z]/i,
            /\b(bank|banking|secure|login|signin|verify|account|update|confirm)\b/i
        ];

        this.sensitiveInputs = [
            'password',
            'pass',
            'pwd',
            'creditcard',
            'credit-card',
            'card-number',
            'cardnumber',
            'ccv',
            'cvc',
            'cvv',
            'ssn',
            'bank',
            'account',
            'routing',
            'swift',
            'iban'
        ];

        this.riskScore = 0;
        this.threats = [];
        this.initialize();
    }

    async initialize() {
        await this.checkExtensionStatus();
        if (this.enabled) {
            this.startDetection();
        }

        // Listen for changes in extension status
        chrome.storage.onChanged.addListener((changes) => {
            if (changes.enabled) {
                this.enabled = changes.enabled.newValue;
                if (this.enabled) {
                    this.startDetection();
                }
            }
        });
    }

    async checkExtensionStatus() {
        try {
            const data = await chrome.storage.sync.get('enabled');
            this.enabled = data.enabled !== false;
        } catch (error) {
            console.error('Error checking extension status:', error);
            this.enabled = true; // Default to enabled
        }
    }

    startDetection() {
        this.analyzePage();
        this.monitorDOMChanges();
        this.monitorUserInput();
    }

    analyzePage() {
        this.checkDomain();
        this.checkSSL();
        this.checkForms();
        this.checkHiddenElements();
        this.checkBrandMisuse();
        this.checkExternalLinks();
        this.analyzeDOMStructure();

        // Calculate final risk and report if necessary
        this.evaluateRisk();
    }

    checkDomain() {
        const domain = window.location.hostname;
        let isDomainSuspicious = false;

        // Check against suspicious patterns
        for (let pattern of this.suspiciousPatterns) {
            if (pattern.test(domain)) {
                isDomainSuspicious = true;
                this.addThreat('suspicious_domain', 'Suspicious domain pattern detected', this.RISK_FACTORS.SUSPICIOUS_DOMAIN);
                break;
            }
        }

        // Check for typosquatting
        for (let legitimateDomain of Object.keys(this.knownBrands)) {
            if (this.isTyposquatting(domain, legitimateDomain)) {
                this.addThreat('typosquatting', `Possible typosquatting of ${legitimateDomain}`, this.RISK_FACTORS.SUSPICIOUS_DOMAIN);
                break;
            }
        }
    }

    checkSSL() {
        if (window.location.protocol !== 'https:') {
            // Check if page contains sensitive inputs
            const hasSensitiveInputs = Array.from(document.querySelectorAll('input')).some(
                input => this.isSensitiveInput(input)
            );

            if (hasSensitiveInputs) {
                this.addThreat('no_ssl', 'Sensitive information being collected without SSL', this.RISK_FACTORS.NO_SSL);
            }
        }
    }

    checkForms() {
        document.querySelectorAll('form').forEach(form => {
            const action = form.action || '';
            const hasSensitiveInputs = Array.from(form.querySelectorAll('input')).some(
                input => this.isSensitiveInput(input)
            );

            if (hasSensitiveInputs) {
                if (!action.startsWith('https://')) {
                    this.addThreat('insecure_form', 'Sensitive form submitting to insecure endpoint', this.RISK_FACTORS.INSECURE_FORM);
                }

                // Check for suspicious form attributes
                if (form.getAttribute('autocomplete') === 'off') {
                    this.addThreat('suspicious_form', 'Form prevents password manager usage', this.RISK_FACTORS.SUSPICIOUS_INPUT);
                }
            }
        });
    }

    checkHiddenElements() {
        const hiddenElements = document.querySelectorAll('[style*="display: none"], [style*="visibility: hidden"], [hidden]');
        hiddenElements.forEach(element => {
            if (this.isSensitiveInput(element)) {
                this.addThreat('hidden_element', 'Hidden sensitive input detected', this.RISK_FACTORS.HIDDEN_ELEMENT);
            }
        });
    }

    checkBrandMisuse() {
        const pageContent = document.body.innerText.toLowerCase();
        const pageDomain = window.location.hostname.toLowerCase();

        for (const [brand, keywords] of Object.entries(this.knownBrands)) {
            if (keywords.some(keyword => pageContent.includes(keyword.toLowerCase()))) {
                if (!pageDomain.includes(brand.split('.')[0])) {
                    this.addThreat('brand_misuse', `Possible ${brand} brand misuse`, this.RISK_FACTORS.BRAND_MISMATCH);
                }
            }
        }
    }

    checkExternalLinks() {
        const currentDomain = window.location.hostname;
        document.querySelectorAll('a[href]').forEach(link => {
            try {
                const url = new URL(link.href);
                if (url.hostname !== currentDomain && this.isSuspiciousDomain(url.hostname)) {
                    this.addThreat('suspicious_link', `Suspicious external link to ${url.hostname}`, this.RISK_FACTORS.SUSPICIOUS_REDIRECT);
                }
            } catch (e) {
                // Invalid URL, ignore
            }
        });
    }

    analyzeDOMStructure() {
        // Check for common phishing page structures
        if (document.querySelectorAll('iframe').length > 0) {
            this.addThreat('iframe_detected', 'Page contains iframes which might be used for clickjacking', 5);
        }

        // Check for login forms in unusual locations
        document.querySelectorAll('input[type="password"]').forEach(input => {
            const form = input.closest('form');
            if (!form || form.querySelectorAll('input').length < 2) {
                this.addThreat('suspicious_password_field', 'Isolated password field detected', this.RISK_FACTORS.SUSPICIOUS_INPUT);
            }
        });
    }

    monitorDOMChanges() {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes.length) {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === 1) { // ELEMENT_NODE
                            this.checkNewElement(node);
                        }
                    });
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    monitorUserInput() {
        document.addEventListener('input', (e) => {
            if (this.isSensitiveInput(e.target)) {
                this.checkInputSecurity(e.target);
            }
        });
    }

    checkNewElement(element) {
        if (element.tagName === 'FORM') {
            this.checkForms();
        } else if (element.tagName === 'INPUT') {
            this.checkInputSecurity(element);
        } else if (element.tagName === 'A') {
            this.checkExternalLinks();
        }
    }

    checkInputSecurity(input) {
        if (this.isSensitiveInput(input)) {
            const form = input.closest('form');
            if (!form || !form.action.startsWith('https://')) {
                this.addThreat('insecure_input', 'Sensitive data being collected insecurely', this.RISK_FACTORS.INSECURE_FORM);
            }
        }
    }

    isSensitiveInput(input) {
        if (!input || !input.type) return false;

        const type = input.type.toLowerCase();
        const name = (input.name || '').toLowerCase();
        const id = (input.id || '').toLowerCase();

        return type === 'password' ||
               this.sensitiveInputs.some(pattern =>
                   name.includes(pattern) || id.includes(pattern)
               );
    }

    isSuspiciousDomain(domain) {
        return this.suspiciousPatterns.some(pattern => pattern.test(domain));
    }

    isTyposquatting(testDomain, legitimateDomain) {
        const similarity = this.calculateSimilarity(testDomain, legitimateDomain);
        return similarity > 0.75 && similarity < 1;
    }

    calculateSimilarity(str1, str2) {
        const longer = str1.length > str2.length ? str1 : str2;
        const shorter = str1.length > str2.length ? str2 : str1;

        if (longer.length === 0) return 1.0;

        return (longer.length - this.levenshteinDistance(longer, shorter)) / longer.length;
    }

    levenshteinDistance(str1, str2) {
        const matrix = Array(str2.length + 1).fill(null)
            .map(() => Array(str1.length + 1).fill(null));

        for (let i = 0; i <= str1.length; i++) matrix[0][i] = i;
        for (let j = 0; j <= str2.length; j++) matrix[j][0] = j;

        for (let j = 1; j <= str2.length; j++) {
            for (let i = 1; i <= str1.length; i++) {
                const substitutionCost = str1[i - 1] === str2[j - 1] ? 0 : 1;
                matrix[j][i] = Math.min(
                    matrix[j][i - 1] + 1,
                    matrix[j - 1][i] + 1,
                    matrix[j - 1][i - 1] + substitutionCost
                );
            }
        }
        return matrix[str2.length][str1.length];
    }

    addThreat(type, message, riskValue) {
        this.threats.push({ type, message });
        this.riskScore += riskValue;
    }

    evaluateRisk() {
        if (this.riskScore >= 50) {
            this.reportHighRisk();
        } else if (this.riskScore >= 30) {
            this.reportMediumRisk();
        } else if (this.threats.length > 0) {
            this.reportLowRisk();
        }
    }

    reportHighRisk() {
        chrome.runtime.sendMessage({
            action: 'threatDetected',
            data: {
                severity: 'high',
                score: this.riskScore,
                threats: this.threats,
                url: window.location.href,
                domain: window.location.hostname
            }
        });
    }

    reportMediumRisk() {
        chrome.runtime.sendMessage({
            action: 'threatDetected',
            data: {
                severity: 'medium',
                score: this.riskScore,
                threats: this.threats,
                url: window.location.href,
                domain: window.location.hostname
            }
        });
    }

    reportLowRisk() {
        chrome.runtime.sendMessage({
            action: 'threatDetected',
            data: {
                severity: 'low',
                score: this.riskScore,
                threats: this.threats,
                url: window.location.href,
                domain: window.location.hostname
            }
        });
    }
}

// Initialize detector
const detector = new PhishingDetector();