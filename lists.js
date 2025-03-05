document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const listType = urlParams.get('type');
    const listTitle = document.getElementById('listTitle');
    const domainCount = document.getElementById('domainCount');
    const domainInput = document.getElementById('domainInput');
    const addDomainBtn = document.getElementById('addDomainBtn');
    const domainList = document.getElementById('domainList');
    const emptyState = document.getElementById('emptyState');
    const inputError = document.getElementById('inputError');
    const closeButton = document.getElementById('closeButton');

    // Set title and theme based on list type
    if (listType === 'blacklist') {
        listTitle.textContent = 'Blocked Domains';
        addDomainBtn.classList.remove('bg-sky-500', 'hover:bg-sky-600');
        addDomainBtn.classList.add('bg-red-500', 'hover:bg-red-600');
    } else {
        listTitle.textContent = 'Trusted Domains';
        addDomainBtn.classList.remove('bg-sky-500', 'hover:bg-sky-600');
        addDomainBtn.classList.add('bg-emerald-500', 'hover:bg-emerald-600');
    }

    // Close button
    closeButton.addEventListener('click', () => window.close());

    // Domain validation
    function isValidDomain(domain) {
        const pattern = /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        return pattern.test(domain);
    }

    // Input error handling
    function showError(message) {
        inputError.textContent = message;
        inputError.classList.remove('hidden');
        domainInput.classList.add('border-red-500');
        setTimeout(() => {
            inputError.classList.add('hidden');
            domainInput.classList.remove('border-red-500');
        }, 3000);
    }

    // Clear error state
    domainInput.addEventListener('input', () => {
        inputError.classList.add('hidden');
        domainInput.classList.remove('border-red-500');
    });

    // Add domain
    addDomainBtn.addEventListener('click', addDomain);
    domainInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') addDomain();
    });

    function addDomain() {
        const domain = domainInput.value.trim().toLowerCase();

        if (!domain) {
            showError('Please enter a domain');
            return;
        }

        if (!isValidDomain(domain)) {
            showError('Please enter a valid domain');
            return;
        }

        chrome.storage.sync.get(listType, (data) => {
            const domains = data[listType] || [];
            if (domains.includes(domain)) {
                showError('Domain already exists in the list');
                return;
            }

            domains.push(domain);
            chrome.storage.sync.set({ [listType]: domains }, () => {
                renderDomains(domains);
                domainInput.value = '';
                domainInput.focus();

                // Show success animation
                const notification = document.createElement('div');
                notification.className = 'fixed bottom-4 right-4 bg-emerald-500 text-white px-4 py-2 rounded-lg shadow-lg';
                notification.textContent = 'Domain added successfully';
                document.body.appendChild(notification);
                setTimeout(() => notification.remove(), 2000);
            });
        });
    }

    // Remove domain
    function removeDomain(domain) {
        const confirmDelete = confirm(`Are you sure you want to remove "${domain}" from the ${listType}?`);

        if (confirmDelete) {
            chrome.storage.sync.get(listType, (data) => {
                const domains = data[listType] || [];
                const newDomains = domains.filter(d => d !== domain);
                chrome.storage.sync.set({ [listType]: newDomains }, () => {
                    renderDomains(newDomains);
                });
            });
        }
    }

    // Render domains
    function renderDomains(domains) {
        domainCount.textContent = `${domains.length} ${domains.length === 1 ? 'domain' : 'domains'}`;
        domainList.innerHTML = '';

        if (domains.length === 0) {
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');
        domains.sort().forEach(domain => {
            const li = document.createElement('li');
            li.className = 'domain-item flex items-center justify-between bg-slate-800/50 px-4 py-3 rounded-lg group hover:bg-slate-700/50 transition-colors';
            li.innerHTML = `
                <span class="text-gray-100 font-medium">${domain}</span>
                <div class="flex items-center space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button class="copy-btn text-gray-400 hover:text-sky-400 transition-colors p-1">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                    </button>
                    <button class="delete-btn text-gray-400 hover:text-red-400 transition-colors p-1">
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                    </button>
                </div>
            `;

            // Add event listeners
            li.querySelector('.delete-btn').addEventListener('click', () => removeDomain(domain));
            li.querySelector('.copy-btn').addEventListener('click', () => {
                navigator.clipboard.writeText(domain).then(() => {
                    const btn = li.querySelector('.copy-btn');
                    btn.innerHTML = `
                        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                  d="M5 13l4 4L19 7" />
                        </svg>
                    `;
                    setTimeout(() => {
                        btn.innerHTML = `
                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                                      d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                        `;
                    }, 1500);
                });
            });

            domainList.appendChild(li);
        });
    }

    // Search functionality
    domainInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        chrome.storage.sync.get(listType, (data) => {
            const domains = data[listType] || [];
            const filteredDomains = domains.filter(domain =>
                domain.toLowerCase().includes(searchTerm)
            );
            renderDomains(filteredDomains);
        });
    });

    // Initial render
    chrome.storage.sync.get(listType, (data) => {
        const domains = data[listType] || [];
        renderDomains(domains);
    });

    // Listen for storage changes
    chrome.storage.onChanged.addListener((changes) => {
        if (changes[listType]) {
            renderDomains(changes[listType].newValue || []);
        }
    });
});