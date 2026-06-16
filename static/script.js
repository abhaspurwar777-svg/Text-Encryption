// State variables
let activeTab = 'encrypt';
let selectedAlgorithm = 'AES';

// DOM Elements
const messageInput = document.getElementById('message-input');
const messageLabel = document.getElementById('message-label');
const charCounter = document.getElementById('char-counter');
const algorithmSelect = document.getElementById('algorithm-select');
const keyInput = document.getElementById('key-input');
const keyLabel = document.getElementById('key-label');
const genKeyBtn = document.getElementById('gen-key-btn');
const rsaKeypairDisplay = document.getElementById('rsa-keypair-display');
const rsaPublicPem = document.getElementById('rsa-public-pem');
const rsaPrivatePem = document.getElementById('rsa-private-pem');
const actionBtn = document.getElementById('action-btn');
const actionBtnIcon = document.getElementById('action-btn-icon');
const actionBtnText = document.getElementById('action-btn-text');
const outputDisplay = document.getElementById('output-display');
const outputLabel = document.getElementById('output-label');
const copyOutputBtn = document.getElementById('copy-output-btn');
const terminalLog = document.getElementById('terminal-log');
const historyRows = document.getElementById('history-rows');
const clockDisplay = document.getElementById('clock-display');

// Initialize Dashboard
document.addEventListener('DOMContentLoaded', () => {
    // Start clock
    updateClock();
    setInterval(updateClock, 1000);
    
    // Character counter listener
    messageInput.addEventListener('input', updateCharCount);
    
    // Load database history
    loadHistory();
    
    // Set initial layout
    handleAlgorithmChange();
    
    logTerminal('SecureText dashboard fully loaded.', 'SYS');
});

// Real-time Clock
function updateClock() {
    const now = new Date();
    const timeString = now.toTimeString().split(' ')[0];
    clockDisplay.textContent = timeString;
}

// Update Input character count
function updateCharCount() {
    const len = messageInput.value.length;
    charCounter.textContent = `${len} character${len !== 1 ? 's' : ''}`;
}

// Clear input textarea
function clearInput() {
    messageInput.value = '';
    updateCharCount();
    logTerminal('Input message cleared.', 'SYS');
}

// Tab Switching (Encrypt vs Decrypt)
function switchTab(tab) {
    if (activeTab === tab) return;
    
    activeTab = tab;
    
    // Update active tab visual state
    document.getElementById('tab-encrypt').classList.toggle('active', tab === 'encrypt');
    document.getElementById('tab-decrypt').classList.toggle('active', tab === 'decrypt');
    
    // Swap classes & labels
    if (tab === 'encrypt') {
        messageLabel.innerHTML = '<span class="label-prefix">></span> Enter Plaintext Message:';
        messageInput.placeholder = 'Type or paste your secret message here...';
        
        outputLabel.innerHTML = '<span class="label-prefix">></span> Encrypted Output (Base64):';
        outputDisplay.placeholder = 'Output will appear here after calculation...';
        
        actionBtn.className = 'btn-execute encrypt-theme';
        actionBtnIcon.className = 'fa-solid fa-shield-halved';
        actionBtnText.textContent = 'Encrypt Message';
        
        logTerminal('Switched workspace to ENCRYPT mode.', 'SYS');
    } else {
        messageLabel.innerHTML = '<span class="label-prefix">></span> Enter Ciphertext (Base64):';
        messageInput.placeholder = 'Paste base64 encrypted text here...';
        
        outputLabel.innerHTML = '<span class="label-prefix">></span> Decrypted Output:';
        outputDisplay.placeholder = 'Plaintext output will appear here...';
        
        actionBtn.className = 'btn-execute decrypt-theme';
        actionBtnIcon.className = 'fa-solid fa-unlock-keyhole';
        actionBtnText.textContent = 'Decrypt Message';
        
        logTerminal('Switched workspace to DECRYPT mode.', 'SYS');
    }
    
    // Update key input label based on selected algorithm and active tab
    updateKeyLabels();
    
    // Clear outputs
    outputDisplay.value = '';
    copyOutputBtn.disabled = true;
}

// Handle selected algorithm changes
function handleAlgorithmChange() {
    selectedAlgorithm = algorithmSelect.value;
    
    // 1. Update Details card metadata & security level
    const strengthBadge = document.getElementById('algo-strength-badge');
    const secLevel = document.getElementById('algo-security-level');
    const blockSize = document.getElementById('algo-block-size');
    const keySize = document.getElementById('algo-key-size');
    const description = document.getElementById('algo-description');
    const warningPane = document.getElementById('algo-warning-pane');
    
    warningPane.classList.add('hidden');
    strengthBadge.className = 'info-badge';
    
    if (selectedAlgorithm === 'AES') {
        strengthBadge.textContent = 'AES-256 SECURED';
        strengthBadge.classList.add('success');
        secLevel.textContent = 'MILITARY GRADE';
        secLevel.className = 'stat-value text-green';
        blockSize.textContent = '128 bits (16 bytes)';
        keySize.textContent = '256 bits (32 bytes)';
        description.textContent = 'Advanced Encryption Standard (AES) in Cipher Block Chaining (CBC) mode. The global standard for encrypting sensitive data. Highly secure, computationally efficient, and robust.';
    } else if (selectedAlgorithm === 'DES') {
        strengthBadge.textContent = 'DES VULNERABLE';
        strengthBadge.classList.add('danger');
        secLevel.textContent = 'OBSOLETE (DEPRECATED)';
        secLevel.className = 'stat-value text-red';
        blockSize.textContent = '64 bits (8 bytes)';
        keySize.textContent = '64 bits (8 bytes / 56 effective)';
        description.textContent = 'Data Encryption Standard (DES) in Cipher Block Chaining (CBC) mode. Designed in the 1970s, it features a small key space easily compromised by modern distributed computers via brute-force.';
        warningPane.classList.remove('hidden');
    } else if (selectedAlgorithm === 'RSA') {
        strengthBadge.textContent = 'RSA-2048 SECURED';
        strengthBadge.classList.add('info');
        secLevel.textContent = 'HIGH SECURITY';
        secLevel.className = 'stat-value text-blue';
        blockSize.textContent = 'Varies (Max 214 byte input)';
        keySize.textContent = '2048 bits';
        description.textContent = 'RSA Asymmetric cryptography with PKCS1_OAEP padding. Uses matching public and private key pairs. Standard protocol for secure key exchange, signatures, and small classified payload transfers.';
    }
    
    // 2. Adjust keys layout fields
    updateKeyLabels();
    
    if (selectedAlgorithm === 'RSA') {
        rsaKeypairDisplay.classList.remove('hidden');
        keyInput.style.height = '120px';
    } else {
        rsaKeypairDisplay.classList.add('hidden');
        keyInput.style.height = '42px';
    }
    
    logTerminal(`Algorithm configuration updated to ${selectedAlgorithm}.`, 'SYS');
}

// Helper to configure specific keys labels
function updateKeyLabels() {
    if (selectedAlgorithm === 'RSA') {
        if (activeTab === 'encrypt') {
            keyLabel.textContent = 'RSA Public Key (PEM)';
            keyInput.placeholder = 'Paste Public Key PEM (auto-generates keypair if empty)';
        } else {
            keyLabel.textContent = 'RSA Private Key (PEM)';
            keyInput.placeholder = 'Paste Private Key PEM to decrypt (Required)';
        }
        genKeyBtn.innerHTML = '<i class="fa-solid fa-key"></i> Gen Keypair';
    } else {
        keyLabel.textContent = `Secret Key (${selectedAlgorithm === 'AES' ? '64 hex / 32 bytes' : '16 hex / 8 bytes'})`;
        keyInput.placeholder = 'Enter symmetric key (auto-generates if empty)';
        genKeyBtn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> Auto Gen';
    }
}

// Trigger Backend Key Generation
async function triggerKeyGen() {
    logTerminal(`Requesting key generation for ${selectedAlgorithm}...`, 'API');
    
    try {
        const response = await fetch('/api/generate-key', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ algorithm: selectedAlgorithm })
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            if (selectedAlgorithm === 'RSA') {
                rsaPublicPem.value = data.public_key;
                rsaPrivatePem.value = data.private_key;
                
                // Pre-fill key input based on current mode
                if (activeTab === 'encrypt') {
                    keyInput.value = data.public_key;
                } else {
                    keyInput.value = data.private_key;
                }
                
                logTerminal('RSA-2048 keypair generated successfully. Public & Private keys populated.', 'OK');
                showToast('RSA Keypair generated.', 'success');
            } else {
                keyInput.value = data.key;
                logTerminal(`${selectedAlgorithm} symmetric key generated: ${data.key.substring(0, 16)}...`, 'OK');
                showToast(`${selectedAlgorithm} key generated.`, 'success');
            }
        } else {
            throw new Error(data.message || 'Key generation response error.');
        }
    } catch (err) {
        logTerminal(`Key generation failed: ${err.message}`, 'ERR');
        showToast('Key generation failed.', 'error');
    }
}

// Execute Encryption or Decryption APIs
async function executeCrypto() {
    const textVal = messageInput.value.trim();
    const keyVal = keyInput.value.trim();
    
    if (!textVal) {
        showToast(`Please enter ${activeTab === 'encrypt' ? 'plaintext' : 'ciphertext'} message.`, 'error');
        return;
    }
    
    if (activeTab === 'decrypt' && !keyVal) {
        showToast('Decryption key is required.', 'error');
        return;
    }
    
    // Loading State Visuals
    actionBtn.disabled = true;
    const originalText = actionBtnText.textContent;
    actionBtnText.textContent = activeTab === 'encrypt' ? 'Encrypting payload...' : 'Decrypting payload...';
    
    const endpoint = activeTab === 'encrypt' ? '/api/encrypt' : '/api/decrypt';
    const payload = activeTab === 'encrypt' 
        ? { text: textVal, algorithm: selectedAlgorithm, key: keyVal }
        : { ciphertext: textVal, algorithm: selectedAlgorithm, key: keyVal };
        
    logTerminal(`Submitting ${activeTab.toUpperCase()} request to backend...`, 'API');
    
    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (data.status === 'success') {
            if (activeTab === 'encrypt') {
                outputDisplay.value = data.ciphertext;
                logTerminal(`Encryption complete. Ciphertext generated using ${selectedAlgorithm}.`, 'OK');
                showToast('Message encrypted successfully.', 'success');
                
                // If backend auto-generated the keys
                if (data.generated_keys) {
                    const keysInfo = data.generated_keys;
                    if (selectedAlgorithm === 'RSA') {
                        rsaPublicPem.value = keysInfo.public_key;
                        rsaPrivatePem.value = keysInfo.private_key;
                        keyInput.value = keysInfo.public_key;
                        logTerminal('Auto-generated RSA keypair by backend. Private Key must be saved for decryption!', 'OK');
                    } else {
                        keyInput.value = keysInfo.key;
                        logTerminal(`Auto-generated symmetric key by backend: ${keysInfo.key.substring(0, 16)}...`, 'OK');
                    }
                }
            } else {
                outputDisplay.value = data.plaintext;
                logTerminal(`Decryption complete. Plaintext message recovered.`, 'OK');
                showToast('Message decrypted successfully.', 'success');
            }
            
            copyOutputBtn.disabled = false;
        } else {
            throw new Error(data.message || 'Operation failed on server.');
        }
    } catch (err) {
        outputDisplay.value = '';
        copyOutputBtn.disabled = true;
        logTerminal(`Operation failed: ${err.message}`, 'ERR');
        showToast(err.message, 'error');
    } finally {
        actionBtn.disabled = false;
        actionBtnText.textContent = originalText;
        // Reload history log entries
        loadHistory();
    }
}

// Copy outputs to clipboard
function copyOutput() {
    const text = outputDisplay.value;
    if (!text) return;
    
    navigator.clipboard.writeText(text)
        .then(() => {
            showToast('Output copied to clipboard.', 'info');
            logTerminal('Copied output buffer to clipboard.', 'SYS');
        })
        .catch(err => {
            logTerminal('Clipboard access denied.', 'ERR');
        });
}

// Generic copy helper by element ID
function copyValueById(elementId) {
    const element = document.getElementById(elementId);
    if (!element || !element.value) {
        showToast('Nothing to copy.', 'error');
        return;
    }
    
    navigator.clipboard.writeText(element.value)
        .then(() => {
            showToast('Key copied to clipboard.', 'info');
            logTerminal(`Copied ${elementId === 'rsa-public-pem' ? 'Public' : 'Private'} Key PEM to clipboard.`, 'SYS');
        })
        .catch(err => {
            logTerminal('Clipboard access denied.', 'ERR');
        });
}

// Load transaction logs from database
async function loadHistory() {
    try {
        const response = await fetch('/api/history');
        const data = await response.json();
        
        if (data.status === 'success') {
            renderHistoryTable(data.history);
        }
    } catch (err) {
        console.error('Failed to load transaction history:', err);
    }
}

// Render history rows dynamically
function renderHistoryTable(history) {
    historyRows.innerHTML = '';
    
    if (history.length === 0) {
        historyRows.innerHTML = '<tr class="empty-row"><td colspan="5">No database logs retrieved.</td></tr>';
        return;
    }
    
    history.forEach(log => {
        const tr = document.createElement('tr');
        
        // Format Timestamp (HH:MM:SS)
        let timeFormatted = log.timestamp;
        try {
            // Extracts time from string "YYYY-MM-DD HH:MM:SS"
            const parts = log.timestamp.split(' ');
            if (parts.length > 1) {
                timeFormatted = parts[1];
            }
        } catch (e) {}
        
        // Badges for operations
        const opBadge = log.operation === 'ENCRYPT' 
            ? '<span class="text-green" style="font-weight:700">ENC</span>' 
            : '<span class="text-blue" style="font-weight:700">DEC</span>';
            
        // Badges for status
        const statusBadge = log.status === 'SUCCESS'
            ? '<i class="fa-solid fa-circle-check text-green" title="Success"></i>'
            : `<i class="fa-solid fa-circle-xmark text-red" title="Failed: ${log.error_message || 'Unknown error'}"></i>`;
            
        tr.innerHTML = `
            <td class="code-font" style="color:var(--text-muted)">${timeFormatted}</td>
            <td>${opBadge}</td>
            <td style="font-weight:600">${log.algorithm}</td>
            <td class="code-font" style="text-align:right">${log.input_length} B</td>
            <td style="text-align:center">${statusBadge}</td>
        `;
        historyRows.appendChild(tr);
    });
}

// Clear transaction logs
async function clearHistory() {
    if (!confirm("Are you sure you want to permanently clear the SQLite operation history?")) {
        return;
    }
    
    logTerminal('Sending request to clear SQLite transaction tables...', 'API');
    
    try {
        const response = await fetch('/api/history/clear', { method: 'POST' });
        const data = await response.json();
        
        if (data.status === 'success') {
            logTerminal('Transaction history cleared. SQLite tables truncated.', 'OK');
            showToast('Database logs cleared.', 'info');
            loadHistory();
        } else {
            throw new Error(data.message || 'Clear operation failed.');
        }
    } catch (err) {
        logTerminal(`Clear failed: ${err.message}`, 'ERR');
        showToast('Failed to clear database.', 'error');
    }
}

// Append logs inside interactive terminal
function logTerminal(message, type) {
    const now = new Date();
    const timeString = now.toTimeString().split(' ')[0];
    
    let typeClass = 'log-info';
    if (type === 'OK') typeClass = 'log-success';
    if (type === 'ERR') typeClass = 'log-err';
    if (type === 'SYS') typeClass = 'log-info';
    
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.innerHTML = `<span class="log-time">[${timeString}]</span> <span class="${typeClass}">[${type}]</span> ${message}`;
    
    terminalLog.appendChild(line);
    
    // Auto-scroll to bottom
    terminalLog.scrollTop = terminalLog.scrollHeight;
}

// Floating Toast Alert
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'fa-circle-info';
    if (type === 'success') icon = 'fa-circle-check';
    if (type === 'error') icon = 'fa-circle-xmark';
    
    toast.innerHTML = `
        <i class="fa-solid ${icon} toast-icon"></i>
        <span class="toast-message">${message}</span>
    `;
    
    container.appendChild(toast);
    
    // Automatically fade out and remove toast after 4s
    setTimeout(() => {
        toast.style.animation = 'toast-slide-in 0.3s ease reverse forwards';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 4000);
}
