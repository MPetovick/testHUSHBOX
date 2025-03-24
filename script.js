// Global cryptographic parameters configuration
const CONFIG = {
    PBKDF2_ITERATIONS: 250000,
    SALT_LENGTH: 32,
    IV_LENGTH: 12,
    AES_KEY_LENGTH: 256,
    HMAC_LENGTH: 256,
    QR_SIZE: 200,
    MIN_PASSPHRASE_LENGTH: 12,
    COMPRESSION_THRESHOLD: 100,
    MAX_QR_SIZE: 350,
    CAMERA_TIMEOUT: 30000,
    DECRYPT_DELAY_INCREMENT: 100,
    MAX_DECRYPT_ATTEMPTS: 5,
    DECRYPT_COOLDOWN: 5 * 60 * 1000, // 5 minutes
    NOTICE_TIMEOUT: 10000 // 10 seconds for notice messages
};

// DOM Elements
const domElements = {
    uploadArrowButton: document.getElementById('upload-arrow-button'),
    scanButton: document.getElementById('scan-button'),
    imageButton: document.getElementById('image-button'),
    pdfButton: document.getElementById('pdf-button'),
    cameraContainer: document.getElementById('camera-container'),
    cameraPreview: document.getElementById('camera-preview'),
    messagesDiv: document.getElementById('messages'),
    passphraseInput: document.getElementById('passphrase'),
    messageInput: document.getElementById('message-input'),
    sendButton: document.getElementById('send-button'),
    qrCanvas: document.getElementById('qr-canvas'),
    decodeButton: document.getElementById('decode-button'),
    downloadButton: document.getElementById('download-button'),
    shareButton: document.getElementById('share-button'),
    qrContainer: document.getElementById('qr-container'),
    tutorialModal: document.getElementById('tutorial-modal'),
    closeTutorial: document.getElementById('close-tutorial'),
    dontShowAgain: document.getElementById('dont-show-again'),
    closeModalButton: document.querySelector('.close-modal'),
    comingSoonMessage: document.getElementById('coming-soon-message'),
    loginIcon: document.getElementById('login-icon')
};

// Hide specific elements in Telegram
function isTelegram() {
    return typeof Telegram !== 'undefined' && Telegram.WebApp && Telegram.WebApp.initData;
}

if (isTelegram()) {
    domElements.loginIcon.style.display = 'none';
}

// Telegram-specific utilities
const telegramUtils = {
    downloadFile: async (blob, fileName) => {
        if (!isTelegram()) return false;
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = () => {
                const base64Data = reader.result.split(',')[1];
                Telegram.WebApp.sendData(JSON.stringify({
                    action: 'download',
                    file: base64Data,
                    filename: fileName,
                    mimeType: blob.type
                }));
                resolve(true);
            };
            reader.readAsDataURL(blob);
        });
    },

    shareFile: async (blob, fileName) => {
        if (!isTelegram()) return false;
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = () => {
                const base64Data = reader.result.split(',')[1];
                Telegram.WebApp.sendData(JSON.stringify({
                    action: 'share',
                    file: base64Data,
                    filename: fileName,
                    mimeType: blob.type
                }));
                resolve(true);
            };
            reader.readAsDataURL(blob);
        });
    }
};

// Enhanced secure passphrase generation
function generateSecurePassphrase(length = 16) {
    length = Math.max(length, CONFIG.MIN_PASSPHRASE_LENGTH);
    const charSets = {
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        digits: '0123456789',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.?'
    };
    const allChars = Object.values(charSets).join('');
    const getRandomChar = (str) => str[crypto.getRandomValues(new Uint32Array(1))[0] % str.length];
    
    let passphraseArray = [
        getRandomChar(charSets.uppercase),
        getRandomChar(charSets.lowercase),
        getRandomChar(charSets.digits),
        getRandomChar(charSets.symbols)
    ];
    
    while (passphraseArray.length < length) {
        passphraseArray.push(getRandomChar(allChars));
    }
    
    for (let i = passphraseArray.length - 1; i > 0; i--) {
        const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
        [passphraseArray[i], passphraseArray[j]] = [passphraseArray[j], passphraseArray[i]];
    }
    
    const passphrase = passphraseArray.join('');
    try {
        cryptoUtils.validatePassphrase(passphrase);
        return passphrase;
    } catch (error) {
        console.warn('Generated passphrase failed validation, regenerating:', error.message);
        return generateSecurePassphrase(length);
    }
}

// Hidden file input for image upload
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = 'image/*';
fileInput.style.display = 'none';
document.body.appendChild(fileInput);

// Hidden canvas for video processing
const scanCanvas = document.createElement('canvas');
const scanContext = scanCanvas.getContext('2d');
scanCanvas.style.display = 'none';
document.body.appendChild(scanCanvas);

// Brute force protection variables
let decryptAttempts = 0;
let lastDecryptAttemptTime = 0;
let cameraTimeoutId = null;

// Clear ArrayBuffer or TypedArray
const clearBuffer = (buffer) => {
    if (buffer instanceof ArrayBuffer) {
        new Uint8Array(buffer).fill(0);
    } else if (buffer instanceof Uint8Array || buffer instanceof Int32Array || buffer instanceof Float32Array) {
        buffer.fill(0);
    } else {
        console.warn("clearBuffer: Object is not an ArrayBuffer or TypedArray.");
    }
};

// Tutorial modal logic
const shouldShowModal = () => localStorage.getItem('dontShowAgain') !== 'true';
const showTutorialModal = () => {
    if (shouldShowModal()) domElements.tutorialModal.style.display = 'flex';
};
const closeTutorialModal = () => domElements.tutorialModal.style.display = 'none';
const setDontShowAgain = () => {
    localStorage.setItem('dontShowAgain', 'true');
    closeTutorialModal();
};

// "Coming Soon" message
const showComingSoonMessage = () => {
    domElements.comingSoonMessage.classList.add('visible');
    setTimeout(() => domElements.comingSoonMessage.classList.remove('visible'), 2000);
};

// Cryptographic utilities
const cryptoUtils = {
    stringToArrayBuffer: str => new TextEncoder().encode(str),
    arrayBufferToString: buffer => new TextDecoder().decode(buffer),

    validatePassphrase: (passphrase) => {
        if (!passphrase || passphrase.length < CONFIG.MIN_PASSPHRASE_LENGTH) throw new Error(`Passphrase must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters long`);
        if (/^(.)\1+$/.test(passphrase)) throw new Error('Passphrase cannot consist of repeated characters');
        if (new Set(passphrase).size < 5) throw new Error('Passphrase must have at least 5 unique characters');
        const commonPasswords = ['password', '123456', 'qwerty', 'admin'];
        if (commonPasswords.includes(passphrase.toLowerCase())) throw new Error('Passphrase is too common');
        if (/[<>'"&\\/]/.test(passphrase)) throw new Error('Passphrase contains invalid characters');
        return true;
    },

    generateIV: () => {
        const nonce = new Uint8Array(CONFIG.IV_LENGTH);
        crypto.getRandomValues(nonce.slice(0, 8));
        const timestamp = Math.floor(Date.now() / 1000);
        nonce.set(new Uint8Array(new Int32Array([timestamp]).buffer), 8);
        return nonce;
    },

    deriveKeyPair: async (passphrase, salt) => {
        const baseKeyMaterial = await crypto.subtle.importKey(
            'raw', cryptoUtils.stringToArrayBuffer(passphrase), { name: 'PBKDF2' }, false, ['deriveBits']
        );
        const derivedBits = await crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt, iterations: CONFIG.PBKDF2_ITERATIONS, hash: 'SHA-256' },
            baseKeyMaterial,
            CONFIG.AES_KEY_LENGTH + CONFIG.HMAC_LENGTH
        );
        const derivedBitsArray = new Uint8Array(derivedBits);
        const aesKey = await crypto.subtle.importKey(
            'raw', derivedBitsArray.slice(0, CONFIG.AES_KEY_LENGTH / 8), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
        );
        const hmacKey = await crypto.subtle.importKey(
            'raw', derivedBitsArray.slice(CONFIG.AES_KEY_LENGTH / 8), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
        );
        clearBuffer(derivedBitsArray);
        return { aesKey, hmacKey };
    },

    encryptMessage: async (message, passphrase) => {
        let dataToEncrypt = cryptoUtils.stringToArrayBuffer(message);
        let salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
        let iv = cryptoUtils.generateIV();
        try {
            cryptoUtils.validatePassphrase(passphrase);
            if (message.length > CONFIG.COMPRESSION_THRESHOLD) {
                dataToEncrypt = pako.deflate(dataToEncrypt, { level: 6 });
            }
            const { aesKey, hmacKey } = await cryptoUtils.deriveKeyPair(passphrase, salt);
            const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, dataToEncrypt);
            const hmac = await crypto.subtle.sign('HMAC', hmacKey, encrypted);
            const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted), ...new Uint8Array(hmac)]);
            return btoa(String.fromCharCode(...combined));
        } finally {
            clearBuffer(dataToEncrypt);
            clearBuffer(salt);
            clearBuffer(iv);
        }
    },

    decryptMessage: async (encryptedBase64, passphrase) => {
        const now = Date.now();
        if (decryptAttempts >= CONFIG.MAX_DECRYPT_ATTEMPTS && (now - lastDecryptAttemptTime) < CONFIG.DECRYPT_COOLDOWN) {
            throw new Error('Too many failed attempts. Please wait before trying again.');
        }
        
        let encryptedData, salt, iv, ciphertext, hmac, decrypted;
        try {
            encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            salt = encryptedData.slice(0, CONFIG.SALT_LENGTH);
            iv = encryptedData.slice(CONFIG.SALT_LENGTH, CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);
            ciphertext = encryptedData.slice(CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH, -32);
            hmac = encryptedData.slice(-32);
            
            const { aesKey, hmacKey } = await cryptoUtils.deriveKeyPair(passphrase, salt);
            const isValid = await crypto.subtle.verify('HMAC', hmacKey, hmac, ciphertext);
            if (!isValid) throw new Error('Integrity check failed: Data has been tampered with');
            
            decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
            let decompressed;
            try {
                decompressed = pako.inflate(new Uint8Array(decrypted));
            } catch (e) {
                decompressed = new Uint8Array(decrypted);
            }
            decryptAttempts = 0; // Reset on success
            return cryptoUtils.arrayBufferToString(decompressed);
        } catch (error) {
            decryptAttempts++;
            lastDecryptAttemptTime = now;
            await new Promise(resolve => setTimeout(resolve, decryptAttempts * CONFIG.DECRYPT_DELAY_INCREMENT));
            throw error;
        } finally {
            clearBuffer(salt);
            clearBuffer(iv);
            clearBuffer(decrypted);
        }
    }
};

// UI Controller
const uiController = {
    displayMessage: (content, isSent = false, isPassphrase = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        const messageType = content.startsWith('Encrypted:') ? 'encrypted' : content.startsWith('Decrypted:') ? 'decrypted' : 'notice';
        messageEl.dataset.messageType = messageType;

        if (isPassphrase) {
            messageEl.innerHTML = `
                <div class="message-content">
                    <span class="passphrase-text">${content}</span>
                    <i class="fas fa-copy copy-icon" title="Copy to clipboard"></i>
                </div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
            messageEl.querySelector('.copy-icon').addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(content);
                    uiController.displayMessage('Passphrase copied to clipboard!', false);
                } catch (error) {
                    uiController.displayMessage('Failed to copy passphrase.', false);
                }
            });
            setTimeout(() => messageEl.remove(), CONFIG.NOTICE_TIMEOUT);
        } else {
            messageEl.innerHTML = `
                <div class="message-content">${content}</div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
            if (messageType === 'notice') setTimeout(() => messageEl.remove(), CONFIG.NOTICE_TIMEOUT);
        }

        while (domElements.messagesDiv.children.length >= 7) {
            domElements.messagesDiv.removeChild(domElements.messagesDiv.firstChild);
        }
        domElements.messagesDiv.appendChild(messageEl);
        domElements.messagesDiv.scrollTop = domElements.messagesDiv.scrollHeight;
        return messageEl;
    },

    generateQR: async (data) => {
        const qrSize = Math.min(CONFIG.MAX_QR_SIZE, Math.max(CONFIG.QR_SIZE, Math.ceil(data.length / 20) * 10 + 150));
        domElements.qrCanvas.width = qrSize;
        domElements.qrCanvas.height = qrSize;

        await new Promise((resolve, reject) => {
            QRCode.toCanvas(domElements.qrCanvas, data, {
                width: qrSize,
                margin: 1,
                color: { dark: '#000000', light: '#ffffff' },
                errorCorrectionLevel: 'H'
            }, (error) => error ? reject(error) : resolve());
        });

        const ctx = domElements.qrCanvas.getContext('2d');
        const circleRadius = qrSize * 0.15;
        const center = qrSize / 2;
        ctx.beginPath();
        ctx.arc(center, center, circleRadius, 0, Math.PI * 2);
        ctx.fillStyle = 'var(--primary-color)';
        ctx.fill();
        ctx.fillStyle = '#00cc99';
        ctx.font = `bold ${qrSize * 0.08}px "Segoe UI", sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('HUSH', center, center - circleRadius * 0.2);
        ctx.fillText('BOX', center, center + circleRadius * 0.3);
        
        domElements.qrContainer.classList.remove('hidden');
    },

    showLoader: (button, text = 'Processing...') => {
        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        button.disabled = true;
    },

    resetButton: (button, originalHTML) => {
        button.innerHTML = originalHTML;
        button.disabled = false;
    }
};

// Event Handlers
const handlers = {
    handleEncrypt: async () => {
        const message = domElements.messageInput.value.trim();
        const passphrase = domElements.passphraseInput.value.trim();
        if (!message || !passphrase) {
            uiController.displayMessage('Please enter both a message and a passphrase', false);
            return;
        }

        const originalHTML = domElements.sendButton.innerHTML;
        uiController.showLoader(domElements.sendButton, 'Encrypting...');
        try {
            const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
            await uiController.generateQR(encrypted);
            uiController.displayMessage(`Encrypted: ${encrypted.slice(0, 40)}...`, true);
            domElements.messageInput.value = '';
            domElements.passphraseInput.value = '';
        } catch (error) {
            uiController.displayMessage(error.message || 'Encryption failed', false);
        } finally {
            uiController.resetButton(domElements.sendButton, originalHTML);
        }
    },

    handleDecrypt: async () => {
        const file = fileInput.files[0];
        const passphrase = domElements.passphraseInput.value.trim();
        if (!file || !passphrase) {
            uiController.displayMessage('Please select a QR file and enter a passphrase', false);
            return;
        }

        const originalHTML = domElements.decodeButton.innerHTML;
        uiController.showLoader(domElements.decodeButton, 'Decrypting...');
        try {
            const imageData = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => {
                    const img = new Image();
                    img.onload = () => {
                        const canvas = document.createElement('canvas');
                        const MAX_SIZE = 800;
                        let width = img.width;
                        let height = img.height;
                        if (width > height && width > MAX_SIZE) {
                            height *= MAX_SIZE / width;
                            width = MAX_SIZE;
                        } else if (height > MAX_SIZE) {
                            width *= MAX_SIZE / height;
                            height = MAX_SIZE;
                        }
                        canvas.width = width;
                        canvas.height = height;
                        canvas.getContext('2d').drawImage(img, 0, 0, width, height);
                        resolve(canvas.getContext('2d').getImageData(0, 0, width, height));
                    };
                    img.onerror = reject;
                    img.src = e.target.result;
                };
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });

            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
            if (!qrCode) throw new Error('No QR code detected');
            
            const decrypted = await cryptoUtils.decryptMessage(qrCode.data, passphrase);
            uiController.displayMessage(`Decrypted: ${decrypted}`, false);
            domElements.passphraseInput.value = '';
            fileInput.value = '';
        } catch (error) {
            uiController.displayMessage(error.message || 'Decryption failed. Wrong passphrase?', false);
        } finally {
            uiController.resetButton(domElements.decodeButton, originalHTML);
        }
    },

    handleDownload: async () => {
        if (!domElements.qrCanvas.toDataURL) {
            uiController.displayMessage('No QR code available to download', false);
            return;
        }

        try {
            const qrDataUrl = domElements.qrCanvas.toDataURL('image/png', 0.9);
            const fileName = `hushbox-qr-${new Date().toISOString().replace(/[:.]/g, '-')}.png`;
            
            if (isTelegram()) {
                await telegramUtils.downloadFile(await (await fetch(qrDataUrl)).blob(), fileName);
                uiController.displayMessage('Download started in Telegram', false);
            } else {
                const link = document.createElement('a');
                link.href = qrDataUrl;
                link.download = fileName;
                link.click();
                link.remove();
                uiController.displayMessage('QR downloaded successfully!', false);
            }
        } catch (error) {
            uiController.displayMessage('Download failed: ' + error.message, false);
        }
    },

    handleShare: async () => {
        if (!domElements.qrCanvas.toDataURL) {
            uiController.displayMessage('No QR code available to share', false);
            return;
        }

        try {
            const qrDataUrl = domElements.qrCanvas.toDataURL('image/png');
            const qrBlob = await (await fetch(qrDataUrl)).blob();
            
            if (isTelegram()) {
                await telegramUtils.shareFile(qrBlob, `hushbox-qr-${Date.now()}.png`);
                uiController.displayMessage('Sharing via Telegram...', false);
            } else if (navigator.share) {
                await navigator.share({
                    title: 'HushBox Secure QR',
                    files: [new File([qrBlob], 'hushbox-qr.png', { type: 'image/png' })]
                });
            } else {
                await navigator.clipboard.writeText(qrDataUrl);
                uiController.displayMessage('QR copied to clipboard!', false);
            }
        } catch (error) {
            uiController.displayMessage('Share failed: ' + error.message, false);
        }
    },

    stopCamera: () => {
        const stream = domElements.cameraPreview.srcObject;
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            domElements.cameraPreview.srcObject = null;
            domElements.cameraContainer.classList.add('hidden');
            if (cameraTimeoutId) {
                clearTimeout(cameraTimeoutId);
                cameraTimeoutId = null;
            }
        }
    },

    handleUploadArrow: () => fileInput.click()
};

// DOMContentLoaded Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    const generateButton = document.querySelector('.generate-password');
    if (generateButton) {
        generateButton.addEventListener('click', () => {
            const securePassphrase = generateSecurePassphrase(16);
            domElements.passphraseInput.value = securePassphrase;
            domElements.passphraseInput.dispatchEvent(new Event('input'));
            uiController.displayMessage(securePassphrase, true, true);
        });
    }

    const charCounter = document.getElementById('char-counter');
    if (charCounter) {
        domElements.messageInput.addEventListener('input', () => {
            const currentLength = domElements.messageInput.value.length;
            const maxLength = domElements.messageInput.getAttribute('maxlength') || 500;
            charCounter.textContent = `${currentLength}/${maxLength}`;
            charCounter.style.color = currentLength >= maxLength * 0.9 ? 'var(--error-color)' : 'rgba(160, 160, 160, 0.8)';
        });
    }

    domElements.uploadArrowButton.addEventListener('click', handlers.handleUploadArrow);
    domElements.sendButton.addEventListener('click', handlers.handleEncrypt);
    domElements.decodeButton.addEventListener('click', handlers.handleDecrypt);
    domElements.downloadButton.addEventListener('click', handlers.handleDownload);
    domElements.shareButton.addEventListener('click', handlers.handleShare);
    fileInput.addEventListener('change', () => {
        domElements.decodeButton.disabled = !fileInput.files.length;
        if (fileInput.files.length) handlers.handleDecrypt();
    });

    domElements.passphraseInput.addEventListener('input', (e) => {
        const passphrase = e.target.value;
        const keyIcon = domElements.passphraseInput.parentElement.querySelector('.fa-key');
        if (!keyIcon) return;
        if (!passphrase) {
            keyIcon.style.color = 'rgba(160, 160, 160, 0.6)';
        } else {
            try {
                cryptoUtils.validatePassphrase(passphrase);
                keyIcon.style.color = 'var(--success-color)';
            } catch {
                keyIcon.style.color = 'var(--error-color)';
            }
        }
    });

    showTutorialModal();
    domElements.closeTutorial.addEventListener('click', closeTutorialModal);
    domElements.closeModalButton.addEventListener('click', closeTutorialModal);
    domElements.dontShowAgain.addEventListener('click', setDontShowAgain);
    domElements.scanButton.addEventListener('click', () => {
        if (isTelegram()) {
            Telegram.WebApp.showScanQrPopup({ text: 'Scan HUSHBOX QR' });
            Telegram.WebApp.onEvent('qrTextReceived', async (qrData) => {
                try {
                    const blob = new Blob([qrData], { type: 'text/plain' });
                    const fakeFile = new File([blob], 'telegram-qr.txt', { type: 'text/plain' });
                    fileInput.files = new DataTransfer().items.add(fakeFile).files;
                    fileInput.dispatchEvent(new Event('change'));
                    Telegram.WebApp.closeScanQrPopup();
                } catch (error) {
                    uiController.displayMessage('Error processing QR: ' + error.message, false);
                }
            });
        } else {
            showComingSoonMessage();
        }
    });
    domElements.imageButton.addEventListener('click', showComingSoonMessage);
    domElements.pdfButton.addEventListener('click', showComingSoonMessage);

    domElements.decodeButton.disabled = true;
});

// Cleanup on page unload
window.addEventListener('beforeunload', handlers.stopCamera);

// Initialization
domElements.qrContainer.classList.add('hidden');
domElements.cameraContainer.classList.add('hidden');
