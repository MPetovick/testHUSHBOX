// Configuración global para parámetros criptográficos
const CONFIG = {
    PBKDF2_ITERATIONS: 500000,
    SALT_LENGTH: 32,
    IV_LENGTH: 12,
    AES_KEY_LENGTH: 256,
    HMAC_LENGTH: 256,
    QR_SIZE: 250,
    MIN_PASSPHRASE_LENGTH: 12
};

// Elementos del DOM
const domElements = {
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
    qrContainer: document.getElementById('qr-container')
};

// Input oculto para la carga de imágenes
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = 'image/*';
fileInput.style.display = 'none';
document.body.appendChild(fileInput);

// Canvas oculto para procesar el video
const scanCanvas = document.createElement('canvas');
const scanContext = scanCanvas.getContext('2d');
scanCanvas.style.display = 'none';
document.body.appendChild(scanCanvas);

// Utilidades criptográficas
const cryptoUtils = {
    stringToArrayBuffer: str => new TextEncoder().encode(str),
    arrayBufferToString: buffer => new TextDecoder().decode(buffer),

    validatePassphrase: (passphrase) => {
        if (passphrase.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
            throw new Error(`Passphrase must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters long`);
        }
        if (/^(.)\1+$/.test(passphrase)) {
            throw new Error('Passphrase cannot consist of repeated characters');
        }
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
            'raw',
            cryptoUtils.stringToArrayBuffer(passphrase),
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );

        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt,
                iterations: CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            baseKeyMaterial,
            CONFIG.AES_KEY_LENGTH + CONFIG.HMAC_LENGTH
        );

        const aesKey = await crypto.subtle.importKey(
            'raw',
            derivedBits.slice(0, CONFIG.AES_KEY_LENGTH / 8),
            { name: 'AES-GCM' },
            false,
            ['encrypt', 'decrypt']
        );

        const hmacKey = await crypto.subtle.importKey(
            'raw',
            derivedBits.slice(CONFIG.AES_KEY_LENGTH / 8),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign', 'verify']
        );

        return { aesKey, hmacKey };
    },

    encryptMessage: async (message, passphrase) => {
        try {
            cryptoUtils.validatePassphrase(passphrase);
            const compressed = pako.deflate(cryptoUtils.stringToArrayBuffer(message), { level: 6 });
            const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
            const iv = cryptoUtils.generateIV();
            const { aesKey, hmacKey } = await cryptoUtils.deriveKeyPair(passphrase, salt);

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                compressed
            );

            const hmac = await crypto.subtle.sign(
                'HMAC',
                hmacKey,
                encrypted
            );

            const combined = new Uint8Array([
                ...salt,
                ...iv,
                ...new Uint8Array(encrypted),
                ...new Uint8Array(hmac)
            ]);
            return btoa(String.fromCharCode(...combined));
        } catch (error) {
            throw new Error('Encryption failed: ' + error.message);
        }
    },

    decryptMessage: async (encryptedBase64, passphrase) => {
        try {
            const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            const salt = encryptedData.slice(0, CONFIG.SALT_LENGTH);
            const iv = encryptedData.slice(CONFIG.SALT_LENGTH, CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);
            const ciphertext = encryptedData.slice(CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH, -32);
            const hmac = encryptedData.slice(-32);

            const { aesKey, hmacKey } = await cryptoUtils.deriveKeyPair(passphrase, salt);

            const isValid = await crypto.subtle.verify(
                'HMAC',
                hmacKey,
                hmac,
                ciphertext
            );

            if (!isValid) {
                throw new Error('Integrity check failed: Data has been tampered with');
            }

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                ciphertext
            );

            const decompressed = pako.inflate(new Uint8Array(decrypted));
            return cryptoUtils.arrayBufferToString(decompressed);
        } catch (error) {
            await new Promise(resolve => setTimeout(resolve, 100));
            throw new Error('Decryption failed: ' + error.message);
        }
    }
};

// Controlador de la interfaz de usuario
const uiController = {
    displayMessage: (content, isSent = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        messageEl.innerHTML = `
            <div class="message-content">${content}</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        `;
        if (!isSent) {
            domElements.messagesDiv.querySelector('.message-placeholder')?.remove();
        }
        domElements.messagesDiv.appendChild(messageEl);
        domElements.messagesDiv.scrollTop = domElements.messagesDiv.scrollHeight;
    },

    generateQR: async (data) => {
        return new Promise((resolve, reject) => {
            QRCode.toCanvas(domElements.qrCanvas, data, {
                width: CONFIG.QR_SIZE,
                margin: 2,
                color: { dark: '#000000', light: '#ffffff' }
            }, (error) => {
                if (error) {
                    reject(error);
                } else {
                    const ctx = domElements.qrCanvas.getContext('2d');
                    const circleRadius = 40, circleX = CONFIG.QR_SIZE / 2, circleY = CONFIG.QR_SIZE / 2;

                    ctx.beginPath();
                    ctx.arc(circleX, circleY, circleRadius, 0, Math.PI * 2);
                    ctx.fillStyle = 'var(--primary-color)';
                    ctx.fill();

                    ctx.fillStyle = '#00cc99';
                    ctx.font = 'bold 18px "Segoe UI", system-ui, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('HUSH', circleX, circleY - 10);
                    ctx.fillText('BOX', circleX, circleY + 15);

                    domElements.qrContainer.classList.remove('hidden');
                    resolve();
                }
            });
        });
    },

    showLoader: (button, text = 'Processing...') => {
        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        button.disabled = true;
    },

    resetButton: (button, originalHTML) => {
        button.innerHTML = originalHTML;
        button.disabled = false;
    },

    showComingSoon: () => {
        // Crear el elemento del mensaje
        const comingSoonEl = document.createElement('div');
        comingSoonEl.className = 'coming-soon-message';
        comingSoonEl.textContent = 'COMING SOON';

        // Añadirlo al body
        document.body.appendChild(comingSoonEl);

        // Eliminarlo después de 3 segundos
        setTimeout(() => {
            comingSoonEl.remove();
        }, 3000);
    }
};

// Manejadores de eventos
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
            navigator.clipboard.writeText(encrypted);
            uiController.displayMessage('Encrypted text copied to clipboard!', false);
            domElements.messageInput.value = '';
            domElements.passphraseInput.value = '';
        } catch (error) {
            console.error('Encryption error:', error);
            uiController.displayMessage(error.message || 'Encryption failed. Please try again.', false);
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
            if (typeof jsQR === 'undefined') {
                throw new Error('jsQR library not loaded. Please refresh the page.');
            }

            const imageData = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = e => {
                    const img = new Image();
                    img.onload = () => {
                        const canvas = document.createElement('canvas');
                        canvas.width = img.width;
                        canvas.height = img.height;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0);
                        resolve(ctx.getImageData(0, 0, img.width, img.height));
                    };
                    img.onerror = reject;
                    img.src = e.target.result;
                };
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });

            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
            if (!qrCode) {
                throw new Error('No QR code detected in the image');
            }

            const decrypted = await cryptoUtils.decryptMessage(qrCode.data, passphrase);
            uiController.displayMessage(decrypted);
            domElements.passphraseInput.value = '';
            fileInput.value = '';
        } catch (error) {
            console.error('Decryption error:', error);
            uiController.displayMessage(
                error.message.includes('decrypt') || error.message.includes('Integrity')
                    ? 'Decryption failed. Wrong passphrase or tampered data?'
                    : error.message,
                false
            );
        } finally {
            uiController.resetButton(domElements.decodeButton, originalHTML);
        }
    },

    handleDownload: () => {
        const link = document.createElement('a');
        link.download = 'hushbox-qr.png';
        link.href = domElements.qrCanvas.toDataURL('image/png', 1.0);
        link.click();
    },

    handleShare: async () => {
        const qrDataUrl = domElements.qrCanvas.toDataURL('image/png', 1.0);
        const qrBlob = await (await fetch(qrDataUrl)).blob();
        const qrFile = new File([qrBlob], 'hushbox-qr.png', { type: 'image/png' });

        if (navigator.share && navigator.canShare({ files: [qrFile] })) {
            try {
                await navigator.share({
                    title: 'HushBox Secure QR',
                    text: 'Check out this encrypted QR code from HushBox!',
                    files: [qrFile]
                });
                uiController.displayMessage('QR shared successfully!', false);
            } catch (error) {
                console.error('Share error:', error);
                uiController.displayMessage('Sharing failed: ' + error.message, false);
            }
        } else {
            try {
                await navigator.clipboard.writeText(qrDataUrl);
                uiController.displayMessage('QR data URL copied to clipboard!', false);
            } catch (error) {
                console.error('Clipboard error:', error);
                uiController.displayMessage('Failed to copy QR to clipboard', false);
            }
        }
    },

    handleScan: async () => {
        try {
            const permission = await navigator.permissions.query({ name: 'camera' });
            if (permission.state === 'denied') {
                uiController.displayMessage('Camera access denied. Please enable it in your settings.', false);
                return;
            }

            if (typeof jsQR === 'undefined') {
                throw new Error('jsQR library not loaded. Please refresh the page.');
            }

            const stream = await navigator.mediaDevices.getUserMedia({ 
                video: { facingMode: 'environment' }
            });
            domElements.cameraPreview.srcObject = stream;
            domElements.cameraContainer.classList.remove('hidden');

            uiController.displayMessage('Scanning QR code... Aim the camera at the QR.', false);

            scanCanvas.width = domElements.cameraPreview.videoWidth;
            scanCanvas.height = domElements.cameraPreview.videoHeight;

            let isScanning = true;
            const scanFrame = () => {
                if (!isScanning || !domElements.cameraPreview.srcObject) return;

                scanContext.drawImage(domElements.cameraPreview, 0, 0, scanCanvas.width, scanCanvas.height);
                const imageData = scanContext.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

                if (qrCode) {
                    isScanning = false;
                    handlers.stopCamera();
                    processQR(qrCode.data);
                } else {
                    requestAnimationFrame(scanFrame);
                }
            };

            const processQR = async (qrData) => {
                const passphrase = domElements.passphraseInput.value.trim();
                if (!passphrase) {
                    uiController.displayMessage('Please enter a passphrase to decrypt the QR.', false);
                    return;
                }

                try {
                    const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
                    uiController.displayMessage(decrypted);
                    domElements.passphraseInput.value = '';
                } catch (error) {
                    uiController.displayMessage(
                        error.message.includes('decrypt') || error.message.includes('Integrity')
                            ? 'Decryption failed. Wrong passphrase or tampered data?'
                            : error.message,
                        false
                    );
                }
            };

            requestAnimationFrame(scanFrame);

        } catch (error) {
            console.error('Scan error:', error);
            uiController.displayMessage('Error scanning QR: ' + error.message, false);
            handlers.stopCamera();
        }
    },

    stopCamera: () => {
        const stream = domElements.cameraPreview.srcObject;
        if (stream) {
            stream.getTracks().forEach(track => track.stop());
            domElements.cameraPreview.srcObject = null;
            domElements.cameraContainer.classList.add('hidden');
        }
    },

    handleImageUpload: () => {
        fileInput.click();
    },

    handlePDFUpload: () => {
        uiController.showComingSoon();
    }
};

// Event listeners
domElements.sendButton.addEventListener('click', handlers.handleEncrypt);
domElements.decodeButton.addEventListener('click', handlers.handleDecrypt);
domElements.downloadButton.addEventListener('click', handlers.handleDownload);
domElements.shareButton.addEventListener('click', handlers.handleShare);
domElements.scanButton.addEventListener('click', handlers.handleScan);
domElements.imageButton.addEventListener('click', handlers.handleImageUpload);
domElements.pdfButton.addEventListener('click', handlers.handlePDFUpload);
fileInput.addEventListener('change', handlers.handleDecrypt);

// Validación visual de la passphrase
domElements.passphraseInput.addEventListener('input', (e) => {
    const passphrase = e.target.value;
    const keyIcon = domElements.passphraseInput.parentElement.querySelector('.icon');

    if (passphrase.length === 0) {
        keyIcon.style.color = 'rgba(160, 160, 160, 0.6)';
    } else if (passphrase.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
        keyIcon.style.color = 'var(--error-color)';
    } else {
        try {
            cryptoUtils.validatePassphrase(passphrase);
            keyIcon.style.color = 'var(--success-color)';
        } catch (error) {
            keyIcon.style.color = 'var(--error-color)';
        }
    }
});

// Detener la cámara al salir de la página si está activa
window.addEventListener('beforeunload', (e) => {
    if (domElements.cameraPreview.srcObject) {
        e.preventDefault();
        e.returnValue = 'Camera is active. Are you sure you want to leave?';
        handlers.stopCamera();
    }
});

// Inicialización
domElements.qrContainer.classList.add('hidden');
domElements.cameraContainer.classList.add('hidden');
