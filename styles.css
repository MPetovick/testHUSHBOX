// Configuración global
const CONFIG = {
    PBKDF2_ITERATIONS: 250000,
    SALT_LENGTH: 32,
    IV_LENGTH: 12,
    AES_KEY_LENGTH: 256,
    QR_SIZE: 200,
    MIN_PASSPHRASE_LENGTH: 12,
    CAMERA_TIMEOUT: 30000,
    DECRYPT_DELAY_INCREMENT: 100,
    MAX_DECRYPT_ATTEMPTS: 5,
    NOTICE_TIMEOUT: 10000
};

// Elementos del DOM
const dom = {
    uploadArrow: document.getElementById('upload-arrow-button'),
    scanButton: document.getElementById('scan-button'),
    imageButton: document.getElementById('image-button'),
    pdfButton: document.getElementById('pdf-button'),
    messages: document.getElementById('messages'),
    passphrase: document.getElementById('passphrase'),
    messageInput: document.getElementById('message-input'),
    sendButton: document.getElementById('send-button'),
    qrCanvas: document.getElementById('qr-canvas'),
    decodeButton: document.getElementById('decode-button'),
    downloadButton: document.getElementById('download-button'),
    shareButton: document.getElementById('share-button'),
    qrContainer: document.getElementById('qr-container'),
    comingSoon: document.getElementById('coming-soon-message'),
    cameraModal: document.getElementById('camera-modal'),
    cameraPreview: document.getElementById('camera-preview'),
    closeCamera: document.getElementById('close-camera'),
    fileInput: document.createElement('input'),
    charCounter: document.getElementById('char-counter'),
    generatePass: document.querySelector('.generate-password')
};

// Inicialización
dom.fileInput.type = 'file';
dom.fileInput.accept = 'image/*';
dom.fileInput.style.display = 'none';
document.body.appendChild(dom.fileInput);

// Utilidades criptográficas
const cryptoUtils = {
    validatePassphrase: (pass) => {
        if (pass.length < CONFIG.MIN_PASSPHRASE_LENGTH) 
            throw new Error(`Passphrase must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters`);
        if (/(.)\1{3,}/.test(pass)) 
            throw new Error('Passphrase has too many repeated characters');
        return true;
    },

    generateSecurePass: (length = 16) => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
        const values = new Uint32Array(length);
        crypto.getRandomValues(values);
        return Array.from(values, v => chars[v % chars.length]).join('');
    },

    encryptMessage: async (message, passphrase) => {
        try {
            cryptoUtils.validatePassphrase(passphrase);
            const data = new TextEncoder().encode(message);
            const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
            const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));
            
            const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 
                { name: 'PBKDF2' }, false, ['deriveBits']);
                
            const keyMaterial = await crypto.subtle.deriveBits({
                name: 'PBKDF2',
                salt,
                iterations: CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            }, baseKey, 256);
            
            const key = await crypto.subtle.importKey('raw', keyMaterial, 
                { name: 'AES-GCM' }, false, ['encrypt']);
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv }, key, data
            );
            
            const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
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
            const ciphertext = encryptedData.slice(CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);
            
            const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 
                { name: 'PBKDF2' }, false, ['deriveBits']);
                
            const keyMaterial = await crypto.subtle.deriveBits({
                name: 'PBKDF2',
                salt,
                iterations: CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            }, baseKey, 256);
            
            const key = await crypto.subtle.importKey('raw', keyMaterial, 
                { name: 'AES-GCM' }, false, ['decrypt']);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, key, ciphertext
            );
            
            return new TextDecoder().decode(decrypted);
        } catch (error) {
            throw new Error('Decryption failed: ' + error.message);
        }
    }
};

// Controlador de UI
const ui = {
    displayMessage: (content, isSent = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        messageEl.innerHTML = `
            <div class="message-content">${content}</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        `;
        
        if (dom.messages.children.length === 0) {
            dom.messages.querySelector('.message-placeholder')?.remove();
        }
        
        if (dom.messages.children.length >= 7) {
            dom.messages.removeChild(dom.messages.firstChild);
        }
        
        dom.messages.appendChild(messageEl);
        dom.messages.scrollTop = dom.messages.scrollHeight;
    },

    generateQR: async (data) => {
        return new Promise((resolve) => {
            QRCode.toCanvas(dom.qrCanvas, data, {
                width: 200,
                margin: 1,
                color: { dark: '#000', light: '#fff' },
                errorCorrectionLevel: 'H'
            }, () => {
                dom.qrContainer.classList.remove('hidden');
                resolve();
            });
        });
    },

    toggleButton: (btn, state, text = '') => {
        btn.disabled = state;
        if (text) btn.innerHTML = text;
    },

    showCameraModal: () => {
        dom.cameraModal.style.display = 'flex';
        handlers.startCamera();
    },

    hideCameraModal: () => {
        dom.cameraModal.style.display = 'none';
        handlers.stopCamera();
    },

    showScanEffect: () => {
        const overlay = document.querySelector('.scanner-overlay');
        overlay.classList.add('scan-success');
        setTimeout(() => overlay.classList.remove('scan-success'), 1000);
    }
};

// Manejadores de eventos
const handlers = {
    handleEncrypt: async () => {
        const message = dom.messageInput.value.trim();
        const passphrase = dom.passphrase.value.trim();
        
        if (!message || !passphrase) {
            ui.displayMessage('Please enter both message and passphrase');
            return;
        }
        
        ui.toggleButton(dom.sendButton, true, '<i class="fas fa-spinner fa-spin"></i> Encrypting');
        
        try {
            const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
            await ui.generateQR(encrypted);
            ui.displayMessage(`Encrypted: ${encrypted.slice(0, 40)}...`, true);
            dom.messageInput.value = '';
            dom.passphrase.value = '';
        } catch (error) {
            ui.displayMessage(error.message);
        } finally {
            ui.toggleButton(dom.sendButton, false, '<i class="fas fa-lock"></i> Encrypt');
        }
    },

    handleDecrypt: async (qrData) => {
        const passphrase = dom.passphrase.value.trim();
        if (!passphrase) {
            ui.displayMessage('Please enter passphrase');
            return;
        }
        
        ui.toggleButton(dom.decodeButton, true, '<i class="fas fa-spinner fa-spin"></i> Decrypting');
        
        try {
            const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
            ui.displayMessage(`Decrypted: ${decrypted}`);
            dom.passphrase.value = '';
        } catch (error) {
            ui.displayMessage(error.message);
        } finally {
            ui.toggleButton(dom.decodeButton, false, '<i class="fas fa-unlock"></i> Decrypt');
        }
    },

    startCamera: () => {
        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
        .then(stream => {
            dom.cameraPreview.srcObject = stream;
            const scanLoop = () => {
                if (!dom.cameraPreview.srcObject) return;
                
                const canvas = document.createElement('canvas');
                canvas.width = dom.cameraPreview.videoWidth;
                canvas.height = dom.cameraPreview.videoHeight;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(dom.cameraPreview, 0, 0, canvas.width, canvas.height);
                
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
                
                if (qrCode) {
                    ui.showScanEffect();
                    handlers.handleDecrypt(qrCode.data);
                    handlers.stopCamera();
                    ui.hideCameraModal();
                } else {
                    requestAnimationFrame(scanLoop);
                }
            };
            scanLoop();
        })
        .catch(error => {
            console.error('Camera error:', error);
            ui.displayMessage('Camera access denied. Please enable camera permissions.');
        });
    },

    stopCamera: () => {
        if (dom.cameraPreview.srcObject) {
            dom.cameraPreview.srcObject.getTracks().forEach(track => track.stop());
            dom.cameraPreview.srcObject = null;
        }
    },

    handleUpload: () => dom.fileInput.click(),

    handleFileSelect: async () => {
        const file = dom.fileInput.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = async (e) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
                
                if (qrCode) {
                    handlers.handleDecrypt(qrCode.data);
                } else {
                    ui.displayMessage('No QR code detected');
                }
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    },

    handleDownload: () => {
        const link = document.createElement('a');
        link.href = dom.qrCanvas.toDataURL('image/png');
        link.download = `hushbox-${Date.now()}.png`;
        link.click();
    },

    handleShare: async () => {
        try {
            const blob = await new Promise(resolve => dom.qrCanvas.toBlob(resolve));
            const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });
            
            if (navigator.share) {
                await navigator.share({
                    title: 'HushBox QR',
                    files: [file]
                });
            } else {
                throw new Error('Sharing not supported');
            }
        } catch (error) {
            handlers.handleDownload();
        }
    },

    showComingSoon: () => {
        dom.comingSoon.classList.add('visible');
        setTimeout(() => dom.comingSoon.classList.remove('visible'), 2000);
    },

    initEventListeners: () => {
        // Botones principales
        dom.sendButton.addEventListener('click', handlers.handleEncrypt);
        dom.decodeButton.addEventListener('click', handlers.handleFileSelect);
        dom.downloadButton.addEventListener('click', handlers.handleDownload);
        dom.shareButton.addEventListener('click', handlers.handleShare);
        
        // Cámara y archivos
        dom.scanButton.addEventListener('click', ui.showCameraModal);
        dom.closeCamera.addEventListener('click', ui.hideCameraModal);
        dom.uploadArrow.addEventListener('click', handlers.handleUpload);
        dom.fileInput.addEventListener('change', handlers.handleFileSelect);
        
        // Generar contraseña
        dom.generatePass.addEventListener('click', () => {
            const pass = cryptoUtils.generateSecurePass();
            dom.passphrase.value = pass;
            ui.displayMessage(`Generated: ${pass}`, true);
        });
        
        // Contador de caracteres
        dom.messageInput.addEventListener('input', () => {
            const len = dom.messageInput.value.length;
            dom.charCounter.textContent = `${len}/4000`;
            dom.charCounter.style.color = len > 3600 ? 'var(--error-color)' : 'rgba(160,160,160,0.8)';
        });
        
        // Botones deshabilitados
        dom.imageButton.addEventListener('click', handlers.showComingSoon);
        dom.pdfButton.addEventListener('click', handlers.showComingSoon);
    }
};

// Inicialización
document.addEventListener('DOMContentLoaded', () => {
    handlers.initEventListeners();
    dom.qrContainer.classList.add('hidden');
    dom.cameraModal.style.display = 'none';
});
