// Configuración global para parámetros criptográficos y de la aplicación
const CONFIG = {
    PBKDF2_ITERATIONS_DESKTOP: 250000,
    PBKDF2_ITERATIONS_MOBILE: 100000,
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
    DECRYPT_COOLDOWN: 5 * 60 * 1000,
    NOTICE_TIMEOUT: 10000
};

// Detectar si es un dispositivo móvil
const isMobileDevice = () => /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent);
const PBKDF2_ITERATIONS = isMobileDevice() ? CONFIG.PBKDF2_ITERATIONS_MOBILE : CONFIG.PBKDF2_ITERATIONS_DESKTOP;

// Elementos del DOM
const domElements = {
    uploadArrowButton: document.getElementById('upload-arrow-button'),
    scanButton: document.getElementById('scan-button'),
    imageButton: document.getElementById('image-button'),
    pdfButton: document.getElementById('pdf-button'),
    cameraModal: document.getElementById('camera-modal'),
    cameraCanvas: document.getElementById('camera-canvas'),
    messagesDiv: document.getElementById('messages'),
    passphraseInput: document.getElementById('passphrase'),
    passphraseError: document.getElementById('passphrase-error'),
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
    closeCameraModal: document.querySelector('.close-camera-modal'),
    toggleCameraButton: document.getElementById('toggle-camera-button')
};

// Input oculto para la carga de archivos
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = 'image/*,application/pdf';
fileInput.style.display = 'none';
document.body.appendChild(fileInput);

// Variables de estado
let decryptAttempts = 0;
let cameraStream = null;
let qrScanAnimation = null;
let currentFacingMode = 'environment';
let qrData = null;

// Función para limpiar buffers sensibles
const clearBuffer = (buffer) => {
    if (buffer instanceof ArrayBuffer || buffer instanceof Uint8Array || buffer instanceof Int32Array || buffer instanceof Float32Array) {
        buffer.fill(0);
    } else {
        console.warn('clearBuffer: Tipo de buffer no soportado.');
    }
};

// Modal de tutorial
const shouldShowModal = () => localStorage.getItem('dontShowAgain') !== 'true';
const showTutorialModal = () => {
    if (shouldShowModal()) {
        domElements.tutorialModal.style.display = 'flex';
        domElements.tutorialModal.focus();
    }
};
const closeTutorialModal = () => {
    domElements.tutorialModal.style.display = 'none';
};
const setDontShowAgain = () => {
    localStorage.setItem('dontShowAgain', 'true');
    closeTutorialModal();
};

// Generar contraseña segura
const generateSecurePassphrase = (length = 16) => {
    length = Math.max(length, CONFIG.MIN_PASSPHRASE_LENGTH);
    const charSets = {
        uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lowercase: 'abcdefghijklmnopqrstuvwxyz',
        digits: '0123456789',
        symbols: '!@#$%^&*()_+-=[]{}|;:,.?'
    };
    const allChars = Object.values(charSets).join('');
    const getRandomChar = (str) => str[crypto.getRandomValues(new Uint32Array(1))[0] % str.length];
    
    let passphrase = [
        getRandomChar(charSets.uppercase),
        getRandomChar(charSets.lowercase),
        getRandomChar(charSets.digits),
        getRandomChar(charSets.symbols),
        getRandomChar(allChars)
    ];
    
    for (let i = passphrase.length; i < length; i++) {
        passphrase.push(getRandomChar(allChars));
    }
    
    for (let i = passphrase.length - 1; i > 0; i--) {
        const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
        [passphrase[i], passphrase[j]] = [passphrase[j], passphrase[i]];
    }
    
    const result = passphrase.join('');
    try {
        cryptoUtils.validatePassphrase(result);
        return result;
    } catch {
        return generateSecurePassphrase(length);
    }
};

// Utilidades criptográficas
const cryptoUtils = {
    stringToArrayBuffer: (str) => new TextEncoder().encode(str),
    arrayBufferToString: (buffer) => new TextDecoder().decode(buffer),

    validatePassphrase: (passphrase) => {
        if (!passphrase || passphrase.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
            throw new Error(`Passphrase must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters long`);
        }
        if (/^(.)\1+$/.test(passphrase)) {
            throw new Error('Passphrase cannot consist of repeated characters');
        }
        if (new Set(passphrase).size < 5) {
            throw new Error('Passphrase must have at least 5 unique characters');
        }
        if (['password', '123456', 'qwerty', 'admin'].includes(passphrase.toLowerCase())) {
            throw new Error('Passphrase is too common');
        }
        if (/[<>'"&\\/]/.test(passphrase)) {
            throw new Error('Passphrase contains invalid characters');
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
        try {
            const baseKeyMaterial = await crypto.subtle.importKey(
                'raw',
                cryptoUtils.stringToArrayBuffer(passphrase),
                'PBKDF2',
                false,
                ['deriveBits']
            );

            const derivedBits = await crypto.subtle.deriveBits(
                {
                    name: 'PBKDF2',
                    salt,
                    iterations: PBKDF2_ITERATIONS,
                    hash: 'SHA-256'
                },
                baseKeyMaterial,
                CONFIG.AES_KEY_LENGTH + CONFIG.HMAC_LENGTH
            );

            const derivedBitsArray = new Uint8Array(derivedBits);
            const aesKey = await crypto.subtle.importKey(
                'raw',
                derivedBitsArray.slice(0, CONFIG.AES_KEY_LENGTH / 8),
                'AES-GCM',
                false,
                ['encrypt', 'decrypt']
            );

            const hmacKey = await crypto.subtle.importKey(
                'raw',
                derivedBitsArray.slice(CONFIG.AES_KEY_LENGTH / 8),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign', 'verify']
            );

            clearBuffer(derivedBitsArray);
            return { aesKey, hmacKey };
        } catch (error) {
            throw new Error(`Key derivation failed: ${error.message}`);
        }
    },

    encryptMessage: async (message, passphrase) => {
        let dataToEncrypt = null;
        let salt = null;
        let iv = null;
        try {
            cryptoUtils.validatePassphrase(passphrase);
            dataToEncrypt = cryptoUtils.stringToArrayBuffer(message);

            if (message.length > CONFIG.COMPRESSION_THRESHOLD) {
                dataToEncrypt = pako.deflate(dataToEncrypt, { level: 6 });
            }

            salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
            iv = cryptoUtils.generateIV();
            const { aesKey, hmacKey } = await cryptoUtils.deriveKeyPair(passphrase, salt);

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                dataToEncrypt
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
            throw new Error(`Encryption failed: ${error.message}`);
        } finally {
            if (dataToEncrypt) clearBuffer(dataToEncrypt);
            if (salt) clearBuffer(salt);
            if (iv) clearBuffer(iv);
        }
    },

    decryptMessage: async (encryptedBase64, passphrase) => {
        let salt = null;
        let iv = null;
        let decrypted = null;
        try {
            if (decryptAttempts >= CONFIG.MAX_DECRYPT_ATTEMPTS) {
                throw new Error('Too many failed attempts. Please try again later.');
            }

            const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            salt = encryptedData.slice(0, CONFIG.SALT_LENGTH);
            iv = encryptedData.slice(CONFIG.SALT_LENGTH, CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);
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

            decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                aesKey,
                ciphertext
            );

            let decompressed;
            try {
                decompressed = pako.inflate(new Uint8Array(decrypted));
            } catch {
                decompressed = new Uint8Array(decrypted);
            }
            return cryptoUtils.arrayBufferToString(decompressed);
        } catch (error) {
            decryptAttempts++;
            await new Promise(resolve => setTimeout(resolve, decryptAttempts * CONFIG.DECRYPT_DELAY_INCREMENT));
            throw new Error(`Decryption failed: ${error.message}`);
        } finally {
            if (salt) clearBuffer(salt);
            if (iv) clearBuffer(iv);
            if (decrypted) clearBuffer(decrypted);
        }
    }
};

// Controlador de la interfaz de usuario
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
                    <i class="fas fa-copy copy-icon" title="Copy to clipboard" aria-label="Copy passphrase"></i>
                </div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
            messageEl.querySelector('.copy-icon').addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(content);
                    uiController.displayMessage('Passphrase copied to clipboard!', false);
                    clearTimeout(messageEl.timeoutId);
                } catch {
                    uiController.displayMessage('Failed to copy passphrase.', false);
                }
            });
        } else {
            messageEl.innerHTML = `
                <div class="message-content">${content}</div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
        }

        if (messageType === 'notice') {
            messageEl.timeoutId = setTimeout(() => messageEl.remove(), CONFIG.NOTICE_TIMEOUT);
            messageEl.addEventListener('mouseenter', () => clearTimeout(messageEl.timeoutId));
            messageEl.addEventListener('mouseleave', () => {
                messageEl.timeoutId = setTimeout(() => messageEl.remove(), CONFIG.NOTICE_TIMEOUT);
            });
        }

        if (!isSent && domElements.messagesDiv.children.length === 0) {
            domElements.messagesDiv.querySelector('.message-placeholder')?.remove();
        }

        while (domElements.messagesDiv.children.length >= 7) {
            domElements.messagesDiv.firstChild.remove();
        }

        domElements.messagesDiv.appendChild(messageEl);
        domElements.messagesDiv.scrollTop = domElements.messagesDiv.scrollHeight;
        return messageEl;
    },

    showPassphraseError: (message) => {
        domElements.passphraseError.textContent = message;
        domElements.passphraseError.classList.add('visible');
        setTimeout(() => domElements.passphraseError.classList.remove('visible'), 3000);
    },

    generateQR: (data) => {
        return new Promise((resolve, reject) => {
            const qrSize = Math.min(CONFIG.MAX_QR_SIZE, Math.max(CONFIG.QR_SIZE, Math.ceil(data.length / 20) * 10 + 150));
            domElements.qrCanvas.width = qrSize;
            domElements.qrCanvas.height = qrSize;

            requestAnimationFrame(() => {
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = qrSize;
                tempCanvas.height = qrSize;

                QRCode.toCanvas(tempCanvas, data, {
                    width: qrSize,
                    margin: 1,
                    color: { dark: '#000000', light: '#ffffff' },
                    errorCorrectionLevel: 'H'
                }, (error) => {
                    if (error) return reject(error);

                    const ctx = tempCanvas.getContext('2d');
                    const circleRadius = qrSize * 0.15;
                    const circleX = qrSize / 2;
                    const circleY = qrSize / 2;

                    ctx.beginPath();
                    ctx.arc(circleX, circleY, circleRadius, 0, Math.PI * 2);
                    ctx.fillStyle = '#00cc99';
                    ctx.fill();

                    ctx.fillStyle = '#ffffff';
                    ctx.font = `bold ${qrSize * 0.08}px 'Segoe UI', sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('HUSH', circleX, circleY - circleRadius * 0.2);
                    ctx.fillText('BOX', circleX, circleY + circleRadius * 0.3);

                    const qrCtx = domElements.qrCanvas.getContext('2d');
                    qrCtx.clearRect(0, 0, qrSize, qrSize);
                    qrCtx.drawImage(tempCanvas, 0, 0, qrSize, qrSize);

                    domElements.qrContainer.classList.remove('hidden');
                    resolve();
                });
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

        try {
            cryptoUtils.validatePassphrase(passphrase);
        } catch (error) {
            uiController.showPassphraseError(error.message);
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
            uiController.displayMessage(error.message || 'Encryption failed.', false);
        } finally {
            uiController.resetButton(domElements.sendButton, originalHTML);
        }
    },

    handleDecrypt: async (data) => {
        const passphrase = domElements.passphraseInput.value.trim();

        if (!data || !passphrase) {
            uiController.displayMessage('Please provide a QR code and a passphrase', false);
            return;
        }

        const originalHTML = domElements.decodeButton.innerHTML;
        uiController.showLoader(domElements.decodeButton, 'Decrypting...');

        try {
            const decrypted = await cryptoUtils.decryptMessage(data, passphrase);
            uiController.displayMessage(`Decrypted: ${decrypted}`, false);
            domElements.passphraseInput.value = '';
            fileInput.value = '';
            qrData = null;
            decryptAttempts = 0;
        } catch (error) {
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

    handleDownload: async () => {
        try {
            const dataUrl = domElements.qrCanvas.toDataURL('image/png', 0.9);
            if (!dataUrl) {
                uiController.displayMessage('No QR code available to download.', false);
                return;
            }

            const blob = await fetch(dataUrl).then(res => res.blob());
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = `hushbox-qr-${timestamp}.png`;
            link.click();
            URL.revokeObjectURL(link.href);

            uiController.displayMessage('QR downloaded successfully!', false);
        } catch (error) {
            uiController.displayMessage('Failed to download QR.', false);
        }
    },

    handleShare: async () => {
        try {
            const dataUrl = domElements.qrCanvas.toDataURL('image/png', 0.9);
            if (!dataUrl) {
                uiController.displayMessage('No QR code available to share.', false);
                return;
            }

            const blob = await fetch(dataUrl).then(res => res.blob());
            const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });

            if (navigator.share && navigator.canShare({ files: [file] })) {
                await navigator.share({
                    title: 'HushBox Secure QR',
                    text: 'Check out this encrypted QR code from HushBox!',
                    files: [file]
                });
                uiController.displayMessage('QR shared successfully!', false);
            } else {
                await navigator.clipboard.writeText(dataUrl);
                uiController.displayMessage('QR code copied to clipboard!', false);
            }
        } catch (error) {
            uiController.displayMessage('Failed to share QR. Copied to clipboard.', false);
            await navigator.clipboard.writeText(domElements.qrCanvas.toDataURL('image/png', 0.9));
        }
    },

    stopCamera: () => {
        console.log('Stopping camera...');
        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
            cameraStream = null;
        }
        if (qrScanAnimation) {
            cancelAnimationFrame(qrScanAnimation);
            qrScanAnimation = null;
        }
        if (domElements.cameraModal) {
            domElements.cameraModal.style.display = 'none';
            domElements.cameraModal.classList.add('hidden');
        }
        window.removeEventListener('resize', handlers.updateCanvasSize);
    },

    updateCanvasSize: () => {
        if (!domElements.cameraCanvas || !cameraStream) return;
        const container = domElements.cameraCanvas.parentElement;
        const settings = cameraStream.getVideoTracks()[0]?.getSettings();
        const aspectRatio = settings?.aspectRatio || 16 / 9;
        let width = container.clientWidth;
        let height = width / aspectRatio;
        if (height > container.clientHeight) {
            height = container.clientHeight;
            width = height * aspectRatio;
        }
        domElements.cameraCanvas.width = Math.floor(width);
        domElements.cameraCanvas.height = Math.floor(height);
        console.log(`Canvas resized to ${width}x${height}`);
    },

    startCamera: async () => {
        console.log('Starting camera...');
        try {
            // Detener cualquier cámara activa
            handlers.stopCamera();

            // Solicitar acceso a la cámara
            cameraStream = await navigator.mediaDevices.getUserMedia({
                video: { 
                    facingMode: currentFacingMode, 
                    width: { ideal: 1280 }, 
                    height: { ideal: 720 }
                }
            });
            console.log('Camera stream acquired:', cameraStream);

            // Crear elemento de video temporal
            const video = document.createElement('video');
            video.srcObject = cameraStream;
            video.play();
            console.log('Video element playing');

            // Configurar el lienzo
            const ctx = domElements.cameraCanvas.getContext('2d');
            if (!ctx) {
                throw new Error('Failed to get canvas context');
            }

            // Escanear QR
            const scanQR = () => {
                if (!cameraStream || !domElements.cameraCanvas) return;

                try {
                    ctx.drawImage(video, 0, 0, domElements.cameraCanvas.width, domElements.cameraCanvas.height);
                    const imageData = ctx.getImageData(0, 0, domElements.cameraCanvas.width, domElements.cameraCanvas.height);
                    const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

                    if (qrCode) {
                        console.log('QR code detected:', qrCode.data);
                        const { topLeftCorner, topRightCorner, bottomRightCorner, bottomLeftCorner } = qrCode.location;
                        ctx.strokeStyle = qrData === qrCode.data ? '#00ff00' : '#ffffff';
                        ctx.lineWidth = 4;
                        ctx.beginPath();
                        ctx.moveTo(topLeftCorner.x, topLeftCorner.y);
                        ctx.lineTo(topRightCorner.x, topRightCorner.y);
                        ctx.lineTo(bottomRightCorner.x, bottomRightCorner.y);
                        ctx.lineTo(bottomLeftCorner.x, bottomLeftCorner.y);
                        ctx.closePath();
                        ctx.stroke();

                        if (qrCode.data && qrData !== qrCode.data) {
                            qrData = qrCode.data;
                            handlers.stopCamera();
                            handlers.handleDecrypt(qrCode.data);
                            return;
                        }
                    }
                } catch (error) {
                    console.error('Error scanning QR:', error);
                }

                qrScanAnimation = requestAnimationFrame(scanQR);
            };

            // Iniciar escaneo cuando el video esté listo
            video.addEventListener('loadedmetadata', () => {
                console.log('Video metadata loaded, starting QR scan');
                handlers.updateCanvasSize();
                window.addEventListener('resize', handlers.updateCanvasSize);
                qrScanAnimation = requestAnimationFrame(scanQR);
            });

            // Mostrar el modal
            if (domElements.cameraModal) {
                domElements.cameraModal.style.display = 'flex';
                domElements.cameraModal.classList.remove('hidden');
                domElements.cameraModal.focus();
                console.log('Camera modal displayed');
            } else {
                throw new Error('Camera modal element not found');
            }

            // Timeout para evitar uso prolongado
            setTimeout(() => {
                if (cameraStream) {
                    handlers.stopCamera();
                    uiController.displayMessage('Camera scan timed out.', false);
                }
            }, CONFIG.CAMERA_TIMEOUT);
        } catch (error) {
            console.error('Camera error:', error);
            uiController.displayMessage('Failed to access camera. Please check permissions.', false);
            handlers.stopCamera();
        }
    },

    toggleCamera: async () => {
        console.log('Toggling camera to:', currentFacingMode === 'environment' ? 'user' : 'environment');
        currentFacingMode = currentFacingMode === 'environment' ? 'user' : 'environment';
        await handlers.startCamera();
    },

    handleUploadArrow: () => fileInput.click(),
    handleImageUpload: () => {
        fileInput.accept = 'image/*';
        fileInput.click();
    },
    handlePDFUpload: () => {
        fileInput.accept = 'application/pdf';
        fileInput.click();
    },

    handleFileUpload: async () => {
        const file = fileInput.files[0];
        if (!file) return;

        if (file.type === 'application/pdf') {
            uiController.displayMessage('PDF processing is not yet implemented.', false);
            fileInput.value = '';
            return;
        }

        try {
            const imageData = await new Promise((resolve, reject) => {
                const reader = new FileReader();
                reader.onload = () => {
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
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0, width, height);
                        resolve(ctx.getImageData(0, 0, width, height));
                    };
                    img.onerror = reject;
                    img.src = reader.result;
                };
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });

            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
            if (!qrCode) throw new Error('No QR code detected in the image');

            qrData = qrCode.data;
            await handlers.handleDecrypt(qrCode.data);
        } catch (error) {
            uiController.displayMessage(error.message || 'Failed to process file.', false);
        } finally {
            fileInput.value = '';
        }
    }
};

// Inicialización y eventos
document.addEventListener('DOMContentLoaded', () => {
    // Generar contraseña
    document.querySelector('.generate-password').addEventListener('click', () => {
        const passphrase = generateSecurePassphrase(16);
        domElements.passphraseInput.value = passphrase;
        domElements.passphraseInput.dispatchEvent(new Event('input'));
        uiController.displayMessage(passphrase, true, true);
    });

    // Contador de caracteres
    const charCounter = document.getElementById('char-counter');
    domElements.messageInput.addEventListener('input', () => {
        const length = domElements.messageInput.value.length;
        const maxLength = parseInt(domElements.messageInput.getAttribute('maxlength'));
        charCounter.textContent = `${length}/${maxLength}`;
        charCounter.style.color = length >= maxLength * 0.9 ? 'var(--error-color)' : 'rgba(160, 160, 160, 0.8)';
    });

    // Validación de passphrase
    domElements.passphraseInput.addEventListener('input', (e) => {
        const passphrase = e.target.value;
        const keyIcon = e.target.parentElement.querySelector('.fa-key');
        if (!passphrase) {
            keyIcon.style.color = 'rgba(160, 160, 160, 0.6)';
            domElements.passphraseError.classList.remove('visible');
            return;
        }

        try {
            cryptoUtils.validatePassphrase(passphrase);
            keyIcon.style.color = 'var(--success-color)';
            domElements.passphraseError.classList.remove('visible');
        } catch (error) {
            keyIcon.style.color = 'var(--error-color)';
            uiController.showPassphraseError(error.message);
        }
    });

    // Eventos de botones
    domElements.uploadArrowButton.addEventListener('click', handlers.handleUploadArrow);
    domElements.scanButton.addEventListener('click', handlers.startCamera);
    domElements.imageButton.addEventListener('click', handlers.handleImageUpload);
    domElements.pdfButton.addEventListener('click', handlers.handlePDFUpload);
    domElements.sendButton.addEventListener('click', handlers.handleEncrypt);
    domElements.decodeButton.addEventListener('click', () => handlers.handleDecrypt(qrData));
    domElements.downloadButton.addEventListener('click', handlers.handleDownload);
    domElements.shareButton.addEventListener('click', handlers.handleShare);
    domElements.closeCameraModal.addEventListener('click', handlers.stopCamera);
    domElements.toggleCameraButton.addEventListener('click', handlers.toggleCamera);
    fileInput.addEventListener('change', handlers.handleFileUpload);

    // Habilitar/deshabilitar botón de descifrado
    fileInput.addEventListener('change', () => {
        domElements.decodeButton.disabled = !fileInput.files.length && !qrData;
    });
    domElements.passphraseInput.addEventListener('input', () => {
        domElements.decodeButton.disabled = !qrData;
    });

    // Modal de tutorial
    showTutorialModal();
    domElements.closeTutorial.addEventListener('click', closeTutorialModal);
    domElements.closeModalButton.addEventListener('click', closeTutorialModal);
    domElements.dontShowAgain.addEventListener('click', setDontShowAgain);

    // Inicialización
    domElements.qrContainer.classList.add('hidden');
    domElements.cameraModal.classList.add('hidden');
});

// Limpieza al salir
window.addEventListener('beforeunload', () => {
    handlers.stopCamera();
});
