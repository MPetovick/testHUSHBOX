// Configuración global para parámetros criptográficos
const CONFIG = {
    PBKDF2_ITERATIONS_DESKTOP: 250000,
    PBKDF2_ITERATIONS_MOBILE: 100000, // Reducido para móviles
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
    DECRYPT_COOLDOWN: 5 * 60 * 1000, // 5 minutos
    NOTICE_TIMEOUT: 10000 // 10 segundos para mensajes de tipo "notice"
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
    cameraContainer: document.getElementById('camera-container'),
    cameraPreview: document.getElementById('camera-preview'),
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
    closeModalButton: document.querySelector('.close-modal')
};

// Input oculto para la carga de imágenes y PDFs
const fileInput = document.createElement('input');
fileInput.type = 'file';
fileInput.accept = 'image/*,application/pdf';
fileInput.style.display = 'none';
document.body.appendChild(fileInput);

// Canvas oculto para procesar el video
const scanCanvas = document.createElement('canvas');
const scanContext = scanCanvas.getContext('2d');
scanCanvas.style.display = 'none';
document.body.appendChild(scanCanvas);

// Variables para protección contra fuerza bruta y cámara
let decryptAttempts = 0;
let cameraTimeoutId = null;
let cameraStream = null;
let qrScanInterval = null;

// Función para limpiar buffers sensibles
const clearBuffer = (buffer) => {
    if (buffer instanceof ArrayBuffer) {
        const zeros = new Uint8Array(buffer.byteLength);
        new Uint8Array(buffer).set(zeros);
    } else if (buffer instanceof Uint8Array || buffer instanceof Int32Array || buffer instanceof Float32Array) {
        buffer.fill(0);
    } else {
        console.warn("clearBuffer: El objeto no es un ArrayBuffer ni un TypedArray.");
    }
};

// Verificar si el usuario ha elegido no mostrar el modal
const shouldShowModal = () => localStorage.getItem('dontShowAgain') !== 'true';

// Mostrar el modal de tutorial
const showTutorialModal = () => {
    if (shouldShowModal()) {
        domElements.tutorialModal.style.display = 'flex';
        domElements.tutorialModal.focus();
    }
};

// Cerrar el modal
const closeTutorialModal = () => {
    domElements.tutorialModal.style.display = 'none';
};

// Guardar preferencia de no mostrar el modal
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
    const allChars = charSets.uppercase + charSets.lowercase + charSets.digits + charSets.symbols;
    const getRandomChar = (str) => str[crypto.getRandomValues(new Uint32Array(1))[0] % str.length];
    let passphraseArray = [
        getRandomChar(charSets.uppercase),
        getRandomChar(charSets.lowercase),
        getRandomChar(charSets.digits),
        getRandomChar(charSets.symbols)
    ];
    let fifthChar;
    do {
        fifthChar = getRandomChar(allChars);
    } while (passphraseArray.includes(fifthChar));
    passphraseArray.push(fifthChar);
    const remainingLength = length - passphraseArray.length;
    const randomValues = new Uint8Array(remainingLength);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < remainingLength; i++) {
        passphraseArray.push(allChars[randomValues[i] % allChars.length]);
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
};

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
        const uniqueChars = new Set(passphrase).size;
        if (uniqueChars < 5) {
            throw new Error('Passphrase should have at least 5 unique characters');
        }
        const commonPasswords = ['password', '123456', 'qwerty', 'admin'];
        if (commonPasswords.includes(passphrase.toLowerCase())) {
            throw new Error('Passphrase is too common. Please choose a stronger one.');
        }
        const dangerousChars = /[<>'"&\\/]/;
        if (dangerousChars.test(passphrase)) {
            throw new Error('Passphrase contains invalid characters.');
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
            { name: 'AES-GCM' },
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
            throw new Error('Encryption failed: ' + error.message);
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
            } catch (e) {
                decompressed = new Uint8Array(decrypted);
            }
            return cryptoUtils.arrayBufferToString(decompressed);
        } catch (error) {
            decryptAttempts++;
            await new Promise(resolve => setTimeout(resolve, decryptAttempts * CONFIG.DECRYPT_DELAY_INCREMENT));
            throw new Error('Decryption failed: ' + error.message);
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
        const messagesDiv = domElements.messagesDiv;
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        
        const isEncrypted = content.startsWith('Encrypted:');
        const isDecrypted = content.startsWith('Decrypted:');
        const messageType = isEncrypted ? 'encrypted' : isDecrypted ? 'decrypted' : 'notice';
        messageEl.dataset.messageType = messageType;

        if (isPassphrase) {
            messageEl.innerHTML = `
                <div class="message-content">
                    <span class="passphrase-text">${content}</span>
                    <i class="fas fa-copy copy-icon" title="Copy to clipboard" aria-label="Copy passphrase"></i>
                </div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
            const copyIcon = messageEl.querySelector('.copy-icon');
            copyIcon.addEventListener('click', async () => {
                try {
                    await navigator.clipboard.writeText(content);
                    uiController.displayMessage('Passphrase copied to clipboard!', false);
                    clearTimeout(messageEl.timeoutId);
                } catch (error) {
                    console.error('Failed to copy passphrase:', error);
                    uiController.displayMessage('Failed to copy passphrase.', false);
                }
            });
            if (messageType === 'notice') {
                messageEl.timeoutId = setTimeout(() => {
                    if (messageEl && messageEl.parentNode) {
                        messageEl.parentNode.removeChild(messageEl);
                    }
                }, CONFIG.NOTICE_TIMEOUT);
                messageEl.addEventListener('mouseenter', () => clearTimeout(messageEl.timeoutId));
                messageEl.addEventListener('mouseleave', () => {
                    messageEl.timeoutId = setTimeout(() => {
                        if (messageEl && messageEl.parentNode) {
                            messageEl.parentNode.removeChild(messageEl);
                        }
                    }, CONFIG.NOTICE_TIMEOUT);
                });
            }
        } else {
            messageEl.innerHTML = `
                <div class="message-content">${content}</div>
                <div class="message-time">${new Date().toLocaleTimeString()}</div>
            `;
            if (messageType === 'notice') {
                messageEl.timeoutId = setTimeout(() => {
                    if (messageEl && messageEl.parentNode) {
                        messageEl.parentNode.removeChild(messageEl);
                    }
                }, CONFIG.NOTICE_TIMEOUT);
                messageEl.addEventListener('mouseenter', () => clearTimeout(messageEl.timeoutId));
                messageEl.addEventListener('mouseleave', () => {
                    messageEl.timeoutId = setTimeout(() => {
                        if (messageEl && messageEl.parentNode) {
                            messageEl.parentNode.removeChild(messageEl);
                        }
                    }, CONFIG.NOTICE_TIMEOUT);
                });
            }
        }

        if (!isSent && messagesDiv.children.length === 0) {
            messagesDiv.querySelector('.message-placeholder')?.remove();
        }

        const maxMessages = 7;
        if (messagesDiv.children.length >= maxMessages) {
            messagesDiv.removeChild(messagesDiv.firstChild);
        }

        messagesDiv.appendChild(messageEl);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
        return messageEl;
    },

    showPassphraseError: (message) => {
        domElements.passphraseError.textContent = message;
        domElements.passphraseError.classList.add('visible');
        setTimeout(() => {
            domElements.passphraseError.classList.remove('visible');
        }, 3000);
    },

    generateQR: (data) => {
        return new Promise((resolve, reject) => {
            const dataLength = data.length;
            const qrSize = Math.min(CONFIG.MAX_QR_SIZE, Math.max(CONFIG.QR_SIZE, Math.ceil(dataLength / 20) * 10 + 150));
            domElements.qrCanvas.width = qrSize;
            domElements.qrCanvas.height = qrSize;

            const drawQR = () => {
                const tempCanvas = document.createElement('canvas');
                tempCanvas.width = qrSize;
                tempCanvas.height = qrSize;

                QRCode.toCanvas(tempCanvas, data, {
                    width: qrSize,
                    margin: 1,
                    color: { dark: '#000000', light: '#ffffff' },
                    errorCorrectionLevel: 'H'
                }, (error) => {
                    if (error) {
                        reject(error);
                        return;
                    }

                    const ctx = tempCanvas.getContext('2d');
                    const circleRadius = qrSize * 0.15;
                    const circleX = qrSize / 2;
                    const circleY = qrSize / 2;

                    ctx.beginPath();
                    ctx.arc(circleX, circleY, circleRadius, 0, Math.PI * 2);
                    ctx.fillStyle = 'var(--primary-color)';
                    ctx.fill();

                    ctx.fillStyle = '#00cc99';
                    ctx.font = `bold ${qrSize * 0.08}px "Segoe UI", system-ui, sans-serif`;
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
            };

            requestAnimationFrame(drawQR);
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
            console.error('Encryption error:', error);
            uiController.displayMessage(error.message || 'Encryption failed. Please try again.', false);
        } finally {
            uiController.resetButton(domElements.sendButton, originalHTML);
        }
    },

    handleDecrypt: async (qrData) => {
        const passphrase = domElements.passphraseInput.value.trim();

        if (!qrData || !passphrase) {
            uiController.displayMessage('Please provide a QR code and enter a passphrase', false);
            return;
        }

        const originalButtonHTML = domElements.decodeButton.innerHTML;
        uiController.showLoader(domElements.decodeButton, 'Decrypting...');

        try {
            const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
            uiController.displayMessage(`Decrypted: ${decrypted}`, false);
            domElements.passphraseInput.value = '';
            fileInput.value = '';
            decryptAttempts = 0;
        } catch (error) {
            console.error('Decryption error:', error);
            uiController.displayMessage(
                error.message.includes('decrypt') || error.message.includes('Integrity')
                    ? 'Decryption failed. Wrong passphrase or tampered data?'
                    : error.message,
                false
            );
        } finally {
            uiController.resetButton(domElements.decodeButton, originalButtonHTML);
        }
    },

    handleDownload: async () => {
        try {
            if (!domElements.qrCanvas.toDataURL) {
                uiController.displayMessage('No QR code available to download.', false);
                return;
            }

            const qrDataUrl = domElements.qrCanvas.toDataURL('image/png', 0.9);
            const qrBlob = await (await fetch(qrDataUrl)).blob();
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const fileName = `hushbox-qr-${timestamp}.png`;

            const link = document.createElement('a');
            link.href = URL.createObjectURL(qrBlob);
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);

            uiController.displayMessage('QR downloaded successfully!', false);
        } catch (error) {
            console.error('Download error:', error);
            uiController.displayMessage('Failed to download QR: ' + error.message, false);
        }
    },

    handleShare: async () => {
        try {
            if (!domElements.qrCanvas.toDataURL) {
                uiController.displayMessage('No QR code available to share.', false);
                return;
            }

            const qrDataUrl = domElements.qrCanvas.toDataURL('image/png', 0.9);
            const qrBlob = await (await fetch(qrDataUrl)).blob();
            const qrFile = new File([qrBlob], 'hushbox-qr.png', { type: 'image/png' });

            if (navigator.share && navigator.canShare({ files: [qrFile] })) {
                await navigator.share({
                    title: 'HushBox Secure QR',
                    text: 'Check out this encrypted QR code from HushBox!',
                    files: [qrFile]
                });
                uiController.displayMessage('QR shared successfully!', false);
            } else {
                await navigator.clipboard.writeText(qrDataUrl);
                uiController.displayMessage('QR code copied to clipboard!', false);
            }
        } catch (error) {
            console.error('Share error:', error);
            uiController.displayMessage('Failed to share QR. Copied to clipboard instead.', false);
            await navigator.clipboard.writeText(domElements.qrCanvas.toDataURL('image/png', 0.9));
        }
    },

    stopCamera: () => {
        if (cameraStream) {
            cameraStream.getTracks().forEach(track => track.stop());
            domElements.cameraPreview.srcObject = null;
            cameraStream = null;
        }
        if (qrScanInterval) {
            clearInterval(qrScanInterval);
            qrScanInterval = null;
        }
        if (cameraTimeoutId) {
            clearTimeout(cameraTimeoutId);
            cameraTimeoutId = null;
        }
        domElements.cameraContainer.classList.add('hidden');
    },

    startCamera: async () => {
        try {
            handlers.stopCamera(); // Detener cualquier cámara activa
            cameraStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'environment' }
            });
            domElements.cameraPreview.srcObject = cameraStream;
            domElements.cameraContainer.classList.remove('hidden');

            const scanQR = () => {
                if (!domElements.cameraPreview.videoWidth) return;
                scanCanvas.width = domElements.cameraPreview.videoWidth;
                scanCanvas.height = domElements.cameraPreview.videoHeight;
                scanContext.drawImage(domElements.cameraPreview, 0, 0, scanCanvas.width, scanCanvas.height);
                const imageData = scanContext.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
                const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
                if (qrCode) {
                    handlers.stopCamera();
                    handlers.handleDecrypt(qrCode.data);
                }
            };

            qrScanInterval = setInterval(() => {
                requestAnimationFrame(scanQR);
            }, 500);

            cameraTimeoutId = setTimeout(() => {
                handlers.stopCamera();
                uiController.displayMessage('Camera scan timed out.', false);
            }, CONFIG.CAMERA_TIMEOUT);
        } catch (error) {
            console.error('Camera error:', error);
            uiController.displayMessage('Failed to access camera. Please check permissions.', false);
            handlers.stopCamera();
        }
    },

    handleUploadArrow: () => {
        fileInput.accept = 'image/*,application/pdf';
        fileInput.click();
    },

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
                reader.onload = e => {
                    const img = new Image();
                    img.onload = () => {
                        const canvas = document.createElement('canvas');
                        const MAX_SIZE = 800;
                        let width = img.width;
                        let height = img.height;
                        if (width > height) {
                            if (width > MAX_SIZE) {
                                height *= MAX_SIZE / width;
                                width = MAX_SIZE;
                            }
                        } else {
                            if (height > MAX_SIZE) {
                                width *= MAX_SIZE / height;
                                height = MAX_SIZE;
                            }
                        }
                        canvas.width = width;
                        canvas.height = height;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(img, 0, 0, width, height);
                        resolve(ctx.getImageData(0, 0, width, height));
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

            await handlers.handleDecrypt(qrCode.data);
        } catch (error) {
            console.error('File upload error:', error);
            uiController.displayMessage(error.message || 'Failed to process file.', false);
        } finally {
            fileInput.value = '';
        }
    }
};

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Generar contraseña
    document.querySelector('.generate-password').addEventListener('click', () => {
        const securePassphrase = generateSecurePassphrase(16);
        domElements.passphraseInput.value = securePassphrase;
        domElements.passphraseInput.dispatchEvent(new Event('input'));
        uiController.displayMessage(securePassphrase, true, true);
    });

    // Contador de caracteres
    const charCounter = document.getElementById('char-counter');
    domElements.messageInput.addEventListener('input', () => {
        const currentLength = domElements.messageInput.value.length;
        const maxLength = domElements.messageInput.getAttribute('maxlength');
        charCounter.textContent = `${currentLength}/${maxLength}`;
        charCounter.style.color = currentLength >= maxLength * 0.9 ? 'var(--error-color)' : 'rgba(160, 160, 160, 0.8)';
    });

    // Validación visual de la passphrase
    domElements.passphraseInput.addEventListener('input', (e) => {
        const passphrase = e.target.value;
        const keyIcon = domElements.passphraseInput.parentElement.querySelector('.fa-key');
        if (passphrase.length === 0) {
            keyIcon.style.color = 'rgba(160, 160, 160, 0.6)';
            domElements.passphraseError.classList.remove('visible');
        } else if (passphrase.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
            keyIcon.style.color = 'var(--error-color)';
            uiController.showPassphraseError(`Passphrase must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters long`);
        } else {
            try {
                cryptoUtils.validatePassphrase(passphrase);
                keyIcon.style.color = 'var(--success-color)';
                domElements.passphraseError.classList.remove('visible');
            } catch (error) {
                keyIcon.style.color = 'var(--error-color)';
                uiController.showPassphraseError(error.message);
            }
        }
    });

    // Eventos de botones
    domElements.uploadArrowButton.addEventListener('click', handlers.handleUploadArrow);
    domElements.scanButton.addEventListener('click', handlers.startCamera);
    domElements.imageButton.addEventListener('click', handlers.handleImageUpload);
    domElements.pdfButton.addEventListener('click', handlers.handlePDFUpload);
    domElements.sendButton.addEventListener('click', handlers.handleEncrypt);
    domElements.decodeButton.addEventListener('click', () => handlers.handleDecrypt(fileInput.qrData));
    domElements.downloadButton.addEventListener('click', handlers.handleDownload);
    domElements.shareButton.addEventListener('click', handlers.handleShare);
    fileInput.addEventListener('change', handlers.handleFileUpload);

    // Habilitar decodeButton cuando se carga un archivo o se escanea un QR
    fileInput.addEventListener('change', () => {
        domElements.decodeButton.disabled = fileInput.files.length === 0;
    });

    // Eventos del modal
    showTutorialModal();
    domElements.closeTutorial.addEventListener('click', closeTutorialModal);
    domElements.closeModalButton.addEventListener('click', closeTutorialModal);
    domElements.dontShowAgain.addEventListener('click', setDontShowAgain);
});

// Detener la cámara al salir de la página
window.addEventListener('beforeunload', (e) => {
    if (cameraStream) {
        e.preventDefault();
        e.returnValue = 'Camera is active. Are you sure you want to leave?';
        handlers.stopCamera();
    }
});

// Inicialización
domElements.qrContainer.classList.add('hidden');
domElements.cameraContainer.classList.add('hidden');
