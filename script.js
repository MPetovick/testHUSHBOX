// Detectar si estamos en Telegram Mini App
const isTelegram = !!window.Telegram?.WebApp?.initData;
if (isTelegram) {
    window.Telegram.WebApp.ready(); // Inicializar la Mini App
    window.Telegram.WebApp.expand(); // Expandir la ventana
    document.getElementById('telegram-notice').style.display = 'block';
}

// Elementos del DOM
const elements = {
    messagesDiv: document.getElementById('messages'),
    passphraseInput: document.getElementById('passphrase'),
    messageInput: document.getElementById('message-input'),
    sendButton: document.getElementById('send-button'),
    qrCanvas: document.getElementById('qr-canvas'),
    qrUpload: document.getElementById('qr-upload'),
    decodeButton: document.getElementById('decode-button'),
    downloadButton: document.getElementById('download-button'),
    qrContainer: document.getElementById('qr-container'),
    shareButton: document.getElementById('share-button'),
    cameraButton: document.getElementById('camera-button'),
    qrModal: document.getElementById('qr-modal'),
    qrModalCanvas: document.getElementById('qr-modal-canvas'),
    closeModal: document.querySelector('.close-modal'),
    cameraPreview: document.getElementById('camera-preview'),
    cameraPreviewContainer: document.getElementById('camera-preview-container'),
    passphraseModal: document.getElementById('passphrase-modal'),
    modalPassphrase: document.getElementById('modal-passphrase'),
    modalDecryptButton: document.getElementById('modal-decrypt-button'),
    closePassphraseModal: document.querySelector('.close-passphrase-modal')
};

// Utilidades criptográficas
const cryptoUtils = {
    stringToArrayBuffer: str => new TextEncoder().encode(str),
    arrayBufferToString: buffer => new TextDecoder().decode(buffer),
    deriveKey: async (passphrase, salt) => {
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            cryptoUtils.stringToArrayBuffer(passphrase),
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 250000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    },
    encryptMessage: async (message, passphrase) => {
        try {
            const compressed = message.length > 100 ? pako.deflate(cryptoUtils.stringToArrayBuffer(message)) : null;
            const salt = crypto.getRandomValues(new Uint8Array(16));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await cryptoUtils.deriveKey(passphrase, salt);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv },
                key,
                compressed || cryptoUtils.stringToArrayBuffer(message)
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
            const salt = encryptedData.slice(0, 16);
            const iv = encryptedData.slice(16, 28);
            const ciphertext = encryptedData.slice(28);
            const key = await cryptoUtils.deriveKey(passphrase, salt);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv },
                key,
                ciphertext
            );
            return cryptoUtils.arrayBufferToString(
                ciphertext.length > 100 ? pako.inflate(new Uint8Array(decrypted)) : new Uint8Array(decrypted)
            );
        } catch (error) {
            throw new Error('Decryption failed: ' + error.message);
        }
    }
};

// Funciones de interfaz de usuario
const ui = {
    displayMessage: (content, isEncrypted = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isEncrypted ? 'encrypted' : 'decrypted'}`;
        const messageType = isEncrypted ? 'Encrypted' : 'Decrypted';
        const timestamp = new Date().toLocaleTimeString();
        messageEl.innerHTML = `
            <div class="message-content">
                <strong>${messageType} (${timestamp}):</strong> ${content}
            </div>
        `;
        if (!isEncrypted) {
            elements.messagesDiv.querySelector('.message-placeholder')?.remove();
        }
        elements.messagesDiv.appendChild(messageEl);
        elements.messagesDiv.scrollTop = elements.messagesDiv.scrollHeight;
    },
    generateQR: async (data) => {
        return new Promise((resolve, reject) => {
            const size = Math.min(500, Math.max(150, data.length * 2));
            QRCode.toCanvas(elements.qrCanvas, data, {
                width: size,
                margin: 2,
                color: { dark: '#000000', light: '#ffffff' }
            }, (error) => {
                if (error) reject(error);
                else {
                    const ctx = elements.qrCanvas.getContext('2d');
                    const circleRadius = size * 0.16;
                    const circleX = size / 2;
                    const circleY = size / 2;
                    ctx.beginPath();
                    ctx.arc(circleX, circleY, circleRadius, 0, Math.PI * 2);
                    ctx.fillStyle = 'var(--primary-color)';
                    ctx.fill();
                    ctx.fillStyle = '#00cc99';
                    ctx.font = `bold ${size * 0.07}px "Segoe UI", system-ui, sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('HUSH', circleX, circleY - (size * 0.03));
                    ctx.fillText('BOX', circleX, circleY + (size * 0.06));
                    elements.qrContainer.classList.remove('hidden');
                    resolve();
                }
            });
        });
    },
    showQRModal: () => {
        const ctx = elements.qrModalCanvas.getContext('2d');
        elements.qrModalCanvas.width = elements.qrCanvas.width;
        elements.qrModalCanvas.height = elements.qrCanvas.height;
        ctx.drawImage(elements.qrCanvas, 0, 0);
        elements.qrModal.classList.remove('hidden');
    },
    showPassphraseModal: (qrData) => {
        elements.passphraseModal.classList.remove('hidden');
        elements.modalPassphrase.value = '';
        elements.passphraseModal.dataset.qrData = qrData;
    },
    showLoader: (button, text = 'Processing...') => {
        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${text}`;
        button.disabled = true;
    },
    resetButton: (button, originalHTML) => {
        button.innerHTML = originalHTML;
        button.disabled = false;
    },
    showError: (message) => {
        const errorEl = document.createElement('div');
        errorEl.className = 'error-message';
        errorEl.textContent = message;
        elements.messagesDiv.appendChild(errorEl);
        setTimeout(() => errorEl.remove(), 5000);
        if (isTelegram) {
            window.Telegram.WebApp.showAlert(message); // Mostrar alerta en Telegram
        }
    }
};

// Manejadores de eventos
const handlers = {
    handleEncrypt: async () => {
        const message = elements.messageInput.value.trim();
        const passphrase = elements.passphraseInput.value.trim();
        if (!message || !passphrase) {
            ui.showError('Please enter both a message and passphrase');
            return;
        }
        if (passphrase.length < 8) {
            ui.showError('Passphrase must be at least 8 characters long');
            return;
        }
        ui.showLoader(elements.sendButton, 'Encrypting...');
        try {
            const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
            await ui.generateQR(encrypted);
            ui.displayMessage(`${encrypted.slice(0, 40)}...`, true);
            elements.messageInput.value = '';
        } catch (error) {
            console.error('Encryption error:', error);
            ui.showError(error.message);
        }
        ui.resetButton(elements.sendButton, `<i class="fas fa-lock"></i> Encrypt & Generate QR`);
    },
    handleDecrypt: async () => {
        const file = elements.qrUpload.files[0];
        const passphrase = elements.passphraseInput.value.trim();
        if (!file || !passphrase) {
            ui.showError('Please select a QR file and enter passphrase');
            return;
        }
        ui.showLoader(elements.decodeButton, 'Decrypting...');
        try {
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
                        resolve(ctx.getImageData(0, 0, canvas.width, canvas.height));
                    };
                    img.onerror = reject;
                    img.src = e.target.result;
                };
                reader.onerror = reject;
                reader.readAsDataURL(file);
            });
            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
            if (!qrCode) throw new Error('No QR code detected in the image');
            const decrypted = await cryptoUtils.decryptMessage(qrCode.data, passphrase);
            ui.displayMessage(decrypted, false);
        } catch (error) {
            console.error('Decryption error:', error);
            ui.showError(error.message.includes('decrypt') ? 'Decryption failed. Wrong passphrase?' : error.message);
        }
        ui.resetButton(elements.decodeButton, `<i class="fas fa-unlock"></i> Decrypt Message`);
    },
    handleDownload: () => {
        if (isTelegram) {
            // Enviar el QR al chat del bot para descarga
            elements.qrCanvas.toBlob((blob) => {
                const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });
                const formData = new FormData();
                formData.append('chat_id', window.Telegram.WebApp.initDataUnsafe.user?.id || 'YOUR_CHAT_ID');
                formData.append('photo', file);
                fetch(`https://api.telegram.org/botYOUR_BOT_TOKEN/sendPhoto`, { // Reemplaza YOUR_BOT_TOKEN
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.ok) {
                        window.Telegram.WebApp.showAlert('QR sent to chat! You can download it there.');
                    } else {
                        throw new Error(data.description);
                    }
                })
                .catch(err => ui.showError('Failed to send QR: ' + err.message));
            }, 'image/png');
        } else {
            const link = document.createElement('a');
            link.download = 'hushbox-qr.png';
            link.href = elements.qrCanvas.toDataURL('image/png', 1.0);
            link.click();
        }
    },
    handleShare: () => {
        if (isTelegram) {
            // Enviar el QR al chat del bot para compartir
            elements.qrCanvas.toBlob((blob) => {
                const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });
                const formData = new FormData();
                formData.append('chat_id', window.Telegram.WebApp.initDataUnsafe.user?.id || 'YOUR_CHAT_ID');
                formData.append('photo', file);
                fetch(`https://api.telegram.org/botYOUR_BOT_TOKEN/sendPhoto`, { // Reemplaza YOUR_BOT_TOKEN
                    method: 'POST',
                    body: formData
                })
                .then(response => response.json())
                .then(data => {
                    if (data.ok) {
                        window.Telegram.WebApp.showAlert('QR sent to chat! You can share it from there.');
                    } else {
                        throw new Error(data.description);
                    }
                })
                .catch(err => ui.showError('Failed to share QR: ' + err.message));
            }, 'image/png');
        } else {
            const canvas = elements.qrCanvas;
            canvas.toBlob((blob) => {
                const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });
                const shareData = {
                    files: [file],
                    title: 'HushBox QR',
                    text: 'Scan this QR code to decrypt the message.',
                };
                if (navigator.canShare && navigator.canShare(shareData)) {
                    navigator.share(shareData).catch(console.error);
                } else {
                    alert('Sharing not supported.');
                }
            }, 'image/png');
        }
    },
    handleCamera: async () => {
        const isCameraActive = !elements.cameraPreviewContainer.classList.contains('hidden');
        if (isCameraActive) {
            if (elements.cameraPreview.srcObject) {
                elements.cameraPreview.srcObject.getTracks().forEach(track => track.stop());
                elements.cameraPreview.srcObject = null;
            }
            elements.cameraPreviewContainer.classList.add('hidden');
            elements.cameraButton.querySelector('i').classList.replace('fa-times', 'fa-camera');
        } else {
            try {
                const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
                elements.cameraPreview.srcObject = stream;
                elements.cameraPreview.play();
                elements.cameraPreviewContainer.classList.remove('hidden');
                elements.cameraButton.querySelector('i').classList.replace('fa-camera', 'fa-times');

                let lastScanTime = 0;
                const scanInterval = 200;

                const scanQR = (timestamp) => {
                    if (!elements.cameraPreview.srcObject) return;
                    if (timestamp - lastScanTime < scanInterval) {
                        requestAnimationFrame(scanQR);
                        return;
                    }
                    lastScanTime = timestamp;

                    const canvas = document.createElement('canvas');
                    const ctx = canvas.getContext('2d');
                    canvas.width = elements.cameraPreview.videoWidth;
                    canvas.height = elements.cameraPreview.videoHeight;
                    ctx.drawImage(elements.cameraPreview, 0, 0, canvas.width, canvas.height);
                    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                    const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

                    if (qrCode) {
                        elements.cameraPreview.srcObject.getTracks().forEach(track => track.stop());
                        elements.cameraPreview.srcObject = null;
                        elements.cameraPreviewContainer.classList.add('hidden');
                        elements.cameraButton.querySelector('i').classList.replace('fa-times', 'fa-camera');
                        ui.showPassphraseModal(qrCode.data);
                    } else {
                        requestAnimationFrame(scanQR);
                    }
                };
                requestAnimationFrame(scanQR);
            } catch (error) {
                console.error('Error accessing camera:', error);
                ui.showError('Camera access denied or not supported.');
            }
        }
    },
    handleDecryptQR: async () => {
        const passphrase = elements.modalPassphrase.value.trim();
        const qrData = elements.passphraseModal.dataset.qrData;
        if (!passphrase) {
            ui.showError('Please enter the passphrase');
            return;
        }
        if (passphrase.length < 8) {
            ui.showError('Passphrase must be at least 8 characters long');
            return;
        }
        ui.showLoader(elements.modalDecryptButton, 'Decrypting...');
        try {
            const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
            ui.displayMessage(decrypted, false);
            elements.passphraseModal.classList.add('hidden');
        } catch (error) {
            console.error('Decryption error:', error);
            ui.showError(error.message.includes('decrypt') ? 'Decryption failed. Wrong passphrase?' : error.message);
        }
        ui.resetButton(elements.modalDecryptButton, `<i class="fas fa-unlock"></i> Decrypt`);
    }
};

// Event listeners
elements.sendButton.addEventListener('click', (e) => {
    e.preventDefault(); // Prevenir envío del formulario
    handlers.handleEncrypt();
});
elements.decodeButton.addEventListener('click', handlers.handleDecrypt);
elements.downloadButton.addEventListener('click', handlers.handleDownload);
elements.shareButton.addEventListener('click', handlers.handleShare);
elements.cameraButton.addEventListener('click', handlers.handleCamera);
elements.qrCanvas.addEventListener('click', ui.showQRModal);
elements.closeModal.addEventListener('click', () => {
    elements.qrModal.classList.add('hidden');
});
elements.closePassphraseModal.addEventListener('click', () => {
    elements.passphraseModal.classList.add('hidden');
});

// Personalizamos el evento show para el modal
ui.showPassphraseModal = (qrData) => {
    elements.passphraseModal.classList.remove('hidden');
    elements.modalPassphrase.value = '';
    elements.passphraseModal.dataset.qrData = qrData;
    elements.modalDecryptButton.onclick = () => handlers.handleDecryptQR();
};

// Inicializar contenedores como ocultos
elements.qrContainer.classList.add('hidden');
elements.cameraPreviewContainer.classList.add('hidden');
elements.passphraseModal.classList.add('hidden');
