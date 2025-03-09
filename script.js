const elements = {
    messagesDiv: document.getElementById('messages'),
    passphraseInput: document.getElementById('passphrase'),
    messageInput: document.getElementById('message-input'),
    encryptForm: document.getElementById('encrypt-form'),
    qrCanvas: document.getElementById('qr-canvas'),
    qrUpload: document.getElementById('qr-upload'),
    decodeButton: document.getElementById('decode-button'),
    downloadButton: document.getElementById('download-button'),
    qrContainer: document.getElementById('qr-container'),
    notification: document.getElementById('notification')
};

const cryptoUtils = {
    stringToArrayBuffer: str => new TextEncoder().encode(str),
    arrayBufferToString: buffer => new TextDecoder().decode(buffer),

    deriveKey: async (passphrase, salt) => {
        const keyMaterial = await crypto.subtle.importKey(
            'raw', cryptoUtils.stringToArrayBuffer(passphrase), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
    },

    encryptMessage: async (message, passphrase) => {
        const compressed = pako.deflate(cryptoUtils.stringToArrayBuffer(message));
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await cryptoUtils.deriveKey(passphrase, salt);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, compressed);
        const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
        return btoa(String.fromCharCode(...combined));
    },

    decryptMessage: async (encryptedBase64, passphrase) => {
        const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const ciphertext = encryptedData.slice(28);
        const key = await cryptoUtils.deriveKey(passphrase, salt);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
        return cryptoUtils.arrayBufferToString(pako.inflate(new Uint8Array(decrypted)));
    }
};

const ui = {
    showNotification: (message, type = 'success') => {
        elements.notification.textContent = message;
        elements.notification.className = `notification ${type}`;
        elements.notification.classList.remove('hidden');
        setTimeout(() => elements.notification.classList.add('hidden'), 3000);
    },

    displayMessage: (content, isSent = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        messageEl.innerHTML = `
            <div class="message-content">${content}</div>
            <div class="message-time">${new Date().toLocaleTimeString()}</div>
        `;
        elements.messagesDiv.querySelector('.message-placeholder')?.remove();
        elements.messagesDiv.appendChild(messageEl);
        elements.messagesDiv.scrollTop = elements.messagesDiv.scrollHeight;
    },

    generateQR: async (data) => {
        const size = Math.min(window.innerWidth * 0.4, 250);
        elements.qrCanvas.width = size;
        elements.qrCanvas.height = size;

        await new Promise((resolve, reject) => {
            QRCode.toCanvas(elements.qrCanvas, data, {
                width: size,
                margin: 2,
                color: { dark: '#000000', light: '#ffffff' }
            }, (error) => error ? reject(error) : resolve());
        });

        const ctx = elements.qrCanvas.getContext('2d');
        const center = size / 2;
        const radius = size * 0.15;

        ctx.beginPath();
        ctx.arc(center, center, radius, 0, Math.PI * 2);
        ctx.fillStyle = 'var(--primary-color)';
        ctx.fill();

        ctx.fillStyle = '#1a1a1a';
        ctx.font = 'bold 18px "Segoe UI", sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('HUSH', center, center - 10);
        ctx.fillText('BOX', center, center + 15);

        elements.qrContainer.classList.remove('hidden');
    },

    showLoader: (button) => {
        button.disabled = true;
        button.innerHTML = `<i class="fas fa-spinner fa-spin"></i> Processing...`;
    },

    resetButton: (button, text, icon) => {
        button.innerHTML = `<i class="fas fa-${icon}"></i> ${text}`;
        button.disabled = false;
    },

    resetForm: () => {
        elements.encryptForm.reset();
        elements.qrContainer.classList.add('hidden');
    }
};

const handlers = {
    handleEncrypt: async (e) => {
        e.preventDefault();
        const message = elements.messageInput.value.trim();
        const passphrase = elements.passphraseInput.value.trim();

        if (!message || passphrase.length < 8) {
            ui.showNotification('Passphrase must be at least 8 characters and message cannot be empty', 'error');
            return;
        }

        ui.showLoader(elements.encryptForm.querySelector('#send-button'));

        try {
            const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
            await ui.generateQR(encrypted);
            ui.displayMessage(`Encrypted: ${encrypted.slice(0, 40)}...`, true);
            ui.showNotification('Message encrypted successfully!');
            ui.resetForm();
        } catch (error) {
            ui.showNotification(`Encryption failed: ${error.message}`, 'error');
        }

        ui.resetButton(elements.encryptForm.querySelector('#send-button'), 'Encrypt & Generate QR', 'lock');
    },

    handleDecrypt: async () => {
        const file = elements.qrUpload.files[0];
        const passphrase = elements.passphraseInput.value.trim();

        if (!file || !passphrase) {
            ui.showNotification('Please upload a QR image and enter a passphrase', 'error');
            return;
        }

        ui.showLoader(elements.decodeButton);

        try {
            const imageData = await new Promise((resolve, reject) => {
                const img = new Image();
                img.onload = () => {
                    const canvas = document.createElement('canvas');
                    canvas.width = img.width;
                    canvas.height = img.height;
                    canvas.getContext('2d').drawImage(img, 0, 0);
                    resolve(canvas.getContext('2d').getImageData(0, 0, img.width, img.height));
                };
                img.onerror = reject;
                img.src = URL.createObjectURL(file);
            });

            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
            if (!qrCode) throw new Error('No QR code detected');

            const decrypted = await cryptoUtils.decryptMessage(qrCode.data, passphrase);
            ui.displayMessage(decrypted);
            ui.showNotification('Message decrypted successfully!');
            elements.qrUpload.value = '';
        } catch (error) {
            ui.showNotification(error.message.includes('decrypt') ? 'Wrong passphrase?' : error.message, 'error');
        }

        ui.resetButton(elements.decodeButton, 'Decrypt Message', 'unlock');
    },

    handleDownload: () => {
        const link = document.createElement('a');
        link.download = 'hushbox-qr.png';
        link.href = elements.qrCanvas.toDataURL('image/png', 1.0);
        link.click();
    }
};

elements.encryptForm.addEventListener('submit', handlers.handleEncrypt);
elements.decodeButton.addEventListener('click', handlers.handleDecrypt);
elements.downloadButton.addEventListener('click', handlers.handleDownload);
