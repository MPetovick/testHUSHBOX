// Configuración global
const CONFIG = {
    PBKDF2_ITERATIONS: 310000,
    SALT_LENGTH: 32,
    IV_LENGTH: 16,
    AES_KEY_LENGTH: 256,
    QR_SIZE: 220,
    MIN_PASSPHRASE_LENGTH: 12,
    MAX_MESSAGE_LENGTH: 4000,
    CAMERA_TIMEOUT: 30000,
    DECRYPT_DELAY_INCREMENT: 100,
    MAX_DECRYPT_ATTEMPTS: 5,
    NOTICE_TIMEOUT: 8000,
    SESSION_TIMEOUT: 1800000, // 30 minutos
    COMPRESSION_THRESHOLD: 100
};

// Elementos del DOM
const dom = {
    encryptForm: document.getElementById('encrypt-form') || throwError('Encrypt form not found'),
    uploadArrow: document.getElementById('upload-arrow-button') || throwError('Upload arrow button not found'),
    scanButton: document.getElementById('scan-button') || throwError('Scan button not found'),
    imageButton: document.getElementById('image-button') || throwError('Image button not found'),
    pdfButton: document.getElementById('pdf-button') || throwError('PDF button not found'),
    messages: document.getElementById('messages') || throwError('Messages container not found'),
    passphrase: document.getElementById('passphrase') || throwError('Passphrase input not found'),
    messageInput: document.getElementById('message-input') || throwError('Message input not found'),
    sendButton: document.getElementById('send-button') || throwError('Send button not found'),
    qrCanvas: document.getElementById('qr-canvas') || throwError('QR canvas not found'),
    decodeButton: document.getElementById('decode-button') || throwError('Decode button not found'),
    downloadButton: document.getElementById('download-button') || throwError('Download button not found'),
    shareButton: document.getElementById('share-button') || throwError('Share button not found'),
    copyButton: document.getElementById('copy-button') || throwError('Copy button not found'),
    qrContainer: document.getElementById('qr-container') || throwError('QR container not found'),
    comingSoon: document.getElementById('coming-soon-message') || throwError('Coming soon message not found'),
    cameraModal: document.getElementById('camera-modal') || throwError('Camera modal not found'),
    cameraPreview: document.getElementById('camera-preview') || throwError('Camera preview not found'),
    closeCamera: document.getElementById('close-camera') || throwError('Close camera button not found'),
    fileInput: document.createElement('input'),
    charCounter: document.getElementById('char-counter') || throwError('Char counter not found'),
    generatePass: document.querySelector('.generate-password') || throwError('Generate password button not found'),
    togglePassword: document.querySelector('.toggle-password') || throwError('Toggle password button not found'),
    passwordStrengthBar: document.getElementById('password-strength-bar') || throwError('Password strength bar not found'),
    clearHistory: document.getElementById('clear-history') || throwError('Clear history button not found'),
    exportHistory: document.getElementById('export-history') || throwError('Export history button not found'),
    toastContainer: document.getElementById('toast-container') || throwError('Toast container not found'),
    passphraseError: document.getElementById('passphrase-error') || throwError('Passphrase error not found'),
    tutorialModal: document.getElementById('tutorial-modal') || throwError('Tutorial modal not found'),
    closeTutorial: document.getElementById('close-tutorial') || throwError('Close tutorial button not found'),
    dontShowAgainCheckbox: document.getElementById('dont-show-again-checkbox') || throwError('Don\'t show again checkbox not found'),
    dontShowAgainButton: document.getElementById('dont-show-again') || throwError('Don\'t show again button not found')
};

// Función auxiliar para errores de DOM
function throwError(message) {
    throw new Error(`DOM Error: ${message}`);
}

// Inicialización del input de archivo
dom.fileInput.type = 'file';
dom.fileInput.accept = 'image/*';
dom.fileInput.style.display = 'none';
document.body.appendChild(dom.fileInput);

// Estado de la aplicación
const appState = {
    isEncrypting: false,
    isDecrypting: false,
    sessionActive: true,
    messageHistory: [],
    passwordVisible: false,
    lastEncryptedData: null,
    sessionTimer: null
};

// Utilidades criptográficas
const cryptoUtils = {
    validatePassphrase: (pass) => {
        if (pass.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
            throw new Error(`La contraseña debe tener al menos ${CONFIG.MIN_PASSPHRASE_LENGTH} caracteres`);
        }
        const hasUpperCase = /[A-Z]/.test(pass);
        const hasLowerCase = /[a-z]/.test(pass);
        const hasNumbers = /[0-9]/.test(pass);
        const hasSymbols = /[^A-Za-z0-9]/.test(pass);
        const uniqueChars = new Set(pass).size;

        if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSymbols) {
            throw new Error('La contraseña debe incluir mayúsculas, minúsculas, números y símbolos');
        }
        if (uniqueChars < CONFIG.MIN_PASSPHRASE_LENGTH * 0.7) {
            throw new Error('La contraseña tiene demasiados caracteres repetidos');
        }
        if (typeof zxcvbn !== 'undefined' && zxcvbn(pass).score < 3) {
            throw new Error('La contraseña es demasiado débil');
        }
        return true;
    },

    calculatePasswordStrength: (pass) => {
        if (!pass) return 0;
        let strength = 0;
        strength += Math.min(pass.length * 4, 40);
        if (/[A-Z]/.test(pass)) strength += 10;
        if (/[a-z]/.test(pass)) strength += 10;
        if (/[0-9]/.test(pass)) strength += 10;
        if (/[^A-Za-z0-9]/.test(pass)) strength += 15;
        if (/(.)\1{2,}/.test(pass)) strength -= 15;
        if (pass.length < 8) strength -= 30;
        return Math.max(0, Math.min(999, strength));
    },

    generateSecurePass: (length = 16) => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
        const values = new Uint32Array(length);
        crypto.getRandomValues(values);
        let pass = Array.from(values, v => chars[v % chars.length]).join('');
        if (!/[A-Z]/.test(pass)) pass = 'A' + pass.slice(1);
        if (!/[a-z]/.test(pass)) pass = pass.slice(0, -1) + 'a';
        if (!/[0-9]/.test(pass)) pass = pass.slice(0, -1) + '1';
        if (!/[^A-Za-z0-9]/.test(pass)) pass = pass.slice(0, -1) + '!';
        try {
            cryptoUtils.validatePassphrase(pass);
            return pass;
        } catch (error) {
            return cryptoUtils.generateSecurePass(length);
        }
    },

    constantTimeCompare: (a, b) => {
        const aBytes = new TextEncoder().encode(a);
        const bBytes = new TextEncoder().encode(b);
        if (aBytes.length !== bBytes.length) return false;
        let result = 0;
        for (let i = 0; i < aBytes.length; i++) {
            result |= aBytes[i] ^ bBytes[i];
        }
        return result === 0;
    },

    secureWipe: (buffer) => {
        if (buffer instanceof ArrayBuffer || buffer instanceof Uint8Array) {
            const wipeArray = new Uint8Array(buffer);
            for (let i = 0; i < wipeArray.length; i++) {
                wipeArray[i] = 0;
            }
        }
    },

    encryptMessage: async (message, passphrase) => {
        let dataToEncrypt = null;
        try {
            cryptoUtils.validatePassphrase(passphrase);
            dataToEncrypt = new TextEncoder().encode(message);

            // Comprimir si el mensaje supera el umbral
            if (message.length > CONFIG.COMPRESSION_THRESHOLD) {
                dataToEncrypt = pako.deflate(dataToEncrypt, { level: 6 });
            }

            const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
            const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));

            const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 
                { name: 'PBKDF2' }, false, ['deriveBits']);
                
            const keyMaterial = await crypto.subtle.deriveBits({
                name: 'PBKDF2',
                salt,
                iterations: CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            }, baseKey, CONFIG.AES_KEY_LENGTH);
            
            const key = await crypto.subtle.importKey('raw', keyMaterial, 
                { name: 'AES-GCM' }, false, ['encrypt']);
            
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv, tagLength: 128 }, key, dataToEncrypt
            );
            
            const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
            const result = btoa(String.fromCharCode(...combined));

            cryptoUtils.secureWipe(keyMaterial);
            cryptoUtils.secureWipe(dataToEncrypt);
            return result;
        } catch (error) {
            console.error(error);
            throw new Error('Encriptación fallida: ' + error.message);
        } finally {
            if (dataToEncrypt) cryptoUtils.secureWipe(dataToEncrypt);
        }
    },

    decryptMessage: async (encryptedBase64, passphrase) => {
        let decrypted = null;
        try {
            const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
            if (encryptedData.length < CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH + 16) {
                throw new Error('Datos encriptados inválidos');
            }
            
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
            }, baseKey, CONFIG.AES_KEY_LENGTH);
            
            const key = await crypto.subtle.importKey('raw', keyMaterial, 
                { name: 'AES-GCM' }, false, ['decrypt']);
            
            decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv, tagLength: 128 }, key, ciphertext
            );
            
            let decompressed;
            try {
                decompressed = pako.inflate(new Uint8Array(decrypted));
            } catch (e) {
                decompressed = new Uint8Array(decrypted);
            }
            const result = new TextDecoder().decode(decompressed);
            
            cryptoUtils.secureWipe(keyMaterial);
            cryptoUtils.secureWipe(ciphertext);
            cryptoUtils.secureWipe(decrypted);
            return result;
        } catch (error) {
            console.error(error);
            throw new Error('Desencriptación fallida: ' + error.message);
        } finally {
            if (decrypted) cryptoUtils.secureWipe(decrypted);
        }
    }
};

// Controlador de UI
const ui = {
    sanitizeHTML: (str) => {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    displayMessage: (content, isSent = false) => {
        const messageEl = document.createElement('div');
        messageEl.className = `message ${isSent ? 'sent' : ''}`;
        messageEl.innerHTML = `
            <div class="message-content" role="alert" aria-live="polite">${ui.sanitizeHTML(content)}</div>
            <div class="message-time">${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</div>
        `;
        
        appState.messageHistory.push({
            content,
            isSent,
            timestamp: new Date()
        });
        
        if (dom.messages.children.length === 0) {
            dom.messages.querySelector('.message-placeholder')?.remove();
        }
        
        if (dom.messages.children.length >= 15) {
            dom.messages.removeChild(dom.messages.firstChild);
        }
        
        dom.messages.appendChild(messageEl);
        dom.messages.scrollTop = dom.messages.scrollHeight;

        dom.exportHistory.disabled = appState.messageHistory.length <= 1;
    },

    generateQR: async (data) => {
        return new Promise((resolve, reject) => {
            const qrSize = CONFIG.QR_SIZE;
            dom.qrCanvas.width = qrSize;
            dom.qrCanvas.height = qrSize;

            const tempCanvas = document.createElement('canvas');
            tempCanvas.width = qrSize;
            tempCanvas.height = qrSize;

            QRCode.toCanvas(tempCanvas, data, {
                width: qrSize,
                margin: 2,
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
                ctx.fillStyle = '#ffffff';
                ctx.fill();

                ctx.fillStyle = '#00cc99';
                ctx.font = `bold ${qrSize * 0.08}px "Segoe UI", system-ui, sans-serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('HUSH', circleX, circleY - circleRadius * 0.2);
                ctx.fillText('BOX', circleX, circleY + circleRadius * 0.3);

                const qrCtx = dom.qrCanvas.getContext('2d');
                qrCtx.clearRect(0, 0, qrSize, qrSize);
                qrCtx.drawImage(tempCanvas, 0, 0, qrSize, qrSize);

                dom.qrContainer.classList.remove('hidden');
                dom.qrContainer.classList.add('no-print');
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
        if (overlay) {
            overlay.classList.add('scan-success');
            setTimeout(() => overlay.classList.remove('scan-success'), 1000);
        }
    },

    showToast: (message, type = 'info') => {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        
        let icon = 'fas fa-info-circle';
        if (type === 'success') icon = 'fas fa-check-circle';
        if (type === 'error') icon = 'fas fa-exclamation-circle';
        if (type === 'warning') icon = 'fas fa-exclamation-triangle';
        
        toast.innerHTML = `
            <i class="${icon}"></i>
            <span>${ui.sanitizeHTML(message)}</span>
        `;
        
        dom.toastContainer.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                toast.remove();
            }, 300);
        }, CONFIG.NOTICE_TIMEOUT);
    },

    updatePasswordStrength: (pass) => {
        const strength = cryptoUtils.calculatePasswordStrength(pass);
        dom.passwordStrengthBar.style.width = `${strength}%`;
        
        if (strength < 40) {
            dom.passwordStrengthBar.style.background = 'var(--error-color)';
        } else if (strength < 70) {
            dom.passwordStrengthBar.style.background = 'var(--warning-color)';
        } else {
            dom.passwordStrengthBar.style.background = 'var(--success-color)';
        }
    },

    clearMessageHistory: () => {
        if (confirm('¿Estás seguro de que quieres borrar el historial de mensajes?')) {
            dom.messages.innerHTML = `
                <div class="message-placeholder">
                    <i class="fas fa-comments" aria-hidden="true"></i>
                    <p>Historial de mensajes borrado</p>
                </div>
            `;
            appState.messageHistory = [];
            dom.exportHistory.disabled = true;
            ui.showToast('Historial de mensajes borrado', 'success');
        }
    },

    togglePasswordVisibility: () => {
        appState.passwordVisible = !appState.passwordVisible;
        dom.passphrase.type = appState.passwordVisible ? 'text' : 'password';
        dom.togglePassword.children[0].classList.toggle('fa-eye', !appState.passwordVisible);
        dom.togglePassword.children[0].classList.toggle('fa-eye-slash', appState.passwordVisible);
    },

    showError: (message) => {
        dom.passphraseError.textContent = ui.sanitizeHTML(message);
        dom.passphraseError.classList.remove('hidden');
        setTimeout(() => {
            dom.passphraseError.classList.add('hidden');
        }, CONFIG.NOTICE_TIMEOUT);
    }
};

// Manejadores de eventos
const handlers = {
    decryptAttempts: 0,

    handleEncrypt: async (e) => {
        e.preventDefault();
        if (appState.isEncrypting) return;
        
        const message = dom.messageInput.value.trim();
        const passphrase = dom.passphrase.value.trim();
        
        if (!message || !passphrase) {
            ui.displayMessage('Por favor, ingrese un mensaje y una contraseña');
            ui.showToast('Falta el mensaje o la contraseña', 'error');
            return;
        }
        
        appState.isEncrypting = true;
        ui.toggleButton(dom.sendButton, true, '<span class="loader"></span> Encriptando...');
        
        try {
            const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
            appState.lastEncryptedData = encrypted;
            await ui.generateQR(encrypted);
            ui.displayMessage(`Mensaje encriptado: ${ui.sanitizeHTML(encrypted.slice(0, 40))}...`, true);
            ui.showToast('Mensaje encriptado exitosamente', 'success');
            
            dom.messageInput.value = '';
            dom.passphrase.value = '';
            ui.updatePasswordStrength('');
            dom.decodeButton.disabled = false;
        } catch (error) {
            ui.displayMessage(error.message);
            ui.showToast(error.message, 'error');
            ui.showError(error.message);
        } finally {
            appState.isEncrypting = false;
            ui.toggleButton(dom.sendButton, false, '<i class="fas fa-lock"></i> Encriptar');
        }
    },

    handleDecrypt: async (qrData) => {
        if (appState.isDecrypting) return;
        
        if (handlers.decryptAttempts >= CONFIG.MAX_DECRYPT_ATTEMPTS) {
            ui.showToast('Demasiados intentos de desencriptación. Espere.', 'error');
            setTimeout(() => { handlers.decryptAttempts = 0; }, CONFIG.DECRYPT_DELAY_INCREMENT * 10);
            return;
        }
        
        const passphrase = dom.passphrase.value.trim();
        if (!passphrase) {
            ui.displayMessage('Por favor, ingrese una contraseña');
            ui.showToast('Falta la contraseña', 'error');
            ui.showError('Falta la contraseña');
            return;
        }
        
        appState.isDecrypting = true;
        ui.toggleButton(dom.decodeButton, true, '<span class="loader"></span> Desencriptando...');
        
        try {
            const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
            ui.displayMessage(`Mensaje desencriptado: ${ui.sanitizeHTML(decrypted)}`);
            ui.showToast('Mensaje desencriptado exitosamente', 'success');
            dom.passphrase.value = '';
            ui.updatePasswordStrength('');
            handlers.decryptAttempts = 0;
        } catch (error) {
            handlers.decryptAttempts++;
            ui.displayMessage(error.message);
            ui.showToast(error.message, 'error');
            ui.showError(error.message);
        } finally {
            appState.isDecrypting = false;
            ui.toggleButton(dom.decodeButton, false, '<i class="fas fa-unlock"></i> Desencriptar');
            dom.decodeButton.disabled = !appState.lastEncryptedData;
        }
    },

    startCamera: () => {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            ui.showToast('Acceso a la cámara no disponible', 'error');
            return;
        }
        
        navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
            .then(stream => {
                dom.cameraPreview.srcObject = stream;
                const scanLoop = () => {
                    if (!dom.cameraPreview.srcObject) return;
                    
                    try {
                        const canvas = document.createElement('canvas');
                        canvas.width = dom.cameraPreview.videoWidth;
                        canvas.height = dom.cameraPreview.videoHeight;
                        const ctx = canvas.getContext('2d');
                        ctx.drawImage(dom.cameraPreview, 0, 0, canvas.width, canvas.height);
                        
                        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                        const qrCode = jsQR(imageData.data, imageData.width, imageData.height);
                        
                        if (qrCode) {
                            ui.showScanEffect();
                            appState.lastEncryptedData = qrCode.data;
                            dom.decodeButton.disabled = false;
                            handlers.handleDecrypt(qrCode.data);
                            handlers.stopCamera();
                            ui.hideCameraModal();
                        } else {
                            requestAnimationFrame(scanLoop);
                        }
                    } catch (e) {
                        console.error('Error de escaneo:', e);
                        ui.showToast('Error al escanear QR', 'error');
                    }
                };
                scanLoop();
            })
            .catch(error => {
                console.error('Error de cámara:', error);
                ui.showToast('Error al acceder a la cámara', 'error');
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
                    appState.lastEncryptedData = qrCode.data;
                    dom.decodeButton.disabled = false;
                    handlers.handleDecrypt(qrCode.data);
                } else {
                    ui.displayMessage('No se detectó un código QR');
                    ui.showToast('No se encontró un código QR', 'error');
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
        ui.showToast('QR descargado', 'success');
    },

    handleCopy: async () => {
        try {
            await navigator.clipboard.writeText(dom.qrCanvas.toDataURL('image/png'));
            ui.showToast('QR copiado al portapapeles', 'success');
        } catch (err) {
            ui.showToast('Error al copiar QR', 'error');
        }
    },

    handleShare: async () => {
        try {
            const blob = await new Promise(resolve => dom.qrCanvas.toBlob(resolve));
            const file = new File([blob], 'hushbox-qr.png', { type: 'image/png' });
            
            if (navigator.share && navigator.canShare({ files: [file] })) {
                await navigator.share({
                    title: 'HushBox QR',
                    files: [file]
                });
                ui.showToast('QR compartido exitosamente', 'success');
            } else {
                throw new Error('Compartir no soportado');
            }
        } catch (error) {
            handlers.handleDownload();
            ui.showToast('Compartición no soportada, QR descargado', 'warning');
        }
    },

    handleExportPDF: async () => {
        if (!appState.lastEncryptedData) {
            ui.showToast('No hay mensaje encriptado para exportar', 'warning');
            return;
        }
        
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFontSize(16);
        doc.text('HushBox - Mensaje Encriptado', 20, 20);
        doc.setFontSize(12);
        doc.text('Escanee el siguiente código QR con HushBox:', 20, 40);
        
        const qrDataUrl = dom.qrCanvas.toDataURL('image/png');
        doc.addImage(qrDataUrl, 'PNG', 20, 50, 80, 80);
        
        doc.text('Instrucciones:', 20, 140);
        doc.text('- Use la contraseña original para desencriptar.', 20, 150);
        doc.text('- El mensaje está protegido con AES-256.', 20, 160);
        
        doc.save(`hushbox-mensaje-${Date.now()}.pdf`);
        ui.showToast('Mensaje exportado como PDF', 'success');
    },

    exportMessageHistory: async () => {
        if (appState.messageHistory.length <= 1) {
            ui.showToast('No hay mensajes para exportar', 'warning');
            return;
        }
        
        const passphrase = prompt('Ingrese una contraseña para encriptar el historial:');
        if (!passphrase) {
            ui.showToast('Se requiere una contraseña para exportar', 'error');
            return;
        }
        
        try {
            const csvContent = "Tipo,Mensaje,Fecha,Hora\n" + appState.messageHistory.map(msg => {
                const date = msg.timestamp.toLocaleDateString();
                const time = msg.timestamp.toLocaleTimeString();
                const type = msg.isSent ? "Enviado" : "Recibido";
                const safeMessage = msg.content.replace(/"/g, '""');
                return `"${type}","${safeMessage}","${date}","${time}"`;
            }).join('\n');
            
            const encryptedCsv = await cryptoUtils.encryptMessage(csvContent, passphrase);
            const blob = new Blob([encryptedCsv], { type: 'text/plain;charset=utf-8;' });
            const link = document.createElement('a');
            const url = URL.createObjectURL(blob);
            
            link.setAttribute('href', url);
            link.setAttribute('download', `hushbox-mensajes-encriptados-${new Date().toISOString().slice(0, 10)}.txt`);
            link.style.visibility = 'hidden';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            ui.showToast('Historial exportado encriptado', 'success');
        } catch (error) {
            ui.showToast('Error al exportar historial', 'error');
        }
    },

    clearSensitiveData: () => {
        dom.passphrase.value = '';
        dom.messageInput.value = '';
        appState.lastEncryptedData = null;
        dom.qrContainer.classList.add('hidden');
        ui.updatePasswordStrength('');
        dom.decodeButton.disabled = true;
        ui.showToast('Datos sensibles borrados', 'success');
    },

    resetSessionTimer: () => {
        clearTimeout(appState.sessionTimer);
        appState.sessionTimer = setTimeout(() => {
            if (!appState.sessionActive) return;
            const modal = document.createElement('div');
            modal.className = 'session-modal';
            modal.innerHTML = `
                <div class="modal-content">
                    <p>Su sesión está a punto de expirar. ¿Continuar?</p>
                    <button id="continue-session">Continuar</button>
                    <button id="end-session">Finalizar Sesión</button>
                </div>
            `;
            document.body.appendChild(modal);

            document.getElementById('continue-session').addEventListener('click', () => {
                appState.sessionActive = true;
                handlers.resetSessionTimer();
                modal.remove();
            });

            document.getElementById('end-session').addEventListener('click', () => {
                appState.sessionActive = false;
                handlers.clearSensitiveData();
                ui.showToast('Sesión finalizada por inactividad', 'warning');
                modal.remove();
            });
        }, CONFIG.SESSION_TIMEOUT);
    },

    initEventListeners: () => {
        dom.encryptForm.addEventListener('submit', handlers.handleEncrypt);
        dom.decodeButton.addEventListener('click', () => handlers.handleDecrypt(appState.lastEncryptedData));
        dom.downloadButton.addEventListener('click', handlers.handleDownload);
        dom.shareButton.addEventListener('click', handlers.handleShare);
        dom.copyButton.addEventListener('click', handlers.handleCopy);
        dom.scanButton.addEventListener('click', ui.showCameraModal);
        dom.closeCamera.addEventListener('click', ui.hideCameraModal);
        dom.uploadArrow.addEventListener('click', handlers.handleUpload);
        dom.imageButton.addEventListener('click', handlers.handleUpload);
        dom.fileInput.addEventListener('change', handlers.handleFileSelect);
        dom.pdfButton.addEventListener('click', handlers.handleExportPDF);
        dom.generatePass.addEventListener('click', () => {
            const pass = cryptoUtils.generateSecurePass();
            dom.passphrase.value = pass;
            ui.updatePasswordStrength(pass);
            ui.displayMessage(`Contraseña generada: ${ui.sanitizeHTML(pass)}`, true);
            ui.showToast('Contraseña segura generada', 'success');
        });
        dom.messageInput.addEventListener('input', () => {
            const len = dom.messageInput.value.length;
            dom.charCounter.textContent = `${CONFIG.MAX_MESSAGE_LENGTH - len}/${CONFIG.MAX_MESSAGE_LENGTH}`;
            dom.charCounter.style.color = len > CONFIG.MAX_MESSAGE_LENGTH - 400 ? 'var(--error-color)' : 'rgba(160,160,160,0.8)';
        });
        dom.clearHistory.addEventListener('click', ui.clearMessageHistory);
        dom.exportHistory.addEventListener('click', handlers.exportMessageHistory);
        dom.togglePassword.addEventListener('click', ui.togglePasswordVisibility);
        dom.passphrase.addEventListener('input', (e) => {
            ui.updatePasswordStrength(e.target.value);
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && dom.cameraModal.style.display === 'flex') {
                ui.hideCameraModal();
            }
        });
        handlers.resetSessionTimer();
        document.addEventListener('click', handlers.resetSessionTimer);
        document.addEventListener('keypress', handlers.resetSessionTimer);
        if (navigator.userAgent.includes('Telegram')) {
            document.documentElement.style.setProperty('--background-gradient', 'linear-gradient(135deg, #0d0d0d 0%, #1a1a1a 100%)');
            ui.showToast('Modo Telegram optimizado', 'info');
        }
    }
};

// Funciones para el modal de bienvenida
const tutorial = {
    showTutorialModal: () => {
        dom.tutorialModal.style.display = 'flex';
    },

    hideTutorialModal: () => {
        dom.tutorialModal.style.display = 'none';
    },

    saveDontShowPreference: () => {
        if (dom.dontShowAgainCheckbox.checked) {
            localStorage.setItem('dontShowTutorial', 'true');
        }
    }
};

// Inicialización
document.addEventListener('DOMContentLoaded', () => {
    handlers.initEventListeners();
    dom.qrContainer.classList.add('hidden');
    dom.cameraModal.style.display = 'none';
    
    const dontShowTutorial = localStorage.getItem('dontShowTutorial');
    if (!dontShowTutorial) {
        tutorial.showTutorialModal();
    } else {
        setTimeout(() => {
            ui.displayMessage('Bienvenido a HushBox Enterprise. Su mensajería segura.', false);
            ui.showToast('Sesión segura iniciada', 'success');
            dom.exportHistory.disabled = true;
        }, 1000);
    }

    dom.closeTutorial.addEventListener('click', () => {
        tutorial.hideTutorialModal();
        setTimeout(() => {
            ui.displayMessage('Bienvenido a HushBox Enterprise. Su mensajería segura.', false);
            ui.showToast('Sesión segura iniciada', 'success');
            dom.exportHistory.disabled = true;
        }, 500);
    });

    dom.tutorialModal.querySelector('.close-modal').addEventListener('click', () => {
        tutorial.hideTutorialModal();
        setTimeout(() => {
            ui.displayMessage('Bienvenido a HushBox Enterprise. Su mensajería segura.', false);
            ui.showToast('Sesión segura iniciada', 'success');
            dom.exportHistory.disabled = true;
        }, 500);
    });

    dom.dontShowAgainButton.addEventListener('click', () => {
        tutorial.saveDontShowPreference();
        tutorial.hideTutorialModal();
        setTimeout(() => {
            ui.displayMessage('Bienvenido a HushBox Enterprise. Su mensajería segura.', false);
            ui.showToast('Sesión segura iniciada', 'success');
            dom.exportHistory.disabled = true;
        }, 500);
    });

    dom.dontShowAgainCheckbox.addEventListener('change', () => {
        dom.dontShowAgainButton.classList.toggle('hidden', !dom.dontShowAgainCheckbox.checked);
    });
});
