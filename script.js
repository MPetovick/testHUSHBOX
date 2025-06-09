// Global configuration
const CONFIG = {
  PBKDF2_ITERATIONS: 310000,
  SALT_LENGTH: 32,
  IV_LENGTH: 16,
  AES_KEY_LENGTH: 256,
  QR_SIZE: 220,
  MIN_PASSPHRASE_LENGTH: 12,
  MAX_MESSAGE_LENGTH: 10000,
  CAMERA_TIMEOUT: 30000,
  DECRYPT_DELAY_INCREMENT: 100,
  MAX_DECRYPT_ATTEMPTS: 5,
  NOTICE_TIMEOUT: 8000,
  SESSION_TIMEOUT: 1800000, // 30 minutes
  COMPRESSION_THRESHOLD: 100
};

// DOM elements
const dom = {
  encryptForm: document.getElementById('encrypt-form') || throwError('Encrypt form not found'),
  uploadArrow: document.getElementById('upload-arrow-button') || throwError('Upload arrow button not found'),
  scanButton: document.getElementById('scan-button') || throwError('Scan button not found'),
  pdfButton: document.getElementById('pdf-button') || throwError('PDF button not found'),
  messages: document.getElementById('messages') || throwError('Messages container not found'),
  passphrase: document.getElementById('passphrase') || throwError('Passphrase input not found'),
  messageInput: document.getElementById('message-input') || throwError('Message input not found'),
  sendButton: document.getElementById('send-button') || throwError('Send button not found'),
  qrCanvas: document.getElementById('qr-canvas') || throwError('QR canvas not found'),
  decodeButton: document.getElementById('decode-button') || throwError('Decode button not found'),
  shareButton: document.getElementById('share-button') || throwError('Share button not found'),
  copyButton: document.getElementById('copy-button') || throwError('Copy button not found'),
  qrContainer: document.getElementById('qr-container') || throwError('QR container not found'),
  comingSoon: document.getElementById('coming-soon-message') || throwError('Coming soon message not found'),
  cameraModal: document.getElementById('camera-modal') || throwError('Camera modal not found'),
  cameraPreview: document.getElementById('camera-preview') || throwError('Camera preview not found'),
  closeCamera: document.getElementById('close-camera') || throwError('Close camera button not found'),
  cameraContainer: document.querySelector('.camera-container') || throwError('Camera container not found'),
  fileInput: document.createElement('input'),
  charCounter: document.getElementById('char-counter') || throwError('Char counter not found'),
  generatePass: document.querySelector('.generate-password') || throwError('Generate password button not found'),
  togglePassword: document.querySelector('.toggle-password') || throwError('Toggle password button not found'),
  passwordStrengthBar: document.getElementById('password-strength-bar') || throwError('Password strength bar not found'),
  clearHistory: document.getElementById('clear-history') || throwError('Clear history button not found'),
  exportHistory: document.getElementById('export-history') || throwError('Export history button not found'),
  importHistory: document.getElementById('import-history') || throwError('Import history button not found'),
  toastContainer: document.getElementById('toast-container') || throwError('Toast container not found'),
  passphraseError: document.getElementById('passphrase-error') || throwError('Passphrase error not found'),
  tutorialModal: document.getElementById('tutorial-modal') || throwError('Tutorial modal not found'),
  closeTutorial: document.getElementById('close-tutorial') || throwError('Close tutorial button not found'),
  dontShowAgainCheckbox: document.getElementById('dont-show-again-checkbox') || throwError('Don\'t show again checkbox not found'),
  dontShowAgainButton: document.getElementById('dont-show-again') || throwError('Don\'t show again button not found'),
  passphraseModal: document.getElementById('passphrase-modal') || throwError('Passphrase modal not found'),
  modalPassphrase: document.getElementById('modal-passphrase') || throwError('Modal passphrase input not found'),
  modalPassphraseError: document.getElementById('modal-passphrase-error') || throwError('Modal passphrase error not found'),
  modalDecryptButton: document.getElementById('modal-decrypt-button') || throwError('Modal decrypt button not found'),
  modalCancelButton: document.getElementById('modal-cancel-button') || throwError('Modal cancel button not found'),
  closePassphraseModal: document.getElementById('close-passphrase') || throwError('Close passphrase modal button not found'),
  detectionBox: null,
  scanLine: null,
};

// Helper function for DOM errors
function throwError(message) {
  throw new Error(`DOM Error: ${message}`);
}

// File input initialization
dom.fileInput.type = 'file';
dom.fileInput.accept = 'image/*,.csv';
dom.fileInput.style.display = 'none';
document.body.appendChild(dom.fileInput);

// Application state
const appState = {
  isEncrypting: false,
  isDecrypting: false,
  sessionActive: true,
  messageHistory: [],
  passwordVisible: false,
  lastEncryptedData: null,
  sessionTimer: null,
  importingHistory: false
};

// Cryptographic utilities
const cryptoUtils = {
  validatePassphrase: (pass) => {
    if (!pass || pass.length < CONFIG.MIN_PASSPHRASE_LENGTH) {
      throw new Error(`Password must be at least ${CONFIG.MIN_PASSPHRASE_LENGTH} characters long`);
    }
    const hasUpperCase = /[A-Z]/.test(pass);
    const hasLowerCase = /[a-z]/.test(pass);
    const hasNumbers = /[0-9]/.test(pass);
    const hasSymbols = /[^A-Za-z0-9]/.test(pass);
    const uniqueChars = new Set(pass).size;

    if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSymbols) {
      throw new Error('Password must include uppercase, lowercase, numbers, and symbols');
    }
    if (uniqueChars < CONFIG.MIN_PASSPHRASE_LENGTH * 0.7) {
      throw new Error('Password has too many repeated characters');
    }
    if (typeof zxcvbn !== 'undefined') {
      const score = zxcvbn(pass).score;
      if (score < 3) {
        throw new Error('Password is too weak');
      }
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
    return Math.max(0, Math.min(100, strength));
  },

  generateSecurePass: (length = 16, maxAttempts = 10) => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
    let attempts = 0;

    while (attempts < maxAttempts) {
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
        attempts++;
      }
    }
    throw new Error('Failed to generate a secure password after multiple attempts');
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
      if (!message) throw new Error('Message cannot be empty');
      dataToEncrypt = new TextEncoder().encode(message);

      if (typeof pako !== 'undefined' && message.length > CONFIG.COMPRESSION_THRESHOLD) {
        dataToEncrypt = pako.deflate(dataToEncrypt, { level: 6 });
      }

      const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
      const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));

      const baseKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: CONFIG.PBKDF2_ITERATIONS,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: CONFIG.AES_KEY_LENGTH },
        false,
        ['encrypt']
      );

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        dataToEncrypt
      );

      const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
      const result = btoa(String.fromCharCode(...combined));

      cryptoUtils.secureWipe(dataToEncrypt);
      return result;
    } catch (error) {
      console.error('Encryption error:', error);
      throw new Error('Encryption failed: ' + error.message);
    } finally {
      if (dataToEncrypt) cryptoUtils.secureWipe(dataToEncrypt);
    }
  },

  decryptMessage: async (encryptedBase64, passphrase) => {
    let decrypted = null;
    try {
      if (!encryptedBase64 || !passphrase) throw new Error('Encrypted data and passphrase are required');
      const encryptedData = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
      if (encryptedData.length < CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH + 16) {
        throw new Error('Invalid encrypted data');
      }

      const salt = encryptedData.slice(0, CONFIG.SALT_LENGTH);
      const iv = encryptedData.slice(CONFIG.SALT_LENGTH, CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);
      const ciphertext = encryptedData.slice(CONFIG.SALT_LENGTH + CONFIG.IV_LENGTH);

      const baseKey = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(passphrase),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
      );

      const key = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt,
          iterations: CONFIG.PBKDF2_ITERATIONS,
          hash: 'SHA-256'
        },
        baseKey,
        { name: 'AES-GCM', length: CONFIG.AES_KEY_LENGTH },
        false,
        ['decrypt']
      );

      decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        ciphertext
      );

      let decompressed;
      try {
        if (typeof pako !== 'undefined') {
          decompressed = pako.inflate(new Uint8Array(decrypted));
        } else {
          decompressed = new Uint8Array(decrypted);
        }
      } catch (e) {
        decompressed = new Uint8Array(decrypted);
      }
      const result = new TextDecoder().decode(decompressed);

      cryptoUtils.secureWipe(ciphertext);
      return result;
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Decryption failed: ' + error.message);
    } finally {
      if (decrypted) cryptoUtils.secureWipe(decrypted);
    }
  }
};

// UI controller
const ui = {
  sanitizeHTML: (str) => {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  },

  showPlaceholder: (message, iconClass) => {
    dom.messages.innerHTML = `
      <div class="message-placeholder">
        <i class="fas ${iconClass}" aria-hidden="true"></i>
        <p>${ui.sanitizeHTML(message)}</p>
      </div>
    `;
  },

  displayMessage: (content, isSent = false) => {
    const placeholder = dom.messages.querySelector('.message-placeholder');
    if (placeholder) {
      placeholder.remove();
    }

    const messageEl = document.createElement('div');
    messageEl.className = `message ${isSent ? 'sent' : ''}`;
    messageEl.innerHTML = `
      <div class="message-content" role="alert" aria-live="polite">${ui.sanitizeHTML(content)}</div>
      <div class="message-time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
    `;

    appState.messageHistory.push({
      content,
      isSent,
      timestamp: new Date()
    });

    if (dom.messages.children.length >= 15) {
      dom.messages.removeChild(dom.messages.firstChild);
    }

    dom.messages.appendChild(messageEl);
    dom.messages.scrollTop = dom.messages.scrollHeight;

    dom.exportHistory.disabled = appState.messageHistory.length === 0;
  },

  generateQR: async (data) => {
    if (typeof QRCode === 'undefined') {
      throw new Error('QRCode library not loaded');
    }
    return new Promise((resolve, reject) => {
      const qrSize = CONFIG.QR_SIZE;
      dom.qrCanvas.width = qrSize;
      dom.qrCanvas.height = qrSize;

      const tempCanvas = document.createElement('canvas');
      tempCanvas.width = qrSize;
      tempCanvas.height = qrSize;

      QRCode.toCanvas(
        tempCanvas,
        data,
        {
          width: qrSize,
          margin: 2,
          color: { dark: '#000000', light: '#ffffff' },
          errorCorrectionLevel: 'H'
        },
        (error) => {
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
          ctx.fillStyle = '#000000';
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
        }
      );
    });
  },

  toggleButton: (btn, state, text = '') => {
    btn.disabled = state;
    if (text) {
      btn.innerHTML = text;
    }
  },

  showCameraModal: () => {
    dom.cameraModal.style.display = 'flex';
    handlers.startCamera();
  },

  hideCameraModal: () => {
    dom.cameraModal.style.display = 'none';
    handlers.stopCamera();
  },

  showPassphraseModal: () => {
    dom.passphraseModal.style.display = 'flex';
    dom.modalPassphrase.focus();
    dom.modalPassphraseError.classList.add('hidden');
  },

  hidePassphraseModal: () => {
    dom.passphraseModal.style.display = 'none';
    dom.modalPassphrase.value = '';
    dom.modalPassphraseError.classList.add('hidden');
  },

  showDetectionBox: () => {
    if (!dom.detectionBox) {
      dom.detectionBox = document.createElement('div');
      dom.detectionBox.className = 'detection-box';
      dom.cameraContainer.appendChild(dom.detectionBox);
      
      dom.scanLine = document.createElement('div');
      dom.scanLine.className = 'scan-line';
      dom.detectionBox.appendChild(dom.scanLine);
    }
    const containerRect = dom.cameraContainer.getBoundingClientRect();
    dom.detectionBox.style.width = `${containerRect.width * 0.7}px`;
    dom.detectionBox.style.height = `${containerRect.width * 0.7}px`;
    dom.detectionBox.style.left = `${containerRect.width * 0.15}px`;
    dom.detectionBox.style.top = `${containerRect.height * 0.15}px`;
  },

  hideDetectionBox: () => {
    if (dom.detectionBox) {
      dom.detectionBox.classList.remove('active');
    }
  },

  updateDetectionBox: (location) => {
    if (!dom.detectionBox) return;
    
    const { topLeft, topRight, bottomLeft, bottomRight } = location;
    const width = Math.max(topRight.x - topLeft.x, bottomRight.x - bottomLeft.x);
    const height = Math.max(bottomLeft.y - topLeft.y, bottomRight.y - topRight.y);
    
    dom.detectionBox.style.width = `${width}px`;
    dom.detectionBox.style.height = `${height}px`;
    dom.detectionBox.style.left = `${topLeft.x}px`;
    dom.detectionBox.style.top = `${topLeft.y}px`;
    dom.detectionBox.classList.add('active');
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
    if (confirm('Are you sure you want to clear the message history?')) {
      ui.showPlaceholder('Message history cleared', 'fa-trash-alt');
      appState.messageHistory = [];
      dom.exportHistory.disabled = true;
      ui.showToast('Message history cleared', 'success');
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
  },

  showComingSoon: () => {
    dom.comingSoon.classList.add('visible');
    setTimeout(() => {
      dom.comingSoon.classList.remove('visible');
    }, 2000);
  }
};

// CSV parsing utilities
const csvUtils = {
  parseCSVLine: (line) => {
    const result = [];
    let current = '';
    let inQuotes = false;
    let escapeNext = false;
    
    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      
      if (escapeNext) {
        current += char;
        escapeNext = false;
        continue;
      }
      
      if (char === '\\') {
        escapeNext = true;
        continue;
      }
      
      if (char === '"') {
        if (inQuotes && i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
        continue;
      }
      
      if (char === ',' && !inQuotes) {
        result.push(current);
        current = '';
        continue;
      }
      
      current += char;
    }
    
    result.push(current);
    return result.map(field => field.trim());
  },

  parseCSV: (csvData) => {
    const lines = csvData
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .split('\n')
      .filter(line => line.trim());
    
    if (lines.length === 0) {
      throw new Error('Empty CSV file');
    }
    
    const header = csvUtils.parseCSVLine(lines[0]);
    const requiredHeaders = ['Type', 'Message', 'Date', 'Time'];
    if (!requiredHeaders.every(h => header.includes(h))) {
      throw new Error('Invalid CSV format: Missing required headers');
    }
    
    const messages = [];
    
    for (let i = 1; i < lines.length; i++) {
      const fields = csvUtils.parseCSVLine(lines[i]);
      if (fields.length < 4) {
        console.warn(`Skipping invalid line ${i + 1}: ${lines[i]}`);
        continue;
      }
      
      const type = fields[0];
      const content = fields[1].replace(/\\n/g, '\n');
      const date = fields[2];
      const time = fields[3];
      
      let timestamp;
      try {
        if (date.includes('-') && time.includes(':')) {
          timestamp = new Date(`${date}T${time}`);
        } else {
          timestamp = new Date(`${date} ${time}`);
        }
        
        if (isNaN(timestamp.getTime())) {
          timestamp = new Date();
        }
      } catch (e) {
        timestamp = new Date();
      }
      
      messages.push({
        content,
        isSent: type === 'Sent',
        timestamp
      });
    }
    
    return messages;
  },

  generateCSV: (messages) => {
    const header = ['Type', 'Message', 'Date', 'Time'];
    const rows = messages.map(msg => {
      const type = msg.isSent ? 'Sent' : 'Received';
      const safeMessage = `"${msg.content
        .replace(/"/g, '""')
        .replace(/\n/g, '\\n')}"`;
      const date = msg.timestamp.toLocaleDateString();
      const time = msg.timestamp.toLocaleTimeString();
      
      return [type, safeMessage, date, time];
    });
    
    return [header, ...rows]
      .map(row => row.join(','))
      .join('\n');
  }
};

// Event handlers
const handlers = {
  decryptAttempts: 0,

  handleEncrypt: async (e) => {
    e.preventDefault();
    if (appState.isEncrypting) return;

    const message = dom.messageInput.value.trim();
    const passphrase = dom.passphrase.value.trim();

    if (!message || !passphrase) {
      ui.displayMessage('Please enter a message and a passphrase');
      ui.showToast('Missing message or passphrase', 'error');
      return;
    }

    appState.isEncrypting = true;
    ui.toggleButton(dom.sendButton, true, '<span class="loader"></span> Encrypting...');

    try {
      const encrypted = await cryptoUtils.encryptMessage(message, passphrase);
      appState.lastEncryptedData = encrypted;
      await ui.generateQR(encrypted);
      ui.displayMessage(`Encrypted message: ${ui.sanitizeHTML(encrypted.slice(0, 40))}...`, true);
      ui.showToast('Message encrypted successfully', 'success');

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
      ui.toggleButton(dom.sendButton, false, '<i class="fas fa-lock"></i> Encrypt');
    }
  },

  handleDecrypt: async (qrData) => {
    if (appState.isDecrypting) return;

    if (handlers.decryptAttempts >= CONFIG.MAX_DECRYPT_ATTEMPTS) {
      ui.showToast('Too many decryption attempts. Please wait.', 'error');
      setTimeout(() => { handlers.decryptAttempts = 0; }, CONFIG.DECRYPT_DELAY_INCREMENT * 10);
      return;
    }

    const passphrase = dom.passphrase.value.trim();
    if (!passphrase) {
      ui.displayMessage('Please enter a passphrase');
      ui.showError('Passphrase missing');
      ui.showToast('Passphrase missing', 'error');
      return;
    }

    appState.isDecrypting = true;
    ui.toggleButton(dom.decodeButton, true, '<span class="loader"></span> Decrypting...');

    try {
      const decrypted = await cryptoUtils.decryptMessage(qrData, passphrase);
      ui.displayMessage(`Decrypted message: ${ui.sanitizeHTML(decrypted)}`);
      ui.showToast('Message decrypted successfully', 'success');
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
      ui.toggleButton(dom.decodeButton, false, '<i class="fas fa-unlock"></i> Decrypt');
      dom.decodeButton.disabled = !appState.lastEncryptedData;
    }
  },

  handleModalDecrypt: async () => {
    const passphrase = dom.modalPassphrase.value.trim();
    
    if (!passphrase) {
      dom.modalPassphraseError.textContent = 'Please enter a passphrase';
      dom.modalPassphraseError.classList.remove('hidden');
      return;
    }

    try {
      const decrypted = await cryptoUtils.decryptMessage(appState.lastEncryptedData, passphrase);
      ui.displayMessage(`Decrypted message: ${ui.sanitizeHTML(decrypted)}`);
      ui.hidePassphraseModal();
      ui.showToast('Message decrypted successfully', 'success');
    } catch (error) {
      console.error('Decryption error:', error);
      dom.modalPassphraseError.textContent = error.message || 'Invalid passphrase or corrupted data';
      dom.modalPassphraseError.classList.remove('hidden');
    }
  },

  startCamera: () => {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      ui.showToast('Camera access not supported', 'error');
      return;
    }
    if (typeof jsQR === 'undefined') {
      ui.showToast('jsQR library not loaded', 'error');
      return;
    }

    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
      .then(stream => {
        dom.cameraPreview.srcObject = stream;
        dom.cameraPreview.play();
        ui.showDetectionBox();
        
        let lastScanTime = 0;
        const scanInterval = 100;

        const timeoutId = setTimeout(() => {
          if (dom.cameraPreview.srcObject) {
            handlers.stopCamera();
            ui.hideCameraModal();
            ui.showToast('Scanning timed out after 30 seconds', 'warning');
          }
        }, CONFIG.CAMERA_TIMEOUT);

        const scanLoop = (timestamp) => {
          if (!dom.cameraPreview.srcObject) {
            clearTimeout(timeoutId);
            return;
          }

          if (timestamp - lastScanTime < scanInterval) {
            requestAnimationFrame(scanLoop);
            return;
          }

          lastScanTime = timestamp;

          try {
            const canvas = document.createElement('canvas');
            canvas.width = dom.cameraPreview.videoWidth;
            canvas.height = dom.cameraPreview.videoHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(dom.cameraPreview, 0, 0, canvas.width, canvas.height);

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const qrCode = jsQR(imageData.data, imageData.width, imageData.height);

            if (qrCode) {
              ui.updateDetectionBox(qrCode.location);
              setTimeout(() => {
                handlers.stopCamera();
                ui.hideCameraModal();
                appState.lastEncryptedData = qrCode.data;
                ui.showPassphraseModal();
                clearTimeout(timeoutId);
              }, 1000);
            } else {
              ui.hideDetectionBox();
              requestAnimationFrame(scanLoop);
            }
          } catch (e) {
            console.error('Scan error:', e);
            ui.showToast('Error scanning QR code', 'error');
            setTimeout(() => requestAnimationFrame(scanLoop), 300);
          }
        };

        requestAnimationFrame(scanLoop);

        dom.cameraPreview.addEventListener('ended', () => {
          clearTimeout(timeoutId);
        }, { once: true });
      })
      .catch(error => {
        console.error('Camera access error:', error);
        ui.showToast('Unable to access camera', 'error');
        ui.hideCameraModal();
      });
  },

  stopCamera: () => {
    if (dom.cameraPreview.srcObject) {
      dom.cameraPreview.srcObject.getTracks().forEach(track => track.stop());
      dom.cameraPreview.srcObject = null;
    }
    ui.hideDetectionBox();
  },

  handleUpload: () => {
    dom.fileInput.accept = 'image/*';
    appState.importingHistory = false;
    dom.fileInput.click();
  },

  handleImportHistory: () => {
    dom.fileInput.accept = '.csv';
    appState.importingHistory = true;
    dom.fileInput.click();
  },

  handleFileSelect: async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      if (appState.importingHistory) {
        if (file.type === 'text/csv' || file.name.endsWith('.csv')) {
          await handlers.importMessageHistory(file);
        } else {
          ui.showToast('Please select a CSV file for history import', 'error');
        }
      } else {
        if (file.type.startsWith('image/')) {
          await handlers.handleQRUpload(file);
        } else {
          ui.showToast('Please select an image file', 'error');
        }
      }
    } catch (error) {
      console.error('File processing error:', error);
      ui.showToast(`Error: ${error.message}`, 'error');
    } finally {
      dom.fileInput.value = '';
    }
  },

  handleQRUpload: async (file) => {
    if (typeof jsQR === 'undefined') {
      ui.showToast('jsQR library not loaded', 'error');
      return;
    }

    return new Promise((resolve) => {
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
            ui.showPassphraseModal();
            ui.showToast('QR code uploaded successfully', 'success');
          } else {
            ui.displayMessage('No QR code detected');
            ui.showToast('No QR code found', 'error');
          }
          resolve();
        };
        img.src = e.target.result;
      };
      reader.readAsDataURL(file);
    });
  },

  handleCopy: async () => {
    try {
      await navigator.clipboard.writeText(dom.qrCanvas.toDataURL('image/png'));
      ui.showToast('QR copied to clipboard', 'success');
    } catch (err) {
      ui.showToast('Error copying QR', 'error');
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
        ui.showToast('QR shared successfully', 'success');
      } else {
        throw new Error('Sharing not supported');
      }
    } catch (error) {
      ui.showToast('Sharing not supported', 'warning');
    }
  },

  handleExportPDF: async () => {
    if (!appState.lastEncryptedData) {
      ui.showToast('No encrypted message to export', 'warning');
      return;
    }

    try {
      if (typeof window.jspdf === 'undefined') {
        throw new Error('jsPDF library not available');
      }

      const { jsPDF } = window.jspdf;
      const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4'
      });

      doc.setFont('helvetica', 'bold');
      doc.setFontSize(18);
      doc.setTextColor(0, 204, 153);
      doc.text('HushBox - Encrypted Message', 105, 20, null, null, 'center');

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(12);
      doc.setTextColor(240, 240, 240);
      doc.text('Scan the following QR code with HushBox to decrypt:', 105, 30, null, null, 'center');

      const qrDataUrl = dom.qrCanvas.toDataURL('image/png');
      doc.addImage(qrDataUrl, 'PNG', 70, 40, 70, 70);

      doc.setFontSize(10);
      doc.setTextColor(200, 200, 200);
      doc.text('Security Instructions:', 20, 120);
      doc.text('- Share this document only with authorized recipients', 20, 130);
      doc.text('- Transmit the passphrase via a separate channel (e.g., Signal)', 20, 140);
      doc.text('- The message is protected with AES-256-GCM', 20, 150);
      doc.text('- Delete this document after use', 20, 160);

      doc.setFontSize(8);
      doc.setTextColor(100, 100, 100, 20);
      doc.text('SECURE DOCUMENT - DO NOT SHARE', 105, 280, null, null, 'center');

      doc.setFont('courier', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(160, 160, 160);
      doc.text(
        `Generated by HushBox Enterprise v3.2.2 | ${new Date().toLocaleString()}`,
        105,
        290,
        null,
        null,
        'center'
      );

      doc.save(`hushbox-message-${Date.now()}.pdf`);
      ui.showToast('PDF exported successfully', 'success');
    } catch (error) {
      console.error('Error exporting PDF:', error);
      ui.showToast(`Error exporting PDF: ${error.message}`, 'error');
    }
  },

  exportMessageHistory: async () => {
    if (appState.messageHistory.length === 0) {
      ui.showToast('No messages to export', 'warning');
      return;
    }

    const passphrase = prompt('Enter a passphrase to encrypt the history:');
    if (!passphrase) {
      ui.showToast('Passphrase required to export', 'error');
      return;
    }

    try {
      const csvContent = csvUtils.generateCSV(appState.messageHistory);
      const encryptedCsv = await cryptoUtils.encryptMessage(csvContent, passphrase);
      const blob = new Blob([encryptedCsv], { type: 'text/csv;charset=utf-8' });
      const link = document.createElement('a');
      const url = URL.createObjectURL(blob);

      link.href = url;
      link.download = `hushbox-messages-encrypted-${new Date().toISOString().slice(0, 10)}.csv`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);

      ui.showToast('History exported successfully', 'success');
    } catch (error) {
      console.error('Error exporting history:', error);
      ui.showToast(`Error exporting history: ${error.message}`, 'error');
    }
  },

  importMessageHistory: async (file) => {
    if (!file) {
      ui.showToast('No file selected', 'error');
      return;
    }

    const passphrase = prompt('Enter the passphrase to decrypt the history:');
    if (!passphrase) {
      ui.showToast('Passphrase required to import', 'error');
      return;
    }

    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        try {
          const encryptedData = e.target.result;
          const decryptedCsv = await cryptoUtils.decryptMessage(encryptedData, passphrase);
          
          const messages = csvUtils.parseCSV(decryptedCsv);
          if (messages.length === 0) {
            ui.showToast('No messages found in the imported file', 'warning');
            return;
          }

          appState.messageHistory.push(...messages);
          dom.messages.innerHTML = '';
          messages.forEach(msg => {
            ui.displayMessage(msg.content, msg.isSent);
          });

          ui.showToast(`Imported ${messages.length} messages`, 'success');
          dom.exportHistory.disabled = false;
        } catch (error) {
          console.error('Error importing history:', error);
          ui.showToast(`Error importing history: ${error.message}`, 'error');
        }
      };
      reader.readAsText(file);
    } catch (error) {
      console.error('Error importing history:', error);
      ui.showToast(`Error importing history: ${error.message}`, 'error');
    }
  },

  clearSensitiveData: () => {
    dom.passphrase.value = '';
    dom.messageInput.value = '';
    appState.lastEncryptedData = null;
    dom.qrContainer.classList.add('hidden');
    ui.updatePasswordStrength('');
    dom.decodeButton.disabled = true;
    ui.showToast('Sensitive data cleared', 'success');
  },

  resetSessionTimer: () => {
    clearTimeout(appState.sessionTimer);
    appState.sessionTimer = setTimeout(() => {
      if (!appState.sessionActive) return;
      const modal = document.createElement('div');
      modal.className = 'session-modal';
      modal.innerHTML = `
        <div class="modal-content">
          <p>Your session is about to expire. Continue?</p>
          <button id="continue-session">Continue</button>
          <button id="end-session">End Session</button>
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
        ui.showToast('Session ended due to inactivity', 'warning');
        modal.remove();
      });
    }, CONFIG.SESSION_TIMEOUT);
  },

  initEventListeners: () => {
    try {
      dom.encryptForm.addEventListener('submit', handlers.handleEncrypt);
      dom.decodeButton.addEventListener('click', () => handlers.handleDecrypt(appState.lastEncryptedData));
      dom.shareButton.addEventListener('click', handlers.handleShare);
      dom.copyButton.addEventListener('click', handlers.handleCopy);
      dom.scanButton.addEventListener('click', ui.showCameraModal);
      dom.closeCamera.addEventListener('click', ui.hideCameraModal);
      dom.uploadArrow.addEventListener('click', handlers.handleUpload);
      dom.fileInput.addEventListener('change', handlers.handleFileSelect);
      dom.pdfButton.addEventListener('click', handlers.handleExportPDF);
      dom.generatePass.addEventListener('click', () => {
        try {
          const pass = cryptoUtils.generateSecurePass();
          dom.passphrase.value = pass;
          ui.updatePasswordStrength(pass);
          ui.displayMessage(`Generated password: ${ui.sanitizeHTML(pass)}`, true);
          ui.showToast('Secure password generated', 'success');
        } catch (error) {
          ui.showToast(`Error generating password: ${error.message}`, 'error');
        }
      });
      dom.messageInput.addEventListener('input', () => {
        const len = dom.messageInput.value.length;
        dom.charCounter.textContent = `${CONFIG.MAX_MESSAGE_LENGTH - len}/${CONFIG.MAX_MESSAGE_LENGTH}`;
        dom.charCounter.style.color = len > CONFIG.MAX_MESSAGE_LENGTH - 400
          ? 'var(--error-color)'
          : 'rgba(160,160,160,0.8)';
      });
      dom.clearHistory.addEventListener('click', ui.clearMessageHistory);
      dom.exportHistory.addEventListener('click', handlers.exportMessageHistory);
      dom.importHistory.addEventListener('click', handlers.handleImportHistory);
      dom.togglePassword.addEventListener('click', ui.togglePasswordVisibility);
      dom.passphrase.addEventListener('input', (e) => {
        ui.updatePasswordStrength(e.target.value);
      });
      dom.modalDecryptButton.addEventListener('click', handlers.handleModalDecrypt);
      dom.modalCancelButton.addEventListener('click', ui.hidePassphraseModal);
      dom.closePassphraseModal.addEventListener('click', ui.hidePassphraseModal);
      const modalTogglePassword = document.querySelector('#passphrase-modal .toggle-password');
      modalTogglePassword.addEventListener('click', () => {
        const input = dom.modalPassphrase;
        const icon = modalTogglePassword.querySelector('i');
        input.type = input.type === 'password' ? 'text' : 'password';
        icon.classList.toggle('fa-eye');
        icon.classList.toggle('fa-eye-slash');
      });
      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
          if (dom.cameraModal.style.display === 'flex') {
            ui.hideCameraModal();
          } else if (dom.passphraseModal.style.display === 'flex') {
            ui.hidePassphraseModal();
          }
        }
      });
      handlers.resetSessionTimer();
      document.addEventListener('click', handlers.resetSessionTimer);
      document.addEventListener('keypress', handlers.resetSessionTimer);
      if (navigator.userAgent.includes('Telegram')) {
        document.documentElement.style.setProperty(
          '--background-gradient',
          'linear-gradient(135deg, #0d0d2d 0%, #1a1a3a 100%)'
        );
        ui.showToast('Telegram mode optimized', 'info');
      }
    } catch (error) {
      console.error('Error initializing listeners:', error);
      ui.showToast('Application initialization failed', 'error');
    }
  }
};

// Welcome modal functions
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

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  try {
    handlers.initEventListeners();
    dom.qrContainer.classList.add('hidden');
    dom.cameraModal.style.display = 'none';
    dom.passphraseModal.style.display = 'none';

    ui.showPlaceholder('Encrypted and decrypted messages will appear here. Secure history', 'fa-comments');

    const dontShowTutorial = localStorage.getItem('dontShowTutorial');
    if (!dontShowTutorial) {
      tutorial.showTutorialModal();
    } else {
      setTimeout(() => {
        ui.showToast('Welcome to HushBox Enterprise. Your secure messaging.', 'success');
        dom.exportHistory.disabled = true;
      }, 1000);
    }

    dom.closeTutorial.addEventListener('click', () => {
      tutorial.hideTutorialModal();
      setTimeout(() => {
        ui.showToast('Welcome to HushBox Enterprise. Your secure messaging.', 'success');
        dom.exportHistory.disabled = true;
      }, 500);
    });

    const closeModalButton = dom.tutorialModal.querySelector('.close-modal');
    if (closeModalButton) {
      closeModalButton.addEventListener('click', () => {
        tutorial.hideTutorialModal();
        setTimeout(() => {
          ui.showToast('Welcome to HushBox Enterprise. Your secure messaging.', 'success');
          dom.exportHistory.disabled = true;
        }, 500);
      });
    }

    dom.dontShowAgainButton.addEventListener('click', () => {
      tutorial.saveDontShowPreference();
      tutorial.hideTutorialModal();
      setTimeout(() => {
        ui.showToast('Welcome to HushBox Enterprise. Your secure messaging.', 'success');
        dom.exportHistory.disabled = true;
      }, 500);
    });

    dom.dontShowAgainCheckbox.addEventListener('change', () => {
      dom.dontShowAgainButton.classList.toggle('hidden', !dom.dontShowAgainCheckbox.checked);
    });
  } catch (error) {
    console.error('Initialization error:', error);
    ui.showToast('Application initialization failed', 'error');
  }
});
