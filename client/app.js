class EncryptionApp {
  constructor() {
    this.currentUser = null;
    this.currentKeyPair = null;
    this.token = null;
    this.fileToProcess = null;

    this.initEventListeners();
    this.checkSession();
  }

  initEventListeners() {
    // Authentication
    document.getElementById('login-btn').addEventListener('click', () => this.showAuthModal('login'));
    document.getElementById('register-btn').addEventListener('click', () => this.showAuthModal('register'));
    document.querySelector('.close').addEventListener('click', () => this.closeAuthModal());
    document.getElementById('auth-form').addEventListener('submit', (e) => this.handleAuthSubmit(e));

    // Key management
    document.getElementById('generate-keys-btn').addEventListener('click', () => this.generateKeyPair());

    // File operations
    document.getElementById('file-input').addEventListener('change', (e) => this.handleFileSelect(e));
    document.getElementById('encrypt-btn').addEventListener('click', () => this.encryptFile());
    document.getElementById('decrypt-btn').addEventListener('click', () => this.decryptFile());
  }

  async checkSession() {
    const token = localStorage.getItem('authToken');
    if (token) {
      try {
        const response = await fetch('/api/auth/verify', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          }
        });

        if (response.ok) {
          const data = await response.json();
          this.currentUser = data.user;
          this.token = token;
          this.updateUIAfterLogin();
          this.loadUserKeyPair();
        } else {
          localStorage.removeItem('authToken');
        }
      } catch (error) {
        this.logStatus(`Error verifying session: ${error.message}`, 'error');
      }
    }
  }

  showAuthModal(mode) {
    const modal = document.getElementById('auth-modal');
    const title = document.getElementById('modal-title');
    const registerFields = document.getElementById('register-fields');
    const masterPasswordField = document.getElementById('master-password-field');

    if (mode === 'login') {
      title.textContent = 'Login';
      registerFields.style.display = 'none';
      masterPasswordField.style.display = 'none';
    } else {
      title.textContent = 'Register';
      registerFields.style.display = 'block';
      masterPasswordField.style.display = 'block';
    }

    modal.style.display = 'block';
  }

  closeAuthModal() {
    document.getElementById('auth-modal').style.display = 'none';
    document.getElementById('auth-form').reset();
  }

  async handleAuthSubmit(e) {
    e.preventDefault();
    const isLogin = document.getElementById('modal-title').textContent === 'Login';
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const email = isLogin ? null : document.getElementById('email').value;
    const masterPassword = isLogin ? null : document.getElementById('master-password').value;

    try {
      const endpoint = isLogin ? '/api/auth/login' : '/api/auth/register';
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, email, masterPassword })
      });

      if (response.ok) {
        const data = await response.json();
        this.currentUser = data.user;
        this.token = data.token;
        localStorage.setItem('authToken', data.token);
        
        if (!isLogin && data.keyPair) {
          this.currentKeyPair = data.keyPair;
          this.displayPublicKey(data.keyPair.publicKey);
        }
        
        this.updateUIAfterLogin();
        this.closeAuthModal();
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Authentication failed');
      }
    } catch (error) {
      this.logStatus(`Authentication error: ${error.message}`, 'error');
    }
  }

  updateUIAfterLogin() {
    document.getElementById('auth-section').innerHTML = `
      <span>Welcome, ${this.currentUser.username}</span>
      <button id="logout-btn">Logout</button>
    `;
    document.getElementById('logout-btn').addEventListener('click', () => this.logout());
  }

  logout() {
    this.currentUser = null;
    this.currentKeyPair = null;
    this.token = null;
    localStorage.removeItem('authToken');
    document.getElementById('auth-section').innerHTML = `
      <button id="login-btn">Login</button>
      <button id="register-btn">Register</button>
    `;
    document.getElementById('public-key-display').innerHTML = '';
    document.getElementById('file-info').innerHTML = '';
    document.getElementById('download-link').style.display = 'none';
    this.initEventListeners();
  }

  async generateKeyPair() {
    if (!this.currentUser) {
      this.logStatus('Please login first', 'error');
      return;
    }

    const masterPassword = prompt('Enter your master password for key encryption:');
    if (!masterPassword) return;

    try {
      const response = await fetch('/api/kms/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({ masterPassword })
      });

      if (response.ok) {
        const data = await response.json();
        this.currentKeyPair = data;
        this.displayPublicKey(data.publicKey);
        this.logStatus('New key pair generated successfully', 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Key generation failed');
      }
    } catch (error) {
      this.logStatus(`Key generation error: ${error.message}`, 'error');
    }
  }

  async loadUserKeyPair() {
    try {
      const response = await fetch('/api/kms/keys', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${this.token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        if (data.publicKey) {
          this.currentKeyPair = data;
          this.displayPublicKey(data.publicKey);
        }
      }
    } catch (error) {
      this.logStatus(`Error loading key pair: ${error.message}`, 'error');
    }
  }

  displayPublicKey(publicKey) {
    const display = document.getElementById('public-key-display');
    display.innerHTML = `
      <h3>Your Public Key</h3>
      <textarea readonly>${publicKey}</textarea>
      <p>Share this key with others to receive encrypted files</p>
    `;
  }

  handleFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;

    // Kiểm tra định dạng file
    const allowedExtensions = ['txt', 'csv', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'odt', 'ods', 'bmp', 'jpg', 'jpeg', 'png', 'gif'];
    const fileExtension = file.name.split('.').pop().toLowerCase();
    
    if (!allowedExtensions.includes(fileExtension)) {
      this.logStatus('File type not supported', 'error');
      return;
    }

    this.fileToProcess = file;
    document.getElementById('file-info').innerHTML = `
      <p>Selected file: ${file.name}</p>
      <p>Size: ${(file.size / 1024).toFixed(2)} KB</p>
      <p>Type: ${file.type || 'Unknown'}</p>
    `;
    this.logStatus(`File "${file.name}" selected`, 'info');
  }

  async encryptFile() {
    if (!this.fileToProcess) {
      this.logStatus('No file selected', 'error');
      return;
    }

    if (!this.currentKeyPair) {
      this.logStatus('No key pair available', 'error');
      return;
    }

    this.logStatus('Encrypting file...', 'info');

    try {
      // Đọc file dưới dạng ArrayBuffer
      const fileData = await this.readFileAsArrayBuffer(this.fileToProcess);

      // Chuyển đổi ArrayBuffer sang Base64 để truyền qua JSON
      const base64Data = this.arrayBufferToBase64(fileData);

      // Gửi lên server để mã hóa
      const response = await fetch('/api/crypto/encrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({
          fileData: base64Data,
          fileName: this.fileToProcess.name,
          fileType: this.fileToProcess.type,
          keyPairId: this.currentKeyPair.id
        })
      });

      if (response.ok) {
        const data = await response.json();
        this.createDownloadLink(data.encryptedData, `encrypted_${this.fileToProcess.name}`, 'application/octet-stream');
        this.logStatus('File encrypted successfully', 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Encryption failed');
      }
    } catch (error) {
      this.logStatus(`Encryption error: ${error.message}`, 'error');
    }
  }

  async decryptFile() {
    if (!this.fileToProcess) {
      this.logStatus('No file selected', 'error');
      return;
    }

    if (!this.currentKeyPair) {
      this.logStatus('No key pair available', 'error');
      return;
    }

    const masterPassword = prompt('Enter your master password to decrypt:');
    if (!masterPassword) return;

    this.logStatus('Decrypting file...', 'info');

    try {
      // Đọc file dưới dạng ArrayBuffer
      const fileData = await this.readFileAsArrayBuffer(this.fileToProcess);

      // Chuyển đổi ArrayBuffer sang Base64
      const base64Data = this.arrayBufferToBase64(fileData);

      // Gửi lên server để giải mã
      const response = await fetch('/api/crypto/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.token}`
        },
        body: JSON.stringify({
          encryptedData: base64Data,
          fileName: this.fileToProcess.name,
          keyPairId: this.currentKeyPair.id,
          masterPassword
        })
      });

      if (response.ok) {
        const data = await response.json();
        
        // Xác định MIME type từ tên file
        let mimeType = 'application/octet-stream';
        const extension = this.fileToProcess.name.split('.').pop().toLowerCase();
        const extensionToMime = {
          'txt': 'text/plain',
          'csv': 'text/csv',
          'doc': 'application/msword',
          'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
          'xls': 'application/vnd.ms-excel',
          'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
          'ppt': 'application/vnd.ms-powerpoint',
          'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
          'pdf': 'application/pdf',
          'odt': 'application/vnd.oasis.opendocument.text',
          'ods': 'application/vnd.oasis.opendocument.spreadsheet',
          'bmp': 'image/bmp',
          'jpg': 'image/jpeg',
          'jpeg': 'image/jpeg',
          'png': 'image/png',
          'gif': 'image/gif'
        };

        if (extensionToMime[extension]) {
          mimeType = extensionToMime[extension];
        }

        this.createDownloadLink(data.decryptedData, `decrypted_${this.fileToProcess.name}`, mimeType);
        this.logStatus('File decrypted successfully', 'success');
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Decryption failed');
      }
    } catch (error) {
      this.logStatus(`Decryption error: ${error.message}`, 'error');
    }
  }

  readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = reject;
      reader.readAsArrayBuffer(file);
    });
  }

  arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  createDownloadLink(base64Data, fileName, mimeType) {
    const link = document.getElementById('download-link');
    const byteString = atob(base64Data);
    const arrayBuffer = new ArrayBuffer(byteString.length);
    const uint8Array = new Uint8Array(arrayBuffer);
    
    for (let i = 0; i < byteString.length; i++) {
      uint8Array[i] = byteString.charCodeAt(i);
    }
    
    const blob = new Blob([arrayBuffer], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    link.href = url;
    link.download = fileName;
    link.style.display = 'block';
    link.textContent = `Download ${fileName}`;
  }

  logStatus(message, type = 'info') {
    const logElement = document.getElementById('status-log');
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logElement.prepend(entry);
  }
}

// Khởi tạo ứng dụng khi trang tải xong
document.addEventListener('DOMContentLoaded', () => {
  new EncryptionApp();
});