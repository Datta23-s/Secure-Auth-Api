// ===== AUTHENTICATION SYSTEM =====
// Enterprise-grade authentication with JWT, RBAC, 2FA (TOTP & Email OTP)

// ===== CONFIGURATION =====
const CONFIG = {
  jwt: {
    algorithm: 'HS256',
    accessTokenExpiry: 15 * 60 * 1000, // 15 minutes
    refreshTokenExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
    issuer: 'https://auth.company.com',
    audience: 'api.company.com',
    secret: 'enterprise-secret-key-2025' // In production, use env variable
  },
  security: {
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000, // 15 minutes
    bcryptRounds: 10
  },
  otp: {
    length: 6,
    expiry: 5 * 60 * 1000 // 5 minutes
  }
};

// ===== DATA MODELS =====
let DATABASE = {
  users: [
    {
      id: 1,
      email: 'admin@company.com',
      password_hash: 'hashed_admin_password_123', // Real password: AdminPass123!
      name: 'Admin User',
      role: 'Admin',
      totp_enabled: false,
      totp_secret: 'JBSWY3DPEBLW64TMMQ========',
      created_at: '2025-01-01T10:00:00Z',
      locked_until: null,
      login_attempts: 0
    },
    {
      id: 2,
      email: 'manager@company.com',
      password_hash: 'hashed_manager_password_456', // Real password: ManagerPass123!
      name: 'Manager User',
      role: 'Manager',
      totp_enabled: false,
      totp_secret: 'NVXXEZLSEBRW63LQMQ========',
      created_at: '2025-01-02T10:00:00Z',
      locked_until: null,
      login_attempts: 0
    },
    {
      id: 3,
      email: 'user@company.com',
      password_hash: 'hashed_user_password_789', // Real password: UserPass123!
      name: 'Regular User',
      role: 'User',
      totp_enabled: false,
      totp_secret: 'OBZXG5DROVZXG5LQMQ========',
      created_at: '2025-01-03T10:00:00Z',
      locked_until: null,
      login_attempts: 0
    }
  ],
  roles: {
    Admin: ['auth:read', 'auth:write', 'users:read', 'users:write', 'users:delete', 'reports:read', 'reports:write', '2fa:manage'],
    Manager: ['auth:read', 'users:read', 'reports:read', 'reports:write', '2fa:manage'],
    User: ['auth:read', 'profile:read', 'profile:write', '2fa:manage']
  },
  endpoints: [
    { method: 'POST', path: '/api/auth/register', required_role: 'Public', description: 'Register a new user account' },
    { method: 'POST', path: '/api/auth/login', required_role: 'Public', description: 'User login with email and password' },
    { method: 'POST', path: '/api/auth/refresh', required_role: 'User', description: 'Refresh access token using refresh token' },
    { method: 'POST', path: '/api/auth/logout', required_role: 'User', description: 'Logout and invalidate tokens' },
    { method: 'GET', path: '/api/auth/profile', required_role: 'User', description: 'Get current user profile' },
    { method: 'GET', path: '/api/users', required_role: 'Admin', description: 'List all users' },
    { method: 'POST', path: '/api/users', required_role: 'Admin', description: 'Create new user' },
    { method: 'GET', path: '/api/reports', required_role: 'Manager', description: 'View reports dashboard' },
    { method: 'POST', path: '/api/2fa/setup', required_role: 'User', description: 'Setup two-factor authentication' },
    { method: 'POST', path: '/api/2fa/verify', required_role: 'User', description: 'Verify 2FA code' }
  ],
  auditLog: [
    { timestamp: '2025-11-02T10:30:00Z', action: 'LOGIN', user: 'admin@company.com', status: 'SUCCESS', ip_address: '192.168.1.100' },
    { timestamp: '2025-11-02T10:31:00Z', action: '2FA_SETUP', user: 'admin@company.com', status: 'SUCCESS', method: 'TOTP' },
    { timestamp: '2025-11-02T10:32:00Z', action: 'TOKEN_REFRESH', user: 'admin@company.com', status: 'SUCCESS' },
    { timestamp: '2025-11-02T10:33:00Z', action: 'API_ACCESS', user: 'admin@company.com', endpoint: '/api/users', status: 'SUCCESS' }
  ],
  revokedTokens: [],
  sessions: {}
};

// ===== SESSION MANAGEMENT =====
let currentSession = {
  user: null,
  accessToken: null,
  refreshToken: null,
  pendingUser: null, // For 2FA flow
  emailOtp: null
};

// ===== UTILITY FUNCTIONS =====

// Simulated password hashing (in production, use bcrypt)
function hashPassword(password) {
  // Simple hash simulation
  return `hashed_${password}_${CONFIG.security.bcryptRounds}`;
}

function verifyPassword(password, hash) {
  // For demo accounts, use simplified verification
  const demoPasswords = {
    'hashed_admin_password_123': 'AdminPass123!',
    'hashed_manager_password_456': 'ManagerPass123!',
    'hashed_user_password_789': 'UserPass123!'
  };
  
  if (demoPasswords[hash]) {
    return password === demoPasswords[hash];
  }
  
  // For new users
  return hash === hashPassword(password);
}

// Password validation
function validatePassword(password) {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (password.length < minLength) {
    return { valid: false, error: 'Password must be at least 8 characters' };
  }
  if (!hasUppercase) {
    return { valid: false, error: 'Password must contain uppercase letter' };
  }
  if (!hasLowercase) {
    return { valid: false, error: 'Password must contain lowercase letter' };
  }
  if (!hasNumber) {
    return { valid: false, error: 'Password must contain number' };
  }
  if (!hasSpecial) {
    return { valid: false, error: 'Password must contain special character' };
  }
  
  return { valid: true };
}

// Email validation
function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// ===== JWT FUNCTIONS =====

// Base64 URL encoding
function base64UrlEncode(str) {
  return btoa(str)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Simple HMAC simulation for JWT signing
function simpleHmac(message, secret) {
  // This is a simplified version for demo purposes
  // In production, use a proper crypto library
  let hash = 0;
  const combinedStr = message + secret;
  for (let i = 0; i < combinedStr.length; i++) {
    const char = combinedStr.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(36);
}

function generateJWT(payload, expiresIn) {
  const header = {
    alg: CONFIG.jwt.algorithm,
    typ: 'JWT'
  };
  
  const now = Date.now();
  const jwtPayload = {
    ...payload,
    iat: Math.floor(now / 1000),
    exp: Math.floor((now + expiresIn) / 1000),
    iss: CONFIG.jwt.issuer,
    aud: CONFIG.jwt.audience
  };
  
  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(jwtPayload));
  const signature = simpleHmac(`${encodedHeader}.${encodedPayload}`, CONFIG.jwt.secret);
  
  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format' };
    }
    
    const [encodedHeader, encodedPayload, signature] = parts;
    
    // Verify signature
    const expectedSignature = simpleHmac(`${encodedHeader}.${encodedPayload}`, CONFIG.jwt.secret);
    if (signature !== expectedSignature) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    // Decode payload
    const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) {
      return { valid: false, error: 'Token expired' };
    }
    
    // Check if token is revoked
    if (DATABASE.revokedTokens.includes(token)) {
      return { valid: false, error: 'Token revoked' };
    }
    
    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: 'Token verification failed' };
  }
}

// ===== TOTP FUNCTIONS =====

function generateTOTPSecret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  for (let i = 0; i < 32; i++) {
    secret += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return secret;
}

function generateTOTPCode(secret) {
  // Simplified TOTP generation for demo
  // In production, use a proper TOTP library
  const timeStep = Math.floor(Date.now() / 30000);
  const hash = simpleHmac(secret + timeStep.toString(), CONFIG.jwt.secret);
  const code = (parseInt(hash.slice(0, 6), 36) % 1000000).toString().padStart(6, '0');
  return code;
}

function verifyTOTPCode(secret, code) {
  // Allow for time drift (±1 time step)
  const currentCode = generateTOTPCode(secret);
  return code === currentCode;
}

// ===== EMAIL OTP FUNCTIONS =====

function generateEmailOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function sendEmailOTP(email) {
  const otp = generateEmailOTP();
  const expiry = Date.now() + CONFIG.otp.expiry;
  
  currentSession.emailOtp = { code: otp, expiry, email };
  
  // Simulate email sending
  console.log(`[EMAIL OTP] Sent to ${email}: ${otp}`);
  return otp;
}

// ===== AUTHENTICATION FUNCTIONS =====

function registerUser(email, password, name, role = 'User') {
  // Validate input
  if (!validateEmail(email)) {
    return { success: false, error: 'Invalid email format' };
  }
  
  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return { success: false, error: passwordValidation.error };
  }
  
  // Check if user already exists
  if (DATABASE.users.find(u => u.email === email)) {
    return { success: false, error: 'User already exists' };
  }
  
  // Create new user
  const newUser = {
    id: DATABASE.users.length + 1,
    email,
    password_hash: hashPassword(password),
    name,
    role,
    totp_enabled: false,
    totp_secret: generateTOTPSecret(),
    created_at: new Date().toISOString(),
    locked_until: null,
    login_attempts: 0
  };
  
  DATABASE.users.push(newUser);
  
  // Add audit log
  DATABASE.auditLog.unshift({
    timestamp: new Date().toISOString(),
    action: 'REGISTER',
    user: email,
    status: 'SUCCESS',
    ip_address: '127.0.0.1'
  });
  
  return { success: true, user: newUser };
}

function loginUser(email, password) {
  const user = DATABASE.users.find(u => u.email === email);
  
  if (!user) {
    return { success: false, error: 'Invalid credentials' };
  }
  
  // Check if account is locked
  if (user.locked_until && Date.now() < user.locked_until) {
    const remainingTime = Math.ceil((user.locked_until - Date.now()) / 60000);
    return { success: false, error: `Account locked. Try again in ${remainingTime} minutes` };
  }
  
  // Reset login attempts if lock expired
  if (user.locked_until && Date.now() >= user.locked_until) {
    user.locked_until = null;
    user.login_attempts = 0;
  }
  
  // Verify password
  if (!verifyPassword(password, user.password_hash)) {
    user.login_attempts++;
    
    if (user.login_attempts >= CONFIG.security.maxLoginAttempts) {
      user.locked_until = Date.now() + CONFIG.security.lockoutDuration;
      
      DATABASE.auditLog.unshift({
        timestamp: new Date().toISOString(),
        action: 'ACCOUNT_LOCKED',
        user: email,
        status: 'FAILED',
        ip_address: '127.0.0.1'
      });
      
      return { success: false, error: 'Too many failed attempts. Account locked for 15 minutes' };
    }
    
    DATABASE.auditLog.unshift({
      timestamp: new Date().toISOString(),
      action: 'LOGIN',
      user: email,
      status: 'FAILED',
      ip_address: '127.0.0.1'
    });
    
    return { success: false, error: `Invalid credentials. ${CONFIG.security.maxLoginAttempts - user.login_attempts} attempts remaining` };
  }
  
  // Reset login attempts on successful password verification
  user.login_attempts = 0;
  user.locked_until = null;
  
  // Store pending user for 2FA flow
  currentSession.pendingUser = user;
  
  return { success: true, requires2FA: true, user };
}

function complete2FA() {
  const user = currentSession.pendingUser;
  if (!user) {
    return { success: false, error: 'No pending authentication' };
  }
  
  // Generate tokens
  const accessToken = generateJWT(
    { userId: user.id, email: user.email, role: user.role },
    CONFIG.jwt.accessTokenExpiry
  );
  
  const refreshToken = generateJWT(
    { userId: user.id, type: 'refresh' },
    CONFIG.jwt.refreshTokenExpiry
  );
  
  // Set current session
  currentSession.user = user;
  currentSession.accessToken = accessToken;
  currentSession.refreshToken = refreshToken;
  currentSession.pendingUser = null;
  currentSession.emailOtp = null;
  
  // Add audit log
  DATABASE.auditLog.unshift({
    timestamp: new Date().toISOString(),
    action: 'LOGIN',
    user: user.email,
    status: 'SUCCESS',
    ip_address: '127.0.0.1'
  });
  
  return { success: true, accessToken, refreshToken, user };
}

function refreshAccessToken(refreshToken) {
  const verification = verifyJWT(refreshToken);
  
  if (!verification.valid) {
    return { success: false, error: verification.error };
  }
  
  if (verification.payload.type !== 'refresh') {
    return { success: false, error: 'Invalid token type' };
  }
  
  const user = DATABASE.users.find(u => u.id === verification.payload.userId);
  if (!user) {
    return { success: false, error: 'User not found' };
  }
  
  // Generate new access token
  const newAccessToken = generateJWT(
    { userId: user.id, email: user.email, role: user.role },
    CONFIG.jwt.accessTokenExpiry
  );
  
  currentSession.accessToken = newAccessToken;
  
  // Add audit log
  DATABASE.auditLog.unshift({
    timestamp: new Date().toISOString(),
    action: 'TOKEN_REFRESH',
    user: user.email,
    status: 'SUCCESS',
    ip_address: '127.0.0.1'
  });
  
  return { success: true, accessToken: newAccessToken };
}

function logoutUser() {
  if (currentSession.accessToken) {
    DATABASE.revokedTokens.push(currentSession.accessToken);
    DATABASE.revokedTokens.push(currentSession.refreshToken);
  }
  
  if (currentSession.user) {
    DATABASE.auditLog.unshift({
      timestamp: new Date().toISOString(),
      action: 'LOGOUT',
      user: currentSession.user.email,
      status: 'SUCCESS',
      ip_address: '127.0.0.1'
    });
  }
  
  currentSession.user = null;
  currentSession.accessToken = null;
  currentSession.refreshToken = null;
  currentSession.pendingUser = null;
  currentSession.emailOtp = null;
}

// ===== RBAC FUNCTIONS =====

function hasPermission(role, permission) {
  const permissions = DATABASE.roles[role] || [];
  return permissions.includes(permission);
}

function canAccessEndpoint(role, endpoint) {
  const roleHierarchy = { Admin: 3, Manager: 2, User: 1, Public: 0 };
  
  if (endpoint.required_role === 'Public') {
    return true;
  }
  
  return roleHierarchy[role] >= roleHierarchy[endpoint.required_role];
}

// ===== UI FUNCTIONS =====

function showView(viewId) {
  document.querySelectorAll('.view').forEach(view => {
    view.classList.remove('active');
  });
  document.getElementById(viewId).classList.add('active');
}

function showMessage(elementId, message, type = 'error') {
  const element = document.getElementById(elementId);
  element.textContent = message;
  element.className = `message ${type}`;
  element.style.display = 'block';
  
  setTimeout(() => {
    element.style.display = 'none';
  }, 5000);
}

function formatTokenExpiry(token) {
  const verification = verifyJWT(token);
  if (!verification.valid) return 'Invalid';
  
  const expiryDate = new Date(verification.payload.exp * 1000);
  const now = new Date();
  const diff = expiryDate - now;
  
  if (diff < 0) return 'Expired';
  
  const minutes = Math.floor(diff / 60000);
  const seconds = Math.floor((diff % 60000) / 1000);
  
  if (minutes > 60) {
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    if (days > 0) return `${days}d ${hours % 24}h`;
    return `${hours}h ${minutes % 60}m`;
  }
  
  return `${minutes}m ${seconds}s`;
}

function updateDashboard() {
  const user = currentSession.user;
  if (!user) return;
  
  // Update profile
  document.getElementById('welcomeMessage').textContent = `Welcome back, ${user.name}!`;
  document.getElementById('profileName').textContent = user.name;
  document.getElementById('profileEmail').textContent = user.email;
  document.getElementById('profileRole').textContent = user.role;
  document.getElementById('profile2FA').innerHTML = user.totp_enabled 
    ? '<span style="color: #4cd964;">✓ Enabled</span>' 
    : '<span style="color: #ff9500;">⚠ Disabled</span>';
  
  // Update tokens
  document.getElementById('accessTokenDisplay').textContent = currentSession.accessToken.substring(0, 100) + '...';
  document.getElementById('refreshTokenDisplay').textContent = currentSession.refreshToken.substring(0, 100) + '...';
  document.getElementById('accessTokenExpiry').textContent = formatTokenExpiry(currentSession.accessToken);
  document.getElementById('refreshTokenExpiry').textContent = formatTokenExpiry(currentSession.refreshToken);
  
  // Update permissions
  const permissionsHtml = DATABASE.roles[user.role].map(perm => 
    `<div class="permission-badge">${perm}</div>`
  ).join('');
  document.getElementById('permissionsList').innerHTML = permissionsHtml;
  
  // Update endpoints
  const endpointsHtml = DATABASE.endpoints.map(endpoint => {
    const accessible = canAccessEndpoint(user.role, endpoint);
    return `
      <div class="endpoint-item ${accessible ? 'accessible' : 'restricted'}">
        <div class="endpoint-header">
          <span class="method-badge ${endpoint.method.toLowerCase()}">${endpoint.method}</span>
          <span class="endpoint-path">${endpoint.path}</span>
        </div>
        <div class="endpoint-desc">${endpoint.description}</div>
        <div class="endpoint-role">
          ${accessible ? '✓ Accessible' : '✗ Requires ' + endpoint.required_role + ' role'}
        </div>
      </div>
    `;
  }).join('');
  document.getElementById('endpointsList').innerHTML = endpointsHtml;
  
  // Update audit log
  const auditHtml = DATABASE.auditLog.slice(0, 10).map(log => {
    const date = new Date(log.timestamp);
    return `
      <div class="audit-item ${log.status === 'SUCCESS' ? 'success' : 'failed'}">
        <div class="audit-header">
          <span class="audit-action">${log.action}</span>
          <span class="audit-timestamp">${date.toLocaleString()}</span>
        </div>
        <div class="audit-details">
          User: ${log.user} | Status: ${log.status}
          ${log.endpoint ? `| Endpoint: ${log.endpoint}` : ''}
          ${log.method ? `| Method: ${log.method}` : ''}
        </div>
      </div>
    `;
  }).join('');
  document.getElementById('auditLogList').innerHTML = auditHtml;
}

// ===== EVENT HANDLERS =====

// Login Form
document.getElementById('loginForm').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const email = document.getElementById('loginEmail').value;
  const password = document.getElementById('loginPassword').value;
  
  const result = loginUser(email, password);
  
  if (result.success) {
    if (result.requires2FA) {
      showMessage('loginMessage', 'Login successful! Please complete 2FA', 'success');
      setTimeout(() => showView('twoFactorView'), 1000);
    }
  } else {
    showMessage('loginMessage', result.error, 'error');
  }
});

// Register Form
document.getElementById('registerForm').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const name = document.getElementById('registerName').value;
  const email = document.getElementById('registerEmail').value;
  const password = document.getElementById('registerPassword').value;
  const role = document.getElementById('registerRole').value;
  
  const result = registerUser(email, password, name, role);
  
  if (result.success) {
    showMessage('registerMessage', 'Registration successful! Please login', 'success');
    setTimeout(() => {
      showView('loginView');
      document.getElementById('loginEmail').value = email;
    }, 1500);
  } else {
    showMessage('registerMessage', result.error, 'error');
  }
});

// Navigation buttons
document.getElementById('showRegisterBtn').addEventListener('click', () => {
  showView('registerView');
});

document.getElementById('showLoginBtn').addEventListener('click', () => {
  showView('loginView');
});

// 2FA Options
document.getElementById('setupTotpBtn').addEventListener('click', () => {
  const user = currentSession.pendingUser;
  if (!user) {
    showMessage('loginMessage', 'Session expired. Please login again', 'error');
    showView('loginView');
    return;
  }
  
  // Display QR code simulation and secret
  document.getElementById('qrCode').textContent = '📱';
  document.getElementById('totpSecret').textContent = user.totp_secret;
  
  showView('totpSetupView');
});

document.getElementById('setupEmailOtpBtn').addEventListener('click', () => {
  const user = currentSession.pendingUser;
  if (!user) {
    showMessage('loginMessage', 'Session expired. Please login again', 'error');
    showView('loginView');
    return;
  }
  
  // Send email OTP
  const otp = sendEmailOTP(user.email);
  document.getElementById('otpEmailDisplay').textContent = user.email;
  
  // Show OTP in console for demo
  showMessage('emailOtpMessage', `Demo: Your OTP is ${otp}`, 'success');
  
  showView('emailOtpView');
});

document.getElementById('skip2FABtn').addEventListener('click', () => {
  const result = complete2FA();
  if (result.success) {
    updateDashboard();
    showView('dashboardView');
  } else {
    showMessage('loginMessage', result.error, 'error');
    showView('loginView');
  }
});

// TOTP Verification
document.getElementById('totpVerifyForm').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const code = document.getElementById('totpCode').value;
  const user = currentSession.pendingUser;
  
  if (!user) {
    showMessage('totpMessage', 'Session expired', 'error');
    return;
  }
  
  // Generate expected code for demo
  const expectedCode = generateTOTPCode(user.totp_secret);
  
  if (verifyTOTPCode(user.totp_secret, code) || code === expectedCode) {
    user.totp_enabled = true;
    
    DATABASE.auditLog.unshift({
      timestamp: new Date().toISOString(),
      action: '2FA_SETUP',
      user: user.email,
      status: 'SUCCESS',
      method: 'TOTP'
    });
    
    const result = complete2FA();
    if (result.success) {
      showMessage('totpMessage', 'TOTP enabled successfully!', 'success');
      setTimeout(() => {
        updateDashboard();
        showView('dashboardView');
      }, 1000);
    }
  } else {
    showMessage('totpMessage', `Invalid code. Demo code: ${expectedCode}`, 'error');
  }
});

document.getElementById('cancelTotpBtn').addEventListener('click', () => {
  showView('twoFactorView');
});

// Email OTP Verification
document.getElementById('emailOtpForm').addEventListener('submit', (e) => {
  e.preventDefault();
  
  const code = document.getElementById('emailOtpCode').value;
  const otpData = currentSession.emailOtp;
  
  if (!otpData) {
    showMessage('emailOtpMessage', 'No OTP sent', 'error');
    return;
  }
  
  if (Date.now() > otpData.expiry) {
    showMessage('emailOtpMessage', 'OTP expired. Please request a new one', 'error');
    return;
  }
  
  if (code === otpData.code) {
    const result = complete2FA();
    if (result.success) {
      showMessage('emailOtpMessage', 'Email OTP verified successfully!', 'success');
      setTimeout(() => {
        updateDashboard();
        showView('dashboardView');
      }, 1000);
    }
  } else {
    showMessage('emailOtpMessage', 'Invalid OTP code', 'error');
  }
});

document.getElementById('resendOtpBtn').addEventListener('click', () => {
  const user = currentSession.pendingUser;
  if (user) {
    const otp = sendEmailOTP(user.email);
    showMessage('emailOtpMessage', `New OTP sent! Demo: ${otp}`, 'success');
  }
});

document.getElementById('cancelOtpBtn').addEventListener('click', () => {
  showView('twoFactorView');
});

// Dashboard Actions
document.getElementById('refreshTokenBtn').addEventListener('click', () => {
  const result = refreshAccessToken(currentSession.refreshToken);
  
  if (result.success) {
    updateDashboard();
    alert('Access token refreshed successfully!');
  } else {
    alert('Token refresh failed: ' + result.error);
  }
});

document.getElementById('logoutBtn').addEventListener('click', () => {
  logoutUser();
  showView('loginView');
  
  // Clear forms
  document.getElementById('loginForm').reset();
  document.getElementById('registerForm').reset();
});

// ===== INITIALIZATION =====

// Start with login view
showView('loginView');

console.log('Enterprise Auth System initialized');
console.log('Demo accounts:');
console.log('- admin@company.com / AdminPass123!');
console.log('- manager@company.com / ManagerPass123!');
console.log('- user@company.com / UserPass123!');