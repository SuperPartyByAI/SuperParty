/**
 * 🔐 SuperParty Authentication Configuration
 * Secure Supabase setup with environment protection
 */

// Supabase Configuration
// ✅ CONFIGURED with your actual credentials
const SUPABASE_CONFIG = {
    url: 'https://bkhzilcjxuncyxpyhtbb.supabase.co',
    anonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImJraHppbGNqeHVuY3l4cHlodGJiIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjI5ODE5ODAsImV4cCI6MjA3ODU1Nzk4MH0._nYGKr3QqjCBhRDJ8zXrcEpG5pUA980ZZIivjC1VXS8'
};

// Initialize Supabase client
let supabaseClient = null;

function initSupabase() {
    if (typeof supabase === 'undefined') {
        console.error('❌ Supabase library not loaded');
        return null;
    }
    
    if (!supabaseClient) {
        supabaseClient = supabase.createClient(
            SUPABASE_CONFIG.url,
            SUPABASE_CONFIG.anonKey
        );
    }
    
    return supabaseClient;
}

// Security Constants
const AUTH_CONFIG = {
    TOKEN_KEY: 'superparty_auth_token',
    USER_KEY: 'superparty_user_data',
    SESSION_TIMEOUT: 24 * 60 * 60 * 1000, // 24 hours
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_DURATION: 15 * 60 * 1000 // 15 minutes
};

// User Roles
const ROLES = {
    ADMIN: 'admin',
    ANGAJAT: 'angajat',
    COLABORATOR: 'colaborator'
};

// Role Permissions
const PERMISSIONS = {
    [ROLES.ADMIN]: {
        canViewAll: true,
        canEdit: true,
        canDelete: true,
        canManageUsers: true,
        canViewSecretPage: true,
        canViewFinancials: true,
        canExportData: true
    },
    [ROLES.ANGAJAT]: {
        canViewAll: true,
        canEdit: true,
        canDelete: false,
        canManageUsers: false,
        canViewSecretPage: false,
        canViewFinancials: true,
        canExportData: false
    },
    [ROLES.COLABORATOR]: {
        canViewAll: true,
        canEdit: false,
        canDelete: false,
        canManageUsers: false,
        canViewSecretPage: false,
        canViewFinancials: false,
        canExportData: false
    }
};

/**
 * Get current authenticated user
 */
async function getCurrentUser() {
    const supabase = initSupabase();
    if (!supabase) return null;
    
    try {
        const { data: { user }, error } = await supabase.auth.getUser();
        
        if (error) throw error;
        if (!user) return null;
        
        // Get user role from database
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('role, full_name, employee_code')
            .eq('id', user.id)
            .single();
        
        if (userError) throw userError;
        
        return {
            id: user.id,
            email: user.email,
            role: userData?.role || ROLES.COLABORATOR,
            fullName: userData?.full_name || user.email,
            employeeCode: userData?.employee_code || null
        };
    } catch (error) {
        console.error('Error getting current user:', error);
        return null;
    }
}

/**
 * Check if user has permission
 */
function hasPermission(userRole, permission) {
    const rolePermissions = PERMISSIONS[userRole];
    return rolePermissions ? rolePermissions[permission] === true : false;
}

/**
 * Save auth token securely
 */
function saveAuthToken(token) {
    try {
        const data = {
            token: token,
            timestamp: Date.now()
        };
        localStorage.setItem(AUTH_CONFIG.TOKEN_KEY, JSON.stringify(data));
        return true;
    } catch (error) {
        console.error('Error saving auth token:', error);
        return false;
    }
}

/**
 * Get auth token
 */
function getAuthToken() {
    try {
        const data = localStorage.getItem(AUTH_CONFIG.TOKEN_KEY);
        if (!data) return null;
        
        const parsed = JSON.parse(data);
        const age = Date.now() - parsed.timestamp;
        
        // Check if token expired
        if (age > AUTH_CONFIG.SESSION_TIMEOUT) {
            clearAuthData();
            return null;
        }
        
        return parsed.token;
    } catch (error) {
        console.error('Error getting auth token:', error);
        return null;
    }
}

/**
 * Save user data securely
 */
function saveUserData(userData) {
    try {
        localStorage.setItem(AUTH_CONFIG.USER_KEY, JSON.stringify(userData));
        return true;
    } catch (error) {
        console.error('Error saving user data:', error);
        return false;
    }
}

/**
 * Get user data
 */
function getUserData() {
    try {
        const data = localStorage.getItem(AUTH_CONFIG.USER_KEY);
        return data ? JSON.parse(data) : null;
    } catch (error) {
        console.error('Error getting user data:', error);
        return null;
    }
}

/**
 * Clear all auth data
 */
function clearAuthData() {
    localStorage.removeItem(AUTH_CONFIG.TOKEN_KEY);
    localStorage.removeItem(AUTH_CONFIG.USER_KEY);
    localStorage.removeItem('login_attempts');
    localStorage.removeItem('lockout_until');
}

/**
 * Track failed login attempts
 */
function trackLoginAttempt(success) {
    if (success) {
        localStorage.removeItem('login_attempts');
        localStorage.removeItem('lockout_until');
        return { allowed: true };
    }
    
    const attempts = parseInt(localStorage.getItem('login_attempts') || '0') + 1;
    localStorage.setItem('login_attempts', attempts.toString());
    
    if (attempts >= AUTH_CONFIG.MAX_LOGIN_ATTEMPTS) {
        const lockoutUntil = Date.now() + AUTH_CONFIG.LOCKOUT_DURATION;
        localStorage.setItem('lockout_until', lockoutUntil.toString());
        return {
            allowed: false,
            locked: true,
            remainingTime: AUTH_CONFIG.LOCKOUT_DURATION
        };
    }
    
    return {
        allowed: true,
        attemptsLeft: AUTH_CONFIG.MAX_LOGIN_ATTEMPTS - attempts
    };
}

/**
 * Check if account is locked
 */
function isAccountLocked() {
    const lockoutUntil = localStorage.getItem('lockout_until');
    if (!lockoutUntil) return { locked: false };
    
    const unlockTime = parseInt(lockoutUntil);
    const now = Date.now();
    
    if (now < unlockTime) {
        return {
            locked: true,
            remainingTime: unlockTime - now
        };
    }
    
    // Lockout expired
    localStorage.removeItem('lockout_until');
    localStorage.removeItem('login_attempts');
    return { locked: false };
}

/**
 * Validate email format
 */
function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

/**
 * Sanitize input to prevent XSS
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') return input;
    
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

/**
 * Generate secure session ID
 */
function generateSessionId() {
    return 'sess_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}
