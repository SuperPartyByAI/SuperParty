/**
 * 🔐 SuperParty Authentication Module
 * Complete authentication system with Supabase
 */

/**
 * Login user with email and password
 */
async function loginUser(email, password) {
    // Validate inputs
    if (!email || !password) {
        return {
            success: false,
            error: 'Email și parolă sunt obligatorii'
        };
    }
    
    if (!validateEmail(email)) {
        return {
            success: false,
            error: 'Email invalid'
        };
    }
    
    // Check if account is locked
    const lockStatus = isAccountLocked();
    if (lockStatus.locked) {
        const minutes = Math.ceil(lockStatus.remainingTime / 60000);
        return {
            success: false,
            error: `Cont blocat. Încearcă din nou în ${minutes} minute.`,
            locked: true
        };
    }
    
    const supabase = initSupabase();
    if (!supabase) {
        return {
            success: false,
            error: 'Eroare de sistem. Contactează administratorul.'
        };
    }
    
    try {
        // Attempt login
        const { data, error } = await supabase.auth.signInWithPassword({
            email: email,
            password: password
        });
        
        if (error) {
            // Track failed attempt
            const attemptResult = trackLoginAttempt(false);
            
            if (attemptResult.locked) {
                return {
                    success: false,
                    error: 'Prea multe încercări eșuate. Cont blocat pentru 15 minute.',
                    locked: true
                };
            }
            
            return {
                success: false,
                error: 'Email sau parolă incorectă',
                attemptsLeft: attemptResult.attemptsLeft
            };
        }
        
        // Login successful
        trackLoginAttempt(true);
        
        // Get user role from database
        const { data: userData, error: userError } = await supabase
            .from('users')
            .select('role, full_name, employee_code')
            .eq('id', data.user.id)
            .single();
        
        if (userError) {
            console.error('Error fetching user data:', userError);
        }
        
        const user = {
            id: data.user.id,
            email: data.user.email,
            role: userData?.role || ROLES.COLABORATOR,
            fullName: userData?.full_name || data.user.email.split('@')[0],
            employeeCode: userData?.employee_code || null
        };
        
        // Save session
        saveAuthToken(data.session.access_token);
        saveUserData(user);
        
        // Log successful login
        await logSecurityEvent('login_success', user.id, {
            email: user.email,
            role: user.role
        });
        
        return {
            success: true,
            user: user
        };
        
    } catch (error) {
        console.error('Login error:', error);
        
        // Log failed login attempt
        await logSecurityEvent('login_failed', null, {
            email: email,
            error: error.message
        });
        
        return {
            success: false,
            error: 'Eroare la autentificare. Te rog încearcă din nou.'
        };
    }
}

/**
 * Register new user
 */
async function registerUser(email, password, fullName, employeeCode = null) {
    // Validate inputs
    if (!email || !password || !fullName) {
        return {
            success: false,
            error: 'Toate câmpurile sunt obligatorii'
        };
    }
    
    if (!validateEmail(email)) {
        return {
            success: false,
            error: 'Email invalid'
        };
    }
    
    if (password.length < 8) {
        return {
            success: false,
            error: 'Parola trebuie să aibă minimum 8 caractere'
        };
    }
    
    const supabase = initSupabase();
    if (!supabase) {
        return {
            success: false,
            error: 'Eroare de sistem. Contactează administratorul.'
        };
    }
    
    try {
        // Register with Supabase Auth
        const { data, error } = await supabase.auth.signUp({
            email: email,
            password: password
        });
        
        if (error) {
            if (error.message.includes('already registered')) {
                return {
                    success: false,
                    error: 'Acest email este deja înregistrat'
                };
            }
            throw error;
        }
        
        // Create user record in database
        const { error: insertError } = await supabase
            .from('users')
            .insert([{
                id: data.user.id,
                email: email,
                full_name: fullName,
                employee_code: employeeCode,
                role: ROLES.COLABORATOR, // Default role
                created_at: new Date().toISOString()
            }]);
        
        if (insertError) {
            console.error('Error creating user record:', insertError);
        }
        
        // Log registration
        await logSecurityEvent('user_registered', data.user.id, {
            email: email,
            fullName: fullName
        });
        
        return {
            success: true,
            message: 'Cont creat cu succes! Verifică emailul pentru confirmare.',
            requiresEmailVerification: true
        };
        
    } catch (error) {
        console.error('Registration error:', error);
        return {
            success: false,
            error: 'Eroare la înregistrare. Te rog încearcă din nou.'
        };
    }
}

/**
 * Logout user
 */
async function logoutUser() {
    const supabase = initSupabase();
    const user = getUserData();
    
    try {
        if (supabase) {
            await supabase.auth.signOut();
        }
        
        // Log logout
        if (user) {
            await logSecurityEvent('logout', user.id, {
                email: user.email
            });
        }
        
        // Clear local data
        clearAuthData();
        
        return { success: true };
        
    } catch (error) {
        console.error('Logout error:', error);
        
        // Clear local data anyway
        clearAuthData();
        
        return { success: true };
    }
}

/**
 * Check if user is authenticated
 */
async function isAuthenticated() {
    const token = getAuthToken();
    if (!token) return false;
    
    const supabase = initSupabase();
    if (!supabase) return false;
    
    try {
        const { data: { user }, error } = await supabase.auth.getUser();
        
        if (error || !user) {
            clearAuthData();
            return false;
        }
        
        return true;
        
    } catch (error) {
        console.error('Auth check error:', error);
        clearAuthData();
        return false;
    }
}

/**
 * Refresh session
 */
async function refreshSession() {
    const supabase = initSupabase();
    if (!supabase) return false;
    
    try {
        const { data, error } = await supabase.auth.refreshSession();
        
        if (error || !data.session) {
            clearAuthData();
            return false;
        }
        
        saveAuthToken(data.session.access_token);
        return true;
        
    } catch (error) {
        console.error('Session refresh error:', error);
        clearAuthData();
        return false;
    }
}

/**
 * Request password reset
 */
async function requestPasswordReset(email) {
    if (!email || !validateEmail(email)) {
        return {
            success: false,
            error: 'Email invalid'
        };
    }
    
    const supabase = initSupabase();
    if (!supabase) {
        return {
            success: false,
            error: 'Eroare de sistem'
        };
    }
    
    try {
        const { error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: window.location.origin + '/reset-password.html'
        });
        
        if (error) throw error;
        
        // Log password reset request
        await logSecurityEvent('password_reset_requested', null, {
            email: email
        });
        
        return {
            success: true,
            message: 'Verifică emailul pentru instrucțiuni de resetare parolă'
        };
        
    } catch (error) {
        console.error('Password reset error:', error);
        return {
            success: false,
            error: 'Eroare la trimiterea emailului. Te rog încearcă din nou.'
        };
    }
}

/**
 * Update password
 */
async function updatePassword(newPassword) {
    if (!newPassword || newPassword.length < 8) {
        return {
            success: false,
            error: 'Parola trebuie să aibă minimum 8 caractere'
        };
    }
    
    const supabase = initSupabase();
    if (!supabase) {
        return {
            success: false,
            error: 'Eroare de sistem'
        };
    }
    
    try {
        const { error } = await supabase.auth.updateUser({
            password: newPassword
        });
        
        if (error) throw error;
        
        const user = getUserData();
        if (user) {
            await logSecurityEvent('password_updated', user.id, {
                email: user.email
            });
        }
        
        return {
            success: true,
            message: 'Parola a fost actualizată cu succes'
        };
        
    } catch (error) {
        console.error('Password update error:', error);
        return {
            success: false,
            error: 'Eroare la actualizarea parolei'
        };
    }
}

/**
 * Log security event to database
 */
async function logSecurityEvent(eventType, userId, metadata = {}) {
    const supabase = initSupabase();
    if (!supabase) return;
    
    try {
        await supabase
            .from('security_logs')
            .insert([{
                event_type: eventType,
                user_id: userId,
                metadata: metadata,
                ip_address: null, // Could be added with server-side logging
                user_agent: navigator.userAgent,
                created_at: new Date().toISOString()
            }]);
    } catch (error) {
        console.error('Error logging security event:', error);
        // Don't throw - logging should not break functionality
    }
}

/**
 * Protected page redirect
 */
async function protectPage(requiredRole = null) {
    const authenticated = await isAuthenticated();
    
    if (!authenticated) {
        // Save intended destination
        sessionStorage.setItem('intended_url', window.location.href);
        
        // Redirect to login
        window.location.href = 'login.html';
        return false;
    }
    
    // Check role if specified
    if (requiredRole) {
        const user = getUserData();
        if (!user || user.role !== requiredRole) {
            alert('Nu ai permisiuni pentru această pagină');
            window.location.href = 'dashboard.html';
            return false;
        }
    }
    
    return true;
}
