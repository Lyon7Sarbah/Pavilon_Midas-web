<?php
// ============================================
// Pavilion Midas Academy Ltd — SECURE LOGIN PROCESSING
// With SQL Injection Protection, Rate Limiting, CSRF
// ============================================

session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict'
]);

require_once '../includes/config.php';

// Constants for security
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes in seconds

// ============================================
// HELPER FUNCTIONS
// ============================================

function getDBConnection() {
    global $pdo;
    return $pdo;
}

function sanitize($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

function generateCSRFToken() {
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    return $token;
}

function logActivity($user_id, $action, $details = '') {
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO user_activity_log (user_id, action, ip_address, user_agent, details, created_at)
            VALUES (?, ?, ?, ?, ?, NOW())
        ");
        $stmt->execute([
            $user_id,
            $action,
            $_SERVER['REMOTE_ADDR'] ?? '',
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            $details
        ]);
    } catch (PDOException $e) {
        error_log('Activity logging error: ' . $e->getMessage());
    }
}

function redirectIfLoggedIn() {
    if (isset($_SESSION['user_id'])) {
        header('Location: ../dashboard.php');
        exit;
    }
}

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Rate limiting - Check IP
    $ip = $_SERVER['REMOTE_ADDR'];
    
    // Honeypot check
    if (!empty($_POST['website'])) {
        error_log("Honeypot triggered for IP: $ip");
        header('Location: ../index.html');
        exit;
    }
    
    // Form submission time check (bot detection)
    if (isset($_POST['form_submit_time']) && is_numeric($_POST['form_submit_time'])) {
        $submit_time = (int)$_POST['form_submit_time'];
        $now = time() * 1000;
        if (($now - $submit_time) < 1500) {
            $errors[] = 'Please wait before submitting.';
            error_log("Too fast login submission from IP: $ip");
        }
    }
    
    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Security validation failed. Please refresh the page and try again.';
        error_log("CSRF validation failed for IP: $ip");
    }
    
    // Sanitize inputs
    $email = trim(strtolower(sanitize($_POST['email'] ?? '')));
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']) ? true : false;
    
    // Validate inputs
    if (empty($email)) {
        $errors[] = 'Email address is required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    
    // Check email domain for disposable emails
    if (!empty($email)) {
        $domain = substr(strrchr($email, "@"), 1);
        $disposable_domains = ['tempmail.com', 'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com'];
        if (in_array(strtolower($domain), $disposable_domains)) {
            $errors[] = 'Please use a permanent email address.';
        }
    }
    
    if (empty($password)) {
        $errors[] = 'Password is required.';
    }
    
    // SQL Injection pattern detection
    $sql_patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', '--', ';', 'OR 1=1', ' AND 1=1'];
    foreach ($sql_patterns as $pattern) {
        if (stripos($email, $pattern) !== false) {
            $errors[] = 'Invalid characters detected.';
            error_log("SQL injection attempt in login from IP: $ip");
            break;
        }
    }
    
    // XSS pattern detection
    $xss_patterns = ['<script', 'javascript:', 'onclick=', 'onload=', 'alert(', 'document.', 'window.'];
    foreach ($xss_patterns as $pattern) {
        if (stripos($email, $pattern) !== false) {
            $errors[] = 'Invalid characters detected.';
            error_log("XSS attempt in login from IP: $ip");
            break;
        }
    }
    
    if (empty($errors)) {
        try {
            $pdo = getDBConnection();
            
            // Check if IP is rate limited
            $stmt = $pdo->prepare("
                SELECT COUNT(*) as attempts 
                FROM failed_logins 
                WHERE ip_address = ? 
                AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ");
            $stmt->execute([$ip]);
            $ipAttempts = $stmt->fetch(PDO::FETCH_ASSOC)['attempts'];
            
            if ($ipAttempts >= 10) {
                $errors[] = 'Too many attempts from this IP. Please try again later.';
                error_log("IP rate limit exceeded: $ip");
            }
            
            if (empty($errors)) {
                // Check if account is locked
                $stmt = $pdo->prepare("
                    SELECT id, password_hash, login_attempts, locked_until, account_status, username, first_name, last_name
                    FROM users
                    WHERE email = ?
                ");
                $stmt->execute([$email]);
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                if ($user) {
                    // Check if account is locked
                    if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                        $remaining = ceil((strtotime($user['locked_until']) - time()) / 60);
                        $errors[] = "Account is temporarily locked due to too many failed attempts. Try again in {$remaining} minutes.";
                        error_log("Locked account login attempt: {$user['id']} from IP: $ip");
                    }
                    // Check account status
                    elseif ($user['account_status'] !== 'active') {
                        $errors[] = 'Your account is not active. Please contact support.';
                        logActivity($user['id'], 'inactive_login_attempt', 'Attempt to login to inactive account');
                    }
                    // Verify password
                    elseif (password_verify($password, $user['password_hash'])) {
                        // Successful login
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['user_email'] = $email;
                        $_SESSION['username'] = $user['username'];
                        $_SESSION['full_name'] = $user['first_name'] . ' ' . $user['last_name'];
                        $_SESSION['login_time'] = time();
                        $_SESSION['ip_address'] = $ip;
                        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
                        
                        // Reset login attempts
                        $stmt = $pdo->prepare("UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?");
                        $stmt->execute([$user['id']]);
                        
                        // Log successful login
                        logActivity($user['id'], 'login_success', 'User logged in successfully');
                        
                        // Set session cookie parameters for "remember me"
                        if ($remember) {
                            $lifetime = 2592000; // 30 days
                            session_set_cookie_params($lifetime, '/', '', true, true);
                        }
                        
                        // Regenerate session ID to prevent fixation
                        session_regenerate_id(true);
                        
                        // Clear CSRF token
                        unset($_SESSION['csrf_token']);
                        
                        // Redirect to dashboard or intended page
                        $redirect = isset($_GET['redirect']) ? $_GET['redirect'] : '../dashboard.php';
                        header('Location: ' . $redirect);
                        exit;
                        
                    } else {
                        // Failed login attempt
                        $attempts = $user['login_attempts'] + 1;
                        $locked_until = null;
                        
                        if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                            $locked_until = date('Y-m-d H:i:s', time() + LOCKOUT_TIME);
                            logActivity($user['id'], 'account_locked', 'Account locked due to too many failed attempts');
                            $errors[] = 'Account locked due to too many failed attempts. Try again later.';
                        } else {
                            $remaining = MAX_LOGIN_ATTEMPTS - $attempts;
                            $errors[] = "Invalid email or password. {$remaining} attempt(s) remaining.";
                        }
                        
                        $stmt = $pdo->prepare("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?");
                        $stmt->execute([$attempts, $locked_until, $user['id']]);
                        
                        logActivity($user['id'], 'login_failed', "Failed login attempt. Attempts: $attempts");
                        
                        // Log failed attempt to IP tracking table
                        $stmt = $pdo->prepare("INSERT INTO failed_logins (ip_address, attempt_time) VALUES (?, NOW())");
                        $stmt->execute([$ip]);
                    }
                } else {
                    // User not found - log IP attempt
                    $errors[] = 'Invalid email or password.';
                    $stmt = $pdo->prepare("INSERT INTO failed_logins (ip_address, attempt_time) VALUES (?, NOW())");
                    $stmt->execute([$ip]);
                    error_log("Login attempt for non-existent email: $email from IP: $ip");
                }
            }
            
        } catch (PDOException $e) {
            error_log('Login error: ' . $e->getMessage());
            $errors[] = 'A system error occurred. Please try again later.';
        }
    }
}

// Generate new CSRF token
$csrf_token = generateCSRFToken();

// If there are errors, store them in session to display on the login page
if (!empty($errors)) {
    $_SESSION['login_errors'] = $errors;
    header('Location: ../login.html');
    exit;
}
?>