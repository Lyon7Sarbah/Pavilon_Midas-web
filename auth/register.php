<?php
// ============================================
// Pavilion Midas Academy Ltd — SECURE REGISTRATION
// With SQL Injection Protection, Rate Limiting, CSRF, XSS Prevention
// ============================================

session_start([
    'cookie_httponly' => true,
    'cookie_secure' => true,
    'cookie_samesite' => 'Strict'
]);

require_once '../includes/config.php';

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header('Location: ../dashboard.php');
    exit;
}

// Rate limiting tables creation (run once)
function initSecurityTables($pdo) {
    $tables = [
        "CREATE TABLE IF NOT EXISTS registration_attempts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            success TINYINT DEFAULT 0,
            attempt_time DATETIME NOT NULL,
            INDEX idx_ip_time (ip_address, attempt_time)
        )",
        "CREATE TABLE IF NOT EXISTS failed_logins (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            attempt_time DATETIME NOT NULL,
            INDEX idx_ip_time (ip_address, attempt_time)
        )"
    ];
    foreach ($tables as $sql) {
        $pdo->exec($sql);
    }
}

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Initialize security tables
    initSecurityTables($pdo);
    
    // Rate limiting - Check IP
    $ip = $_SERVER['REMOTE_ADDR'];
    $stmt = $pdo->prepare("
        SELECT COUNT(*) as attempts 
        FROM registration_attempts 
        WHERE ip_address = ? 
        AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    ");
    $stmt->execute([$ip]);
    $attempts = $stmt->fetch(PDO::FETCH_ASSOC)['attempts'];
    
    if ($attempts >= 5) {
        $errors[] = 'Too many registration attempts. Please try again after 1 hour.';
        error_log("Rate limit exceeded for IP: $ip");
    }
    
    // CSRF Protection
    if (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || 
        !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $errors[] = 'Security validation failed. Please refresh the page and try again.';
        error_log("CSRF validation failed for IP: $ip");
    }
    
    // Form submission time check (bot detection)
    if (isset($_POST['form_submit_time']) && is_numeric($_POST['form_submit_time'])) {
        $submit_time = (int)$_POST['form_submit_time'];
        $now = time() * 1000;
        if (($now - $submit_time) < 2000) {
            $errors[] = 'Please wait before submitting.';
            error_log("Too fast submission from IP: $ip");
        }
    }
    
    // Honeypot check
    if (!empty($_POST['website'])) {
        error_log("Honeypot triggered for IP: $ip");
        header('Location: ../index.html');
        exit;
    }
    
    // Sanitize inputs with strict validation
    $first_name = trim(strip_tags($_POST['first_name'] ?? ''));
    $last_name = trim(strip_tags($_POST['last_name'] ?? ''));
    $username = trim(strip_tags($_POST['username'] ?? ''));
    $email = trim(strtolower(strip_tags($_POST['email'] ?? '')));
    $phone = trim(strip_tags($_POST['phone'] ?? ''));
    $country = strip_tags($_POST['country'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $referral_code = trim(strtoupper(strip_tags($_POST['referral_code'] ?? '')));
    $agree_terms = isset($_POST['agree_terms']);
    
    // Validate required fields
    if (empty($first_name)) $errors[] = 'First name is required.';
    if (empty($last_name)) $errors[] = 'Last name is required.';
    if (empty($username)) $errors[] = 'Username is required.';
    if (empty($email)) $errors[] = 'Email address is required.';
    if (empty($password)) $errors[] = 'Password is required.';
    if (!$agree_terms) $errors[] = 'You must agree to the terms and conditions.';
    
    // Name validation - prevent SQL injection and XSS
    if (!empty($first_name) && !preg_match('/^[A-Za-z\s\-\']{2,50}$/', $first_name)) {
        $errors[] = 'First name must contain only letters, spaces, hyphens, and apostrophes.';
    }
    if (!empty($last_name) && !preg_match('/^[A-Za-z\s\-\']{2,50}$/', $last_name)) {
        $errors[] = 'Last name must contain only letters, spaces, hyphens, and apostrophes.';
    }
    
    // Email validation
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }
    
    // Domain validation - block disposable emails
    $domain = substr(strrchr($email, "@"), 1);
    $disposable_domains = ['tempmail.com', 'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'yopmail.com'];
    if (in_array(strtolower($domain), $disposable_domains)) {
        $errors[] = 'Please use a permanent email address.';
    }
    
    // Username validation
    if (!empty($username) && !preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        $errors[] = 'Username must be 3-30 characters (letters, numbers, underscore only).';
    }
    
    // Reserved usernames
    $reserved = ['admin', 'administrator', 'root', 'system', 'support', 'pavilon', 'midas', 'moderator', 'staff'];
    if (in_array(strtolower($username), $reserved)) {
        $errors[] = 'This username is reserved. Please choose another.';
    }
    
    // Phone validation
    if (!empty($phone) && !preg_match('/^\+?[0-9\s\-\(\)]{10,20}$/', $phone)) {
        $errors[] = 'Please enter a valid phone number.';
    }
    
    // Country validation
    $allowed_countries = ['GH', 'NG', 'SN', 'CI', 'KE', 'ZA', 'Other'];
    if (!in_array($country, $allowed_countries)) {
        $errors[] = 'Please select a valid country.';
    }
    
    // Password validation - STRONG requirements
    if (!empty($password)) {
        if (strlen($password) < 12) {
            $errors[] = 'Password must be at least 12 characters.';
        }
        if (strlen($password) > 128) {
            $errors[] = 'Password is too long.';
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = 'Password must contain at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = 'Password must contain at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = 'Password must contain at least one number.';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $password)) {
            $errors[] = 'Password must contain at least one special character.';
        }
        
        // Check password against common passwords
        $common_passwords = ['Password123', 'Admin123!', 'Qwerty123!', 'Welcome123!', 'Pavilon2024'];
        if (in_array($password, $common_passwords)) {
            $errors[] = 'This password is too common. Please choose a stronger password.';
        }
        
        // Check if password contains personal info
        if (stripos($password, $username) !== false || 
            ($email && stripos($password, explode('@', $email)[0]) !== false)) {
            $errors[] = 'Password cannot contain your username or email address.';
        }
    }
    
    // Password match
    if ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match.';
    }
    
    // SQL Injection pattern detection
    $sql_patterns = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION', '--', ';', 'OR 1=1', ' AND 1=1'];
    $fields_to_check = [$first_name, $last_name, $username, $email, $phone, $referral_code];
    foreach ($fields_to_check as $field) {
        foreach ($sql_patterns as $pattern) {
            if (stripos($field, $pattern) !== false) {
                $errors[] = 'Invalid characters detected.';
                error_log("SQL injection attempt from IP: $ip");
                break 2;
            }
        }
    }
    
    // XSS pattern detection
    $xss_patterns = ['<script', 'javascript:', 'onclick=', 'onload=', 'alert(', 'document.', 'window.'];
    foreach ($fields_to_check as $field) {
        foreach ($xss_patterns as $pattern) {
            if (stripos($field, $pattern) !== false) {
                $errors[] = 'Invalid characters detected.';
                error_log("XSS attempt from IP: $ip");
                break 2;
            }
        }
    }
    
    // Check for existing users using prepared statements
    if (empty($errors)) {
        try {
            // Check email
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? LIMIT 1");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $errors[] = 'An account with this email address already exists.';
            }
            
            // Check username
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $errors[] = 'This username is already taken.';
            }
            
            // Validate referral code
            $referrer_id = null;
            if (!empty($referral_code)) {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = ? AND account_status = 'active' LIMIT 1");
                $stmt->execute([$referral_code]);
                $referrer = $stmt->fetch(PDO::FETCH_ASSOC);
                if ($referrer) {
                    $referrer_id = $referrer['id'];
                } else {
                    $errors[] = 'Invalid referral code.';
                }
            }
        } catch (PDOException $e) {
            error_log('Registration validation error: ' . $e->getMessage());
            $errors[] = 'A system error occurred. Please try again later.';
        }
    }
    
    // Create account
    if (empty($errors)) {
        try {
            $pdo->beginTransaction();
            
            // Generate unique referral code
            $user_referral_code = '';
            do {
                $user_referral_code = strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
                $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = ?");
                $stmt->execute([$user_referral_code]);
            } while ($stmt->fetch());
            
            // Hash password with bcrypt
            $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            
            // Insert user using prepared statement
            $stmt = $pdo->prepare("
                INSERT INTO users (
                    username, email, password_hash, first_name, last_name,
                    phone, country, referral_code, referred_by, account_status,
                    created_at, updated_at, registration_ip
                ) VALUES (
                    :username, :email, :password_hash, :first_name, :last_name,
                    :phone, :country, :referral_code, :referred_by, 'active',
                    NOW(), NOW(), :registration_ip
                )
            ");
            
            $stmt->execute([
                ':username' => $username,
                ':email' => $email,
                ':password_hash' => $password_hash,
                ':first_name' => $first_name,
                ':last_name' => $last_name,
                ':phone' => $phone,
                ':country' => $country,
                ':referral_code' => $user_referral_code,
                ':referred_by' => $referrer_id,
                ':registration_ip' => $ip
            ]);
            
            $user_id = $pdo->lastInsertId();
            
            // Log successful registration
            $stmt = $pdo->prepare("
                INSERT INTO registration_attempts (ip_address, success, attempt_time)
                VALUES (?, 1, NOW())
            ");
            $stmt->execute([$ip]);
            
            // Create user profile
            $stmt = $pdo->prepare("
                INSERT INTO user_profiles (user_id, created_at, updated_at)
                VALUES (?, NOW(), NOW())
            ");
            $stmt->execute([$user_id]);
            
            // Create user settings
            $stmt = $pdo->prepare("
                INSERT INTO user_settings (user_id, email_notifications, signal_alerts, created_at)
                VALUES (?, 1, 1, NOW())
            ");
            $stmt->execute([$user_id]);
            
            // Process referral bonus if applicable
            if ($referrer_id) {
                $stmt = $pdo->prepare("
                    INSERT INTO referral_bonuses (referrer_id, referred_user_id, bonus_amount, status, created_at)
                    VALUES (?, ?, 10.00, 'pending', NOW())
                ");
                $stmt->execute([$referrer_id, $user_id]);
            }
            
            $pdo->commit();
            
            // Set secure session
            $_SESSION['user_id'] = $user_id;
            $_SESSION['user_email'] = $email;
            $_SESSION['username'] = $username;
            $_SESSION['login_time'] = time();
            $_SESSION['ip_address'] = $ip;
            $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
            
            // Regenerate session ID to prevent fixation
            session_regenerate_id(true);
            
            // Clear CSRF token
            unset($_SESSION['csrf_token']);
            
            header('Location: ../dashboard.php');
            exit;
            
        } catch (PDOException $e) {
            $pdo->rollBack();
            error_log('Registration error: ' . $e->getMessage());
            $errors[] = 'Failed to create account. Please try again.';
        }
    }
    
    // Log failed attempt
    if (!empty($errors)) {
        $stmt = $pdo->prepare("
            INSERT INTO registration_attempts (ip_address, success, attempt_time)
            VALUES (?, 0, NOW())
        ");
        $stmt->execute([$ip]);
    }
}

// Generate new CSRF token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
$csrf_token = $_SESSION['csrf_token'];

// Store errors in session for display on the form page
if (!empty($errors)) {
    $_SESSION['registration_errors'] = $errors;
    header('Location: ../register.html');
    exit;
}
?>