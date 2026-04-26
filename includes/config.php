<?php
// ============================================
// PAVILON MIDAS ACADEMY LTD — CONFIGURATION FILE
// ============================================

// Start session with secure settings
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_httponly' => true,
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_samesite' => 'Strict'
    ]);
}

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'siteviic_pavilonmidas');
define('DB_USER', 'siteviic_psarbah');
define('DB_PASS', 'Pavilon_Midas@2026');

// Site configuration
define('SITE_URL', 'https://pavilonmidas.com');
define('SITE_NAME', 'Pavilion Midas Academy Ltd');

// Security settings
define('SESSION_LIFETIME', 1800); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes

// Email configuration (for password reset, etc.)
define('SMTP_HOST', 'your_smtp_host');
define('SMTP_USER', 'info@pavilonmidas.com');
define('SMTP_PASS', 'your_email_password');
define('SMTP_PORT', 587);

// Error reporting (set to 0 in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Timezone
date_default_timezone_set('Africa/Accra');

// Database connection function
function getDBConnection() {
    static $conn = null;
    if ($conn === null) {
        try {
            $conn = new PDO(
                "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
                DB_USER,
                DB_PASS,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            die("System error. Please try again later.");
        }
    }
    return $conn;
}

// Helper function to get PDO connection (alias for getDBConnection)
function get_pdo_connection() {
    return getDBConnection();
}

// ============================================
// SECURITY FUNCTIONS
// ============================================

function sanitize($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function generateToken($length = 32) {
    return bin2hex(random_bytes($length));
}

function isLoggedIn() {
    return isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: ' . SITE_URL . '/login.html');
        exit;
    }
}

function redirectIfLoggedIn() {
    if (isLoggedIn()) {
        header('Location: ' . SITE_URL . '/dashboard.php');
        exit;
    }
}

// CSRF protection
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = generateToken();
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ============================================
// LOGGING FUNCTIONS
// ============================================

function logActivity($user_id, $action, $details = '') {
    try {
        $pdo = getDBConnection();
        
        // Check if table exists first
        $stmt = $pdo->prepare("SHOW TABLES LIKE 'user_activity_log'");
        $stmt->execute();
        if ($stmt->rowCount() === 0) {
            // Create table if it doesn't exist
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS user_activity_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    action VARCHAR(100) NOT NULL,
                    ip_address VARCHAR(45) NULL,
                    user_agent TEXT NULL,
                    details TEXT NULL,
                    created_at DATETIME NOT NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_action (action),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");
        }
        
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

// ============================================
// RATE LIMITING FUNCTIONS
// ============================================

function isRegistrationRateLimited($ip) {
    try {
        $pdo = getDBConnection();
        
        // Check if table exists
        $stmt = $pdo->prepare("SHOW TABLES LIKE 'registration_attempts'");
        $stmt->execute();
        if ($stmt->rowCount() === 0) {
            // Create table if it doesn't exist
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS registration_attempts (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL,
                    success TINYINT DEFAULT 0,
                    attempt_time DATETIME NOT NULL,
                    INDEX idx_ip_time (ip_address, attempt_time)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
            ");
            return false;
        }
        
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as attempts 
            FROM registration_attempts 
            WHERE ip_address = ? 
            AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        $stmt->execute([$ip]);
        $result = $stmt->fetch();
        
        return ($result['attempts'] ?? 0) >= 5;
    } catch (PDOException $e) {
        error_log('Rate limiting check error: ' . $e->getMessage());
        return false;
    }
}

// ============================================
// VALIDATION FUNCTIONS
// ============================================

function validateEmailDomain($email) {
    $domain = substr(strrchr($email, "@"), 1);
    
    $disposableDomains = [
        'tempmail.com', 'throwaway.com', 'mailinator.com', 'guerrillamail.com',
        '10minutemail.com', 'yopmail.com', 'temp-mail.org', 'fakeinbox.com'
    ];
    
    if (in_array(strtolower($domain), $disposableDomains)) {
        return false;
    }
    
    return true;
}

function isReservedUsername($username) {
    $reserved = [
        'admin', 'administrator', 'root', 'system', 'support', 'info',
        'pavilon', 'midas', 'pavilonmidas', 'ceo', 'founder', 'owner',
        'moderator', 'mod', 'staff', 'team', 'official'
    ];
    
    return in_array(strtolower($username), $reserved);
}

function isCommonPassword($password) {
    $commonPasswords = [
        'password123', 'Password123', 'Admin123!', 'Qwerty123!', 'Welcome123!',
        '12345678', 'qwerty123', 'admin123', 'password123', 'pavilonmidas',
        'midas2024', 'letmein', 'welcome', 'monkey', 'dragon', 'master'
    ];
    
    return in_array(strtolower($password), $commonPasswords);
}

// ============================================
// REFERRAL FUNCTIONS
// ============================================

function generateReferralCode($pdo) {
    $maxAttempts = 10;
    $attempts = 0;
    
    do {
        $bytes = random_bytes(6);
        $code = strtoupper(bin2hex($bytes));
        $code = substr($code, 0, 8);
        
        $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = ? LIMIT 1");
        $stmt->execute([$code]);
        $exists = $stmt->fetch();
        
        $attempts++;
    } while ($exists && $attempts < $maxAttempts);
    
    if ($attempts >= $maxAttempts) {
        $code = strtoupper(substr(md5(uniqid(mt_rand(), true) . time()), 0, 8));
    }
    
    return $code;
}

function processReferralBonus($pdo, $referrer_id, $new_user_id) {
    try {
        $bonus_amount = 10.00;
        
        $stmt = $pdo->prepare("
            INSERT INTO referral_bonuses (referrer_id, referred_user_id, bonus_amount, status, created_at)
            VALUES (?, ?, ?, 'pending', NOW())
        ");
        $stmt->execute([$referrer_id, $new_user_id, $bonus_amount]);
        
        logActivity($referrer_id, 'referral_bonus', "Earned referral bonus from user ID: $new_user_id");
        
    } catch (PDOException $e) {
        error_log('Referral bonus processing error: ' . $e->getMessage());
    }
}

// ============================================
// EMAIL FUNCTIONS
// ============================================

function sendEmail($to, $subject, $message) {
    // Implement email sending logic (PHPMailer, etc.)
    // Placeholder for now
    error_log("Email would be sent to: $to - Subject: $subject");
    return true;
}
?>