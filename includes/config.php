<?php
// ============================================
// PAVILON MIDAS LTD — CONFIGURATION FILE
// ============================================

// Start session
session_start();

// Database configuration
define('DB_HOST', 'localhost');
define('DB_NAME', 'pavilon_midas');
define('DB_USER', 'your_db_user');
define('DB_PASS', 'your_db_password');

// Site configuration
define('SITE_URL', 'https://yourdomain.com');
define('SITE_NAME', 'Pavilon Midas Asset Management Ltd');

// Security settings
define('SESSION_LIFETIME', 1800); // 30 minutes
define('MAX_LOGIN_ATTEMPTS', 5);
define('LOCKOUT_TIME', 900); // 15 minutes

// Email configuration (for password reset, etc.)
define('SMTP_HOST', 'your_smtp_host');
define('SMTP_USER', 'your_email@domain.com');
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
            die("Database connection failed: " . $e->getMessage());
        }
    }
    return $conn;
}

// Utility functions
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
        header('Location: ' . SITE_URL . '/auth/dashboard.php');
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
?>