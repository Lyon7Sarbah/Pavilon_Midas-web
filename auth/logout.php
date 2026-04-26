<?php
// ============================================
// Pavilion Midas Academy Ltd — LOGOUT PROCESSING
// ============================================

require_once '../includes/config.php';

// Log the logout action
if (isLoggedIn()) {
    try {
        $pdo = getDBConnection();
        $stmt = $pdo->prepare("
            INSERT INTO user_activity_log (user_id, action, ip_address, user_agent, details)
            VALUES (?, 'logout', ?, ?, 'User logged out')
        ");
        $stmt->execute([
            $_SESSION['user_id'],
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    } catch (PDOException $e) {
        error_log('Logout logging error: ' . $e->getMessage());
    }
}

// Destroy the session
session_destroy();

// Clear session cookie
if (isset($_COOKIE[session_name()])) {
    setcookie(session_name(), '', time() - 3600, '/');
}

// Redirect to home page with logout message
header('Location: ' . SITE_URL . '/index.html?logout=success');
exit;
?>