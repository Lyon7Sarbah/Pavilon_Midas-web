<?php
// ============================================
// PAVILON MIDAS LTD — REGISTRATION PROCESSING
// SECURE REGISTRATION WITH SQL INJECTION PROTECTION
// ============================================

require_once '../includes/config.php';

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs with type casting where appropriate
    $first_name = trim(sanitize($_POST['first_name'] ?? ''));
    $last_name = trim(sanitize($_POST['last_name'] ?? ''));
    $username = trim(sanitize($_POST['username'] ?? ''));
    $email = trim(strtolower(sanitize($_POST['email'] ?? '')));
    $phone = trim(sanitize($_POST['phone'] ?? ''));
    $country = sanitize($_POST['country'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $referral_code = trim(strtoupper(sanitize($_POST['referral_code'] ?? '')));
    $agree_terms = isset($_POST['agree_terms']);

    // Honeypot check - bot detection
    if (!empty($_POST['website'])) {
        error_log('Bot registration attempt detected from IP: ' . $_SERVER['REMOTE_ADDR']);
        header('Location: ../index.html');
        exit;
    }

    // Validate CSRF token with timing-safe comparison
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Security validation failed. Please refresh the page and try again.';
        error_log('CSRF validation failed for registration from IP: ' . $_SERVER['REMOTE_ADDR']);
    }

    // Rate limiting check
    if (isRegistrationRateLimited($_SERVER['REMOTE_ADDR'])) {
        $errors[] = 'Too many registration attempts. Please try again later.';
    }

    // Validate required fields
    if (empty($first_name)) $errors[] = 'First name is required.';
    if (empty($last_name)) $errors[] = 'Last name is required.';
    if (empty($username)) $errors[] = 'Username is required.';
    if (empty($email)) $errors[] = 'Email address is required.';
    if (empty($password)) $errors[] = 'Password is required.';
    if (!$agree_terms) $errors[] = 'You must agree to the terms and conditions.';

    // Validate name formats - prevent SQL injection patterns
    if (!empty($first_name) && !preg_match('/^[A-Za-z\s\-\']{2,50}$/', $first_name)) {
        $errors[] = 'First name must be 2-50 characters and contain only letters, spaces, hyphens, and apostrophes.';
    }
    if (!empty($last_name) && !preg_match('/^[A-Za-z\s\-\']{2,50}$/', $last_name)) {
        $errors[] = 'Last name must be 2-50 characters and contain only letters, spaces, hyphens, and apostrophes.';
    }

    // Validate email format and domain
    if (!empty($email)) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Please enter a valid email address.';
        } elseif (!validateEmailDomain($email)) {
            $errors[] = 'Please use a valid email domain.';
        } elseif (strlen($email) > 100) {
            $errors[] = 'Email address is too long.';
        }
    }

    // Validate username format
    if (!empty($username)) {
        if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
            $errors[] = 'Username must be 3-30 characters and contain only letters, numbers, and underscores.';
        }
        // Check for reserved usernames
        if (isReservedUsername($username)) {
            $errors[] = 'This username is not allowed. Please choose another.';
        }
    }

    // Enhanced password validation
    if (!empty($password)) {
        if (strlen($password) < 12) {
            $errors[] = 'Password must be at least 12 characters long for better security.';
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
        // Check against common passwords
        if (isCommonPassword($password)) {
            $errors[] = 'This password is too common. Please choose a stronger password.';
        }
        // Check if password contains username or email
        if (stripos($password, $username) !== false || stripos($password, explode('@', $email)[0]) !== false) {
            $errors[] = 'Password cannot contain your username or email address.';
        }
    }

    // Validate password confirmation
    if ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match.';
    }

    // Validate phone format
    if (!empty($phone) && !preg_match('/^\+?[0-9\s\-\(\)]{10,20}$/', $phone)) {
        $errors[] = 'Please enter a valid phone number.';
    }

    // Validate country
    $allowed_countries = ['GH', 'NG', 'SN', 'CI', 'KE', 'ZA', 'Other'];
    if (!in_array($country, $allowed_countries)) {
        $errors[] = 'Please select a valid country.';
    }

    // SQL Injection pattern detection (additional protection)
    $sqlPatterns = '/(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bUNION\b|--|;|\bOR\b.*=|\bAND\b.*=|\bEXEC\b|\bEXECUTE\b)/i';
    $fieldsToCheck = [$first_name, $last_name, $username, $email, $phone, $referral_code];
    foreach ($fieldsToCheck as $field) {
        if (preg_match($sqlPatterns, $field)) {
            $errors[] = 'Invalid characters detected in input.';
            error_log('SQL injection pattern detected in registration from IP: ' . $_SERVER['REMOTE_ADDR']);
            break;
        }
    }

    // Check for existing users
    if (empty($errors)) {
        try {
            $pdo = getDBConnection();

            // Use prepared statements to prevent SQL injection
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
            $stmt->execute([':email' => $email]);
            if ($stmt->fetch()) {
                $errors[] = 'An account with this email address already exists.';
            }

            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username LIMIT 1");
            $stmt->execute([':username' => $username]);
            if ($stmt->fetch()) {
                $errors[] = 'This username is already taken.';
            }

            // Validate referral code if provided
            $referrer_id = null;
            if (!empty($referral_code)) {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = :referral_code AND account_status = 'active' LIMIT 1");
                $stmt->execute([':referral_code' => $referral_code]);
                $referrer = $stmt->fetch();
                if (!$referrer) {
                    $errors[] = 'Invalid referral code.';
                } else {
                    $referrer_id = $referrer['id'];
                }
            }

        } catch (PDOException $e) {
            error_log('Registration validation error: ' . $e->getMessage());
            $errors[] = 'A system error occurred. Please try again later.';
        }
    }

    // Create account if no errors
    if (empty($errors)) {
        try {
            $pdo = getDBConnection();
            
            // Begin transaction for data integrity
            $pdo->beginTransaction();

            // Generate unique referral code
            $user_referral_code = generateReferralCode($pdo);

            // Hash password with bcrypt (cost factor 12)
            $password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

            // Insert user with prepared statement
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
                ':registration_ip' => $_SERVER['REMOTE_ADDR'] ?? ''
            ]);

            $user_id = $pdo->lastInsertId();

            // Create user profile record
            $stmt = $pdo->prepare("
                INSERT INTO user_profiles (user_id, created_at, updated_at)
                VALUES (:user_id, NOW(), NOW())
            ");
            $stmt->execute([':user_id' => $user_id]);

            // Create user settings record
            $stmt = $pdo->prepare("
                INSERT INTO user_settings (user_id, email_notifications, signal_alerts, created_at)
                VALUES (:user_id, 1, 1, NOW())
            ");
            $stmt->execute([':user_id' => $user_id]);

            // Process referral bonus if applicable
            if ($referrer_id) {
                processReferralBonus($pdo, $referrer_id, $user_id);
            }

            // Commit transaction
            $pdo->commit();

            // Log registration
            logActivity($user_id, 'registration', 'User account created successfully');

            // Set session with secure flags
            $_SESSION['user_id'] = $user_id;
            $_SESSION['user_email'] = $email;
            $_SESSION['username'] = $username;
            $_SESSION['login_time'] = time();
            
            // Regenerate session ID to prevent fixation
            session_regenerate_id(true);

            // Success message
            $success = 'Account created successfully! Welcome to Pavilon Midas. Redirecting to dashboard...';

            // Redirect after 2 seconds
            header('refresh:2;url=' . SITE_URL . '/auth/dashboard.php');

        } catch (PDOException $e) {
            // Rollback transaction on error
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            error_log('Registration error: ' . $e->getMessage());
            $errors[] = 'Failed to create account. Please try again.';
        }
    }
}

// Generate new CSRF token
$csrf_token = generateCSRFToken();

// ============================================
// HELPER FUNCTIONS
// ============================================

/**
 * Generate unique referral code
 */
function generateReferralCode($pdo) {
    $maxAttempts = 10;
    $attempts = 0;
    
    do {
        // Generate cryptographically secure random bytes
        $bytes = random_bytes(6);
        $code = strtoupper(bin2hex($bytes));
        $code = substr($code, 0, 8);
        
        $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = :code LIMIT 1");
        $stmt->execute([':code' => $code]);
        $exists = $stmt->fetch();
        
        $attempts++;
    } while ($exists && $attempts < $maxAttempts);
    
    if ($attempts >= $maxAttempts) {
        // Fallback with timestamp
        $code = strtoupper(substr(md5(uniqid(mt_rand(), true) . time()), 0, 8));
    }
    
    return $code;
}

/**
 * Log user activity
 */
function logActivity($user_id, $action, $details = '') {
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO user_activity_log (user_id, action, ip_address, user_agent, details, created_at)
            VALUES (:user_id, :action, :ip_address, :user_agent, :details, NOW())
        ");
        $stmt->execute([
            ':user_id' => $user_id,
            ':action' => $action,
            ':ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
            ':user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            ':details' => $details
        ]);
    } catch (PDOException $e) {
        error_log('Activity logging error: ' . $e->getMessage());
    }
}

/**
 * Check registration rate limiting
 */
function isRegistrationRateLimited($ip) {
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) as attempts 
            FROM user_activity_log 
            WHERE ip_address = :ip 
            AND action = 'registration_attempt'
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
        ");
        $stmt->execute([':ip' => $ip]);
        $result = $stmt->fetch();
        
        // Log this attempt
        $stmt = $pdo->prepare("
            INSERT INTO user_activity_log (ip_address, action, details, created_at)
            VALUES (:ip, 'registration_attempt', :details, NOW())
        ");
        $stmt->execute([
            ':ip' => $ip,
            ':details' => 'Registration attempt from IP'
        ]);
        
        return ($result['attempts'] ?? 0) >= 5;
    } catch (PDOException $e) {
        error_log('Rate limiting check error: ' . $e->getMessage());
        return false;
    }
}

/**
 * Validate email domain
 */
function validateEmailDomain($email) {
    $domain = substr(strrchr($email, "@"), 1);
    
    // Block disposable email domains
    $disposableDomains = [
        'tempmail.com', 'throwaway.com', 'mailinator.com', 'guerrillamail.com',
        '10minutemail.com', 'yopmail.com', 'temp-mail.org', 'fakeinbox.com'
    ];
    
    if (in_array(strtolower($domain), $disposableDomains)) {
        return false;
    }
    
    // Check DNS records
    return checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
}

/**
 * Check if username is reserved
 */
function isReservedUsername($username) {
    $reserved = [
        'admin', 'administrator', 'root', 'system', 'support', 'info',
        'pavilon', 'midas', 'pavilonmidas', 'ceo', 'founder', 'owner',
        'moderator', 'mod', 'staff', 'team', 'official'
    ];
    
    return in_array(strtolower($username), $reserved);
}

/**
 * Check if password is common
 */
function isCommonPassword($password) {
    $commonPasswords = [
        'password', '12345678', 'qwerty123', 'admin123', 'password123',
        '123456789', 'qwertyuiop', '1q2w3e4r', 'pavilonmidas', 'midas2024',
        'letmein', 'welcome', 'monkey', 'dragon', 'master', 'hello',
        'freedom', 'whatever', 'qazwsx', 'trustno1'
    ];
    
    return in_array(strtolower($password), $commonPasswords);
}

/**
 * Process referral bonus
 */
function processReferralBonus($pdo, $referrer_id, $new_user_id) {
    try {
        // Add referral bonus to referrer's account
        $bonus_amount = 10.00; // $10 bonus
        
        $stmt = $pdo->prepare("
            INSERT INTO referral_bonuses (referrer_id, referred_user_id, bonus_amount, status, created_at)
            VALUES (:referrer_id, :referred_user_id, :bonus_amount, 'pending', NOW())
        ");
        $stmt->execute([
            ':referrer_id' => $referrer_id,
            ':referred_user_id' => $new_user_id,
            ':bonus_amount' => $bonus_amount
        ]);
        
        // Log the referral
        logActivity($referrer_id, 'referral_bonus', "Earned referral bonus from user ID: $new_user_id");
        
    } catch (PDOException $e) {
        error_log('Referral bonus processing error: ' . $e->getMessage());
    }
}

// Include header
$page_title = 'Create Account — Pavilon Midas Ltd';
include '../includes/header.php';
?>

<!-- NAVBAR -->
<nav class="navbar">
  <div class="nav-container">
    <a href="../index.html" class="nav-logo">
      <img src="../assets/logo1.png" alt="Pavilon Midas" onerror="this.style.display='none'">
      <!--<div class="nav-logo-text">PAVILON MIDAS<span>Asset Management Ltd</span></div>-->
    </a>
    <div class="nav-links">
      <a href="../index.html">Home</a>
      <div class="dropdown">
        <a href="../services.html">Services <i class="fas fa-chevron-down" style="font-size:0.65rem;"></i></a>
        <div class="dropdown-menu">
          <a href="../signals.html"><i class="fas fa-chart-bar"></i> Forex Signals</a>
          <a href="../pool-investment.html"><i class="fas fa-wallet"></i> Forex Trading Pool</a>
          <a href="../referral.html"><i class="fas fa-handshake"></i> Referral Program</a>
        </div>
      </div>
      <a href="../about.html">About Us</a>
      <a href="../referral.html">Referral</a>
      <a href="../contact.html">Contact</a>
    </div>
    <div class="nav-actions">
      <a href="login.php" class="btn btn-outline btn-sm">Login</a>
      <a href="register.php" class="btn btn-primary btn-sm active">Register</a>
    </div>
    <div class="hamburger"><span></span><span></span><span></span></div>
  </div>
</nav>

<!-- MOBILE MENU -->
<div class="mobile-menu">
  <a href="../index.html">Home</a>
  <a href="../services.html">Services</a>
  <a href="../signals.html">Forex Signals</a>
  <a href="../pool-investment.html">Forex Trading Pool</a>
  <a href="../referral.html">Referral Program</a>
  <a href="../about.html">About Us</a>
  <a href="../contact.html">Contact</a>
  <a href="login.php" class="btn btn-outline" style="color:#e87a20;border-color:#e87a20;">Login</a>
  <a href="register.php" class="btn btn-primary">Register</a>
</div>

<!-- PAGE HERO -->
<div class="page-hero">
  <div class="container">
    <div class="page-hero-label"><i class="fas fa-user-plus"></i> Join Pavilon Midas</div>
    <h1>Create Your <span class="text-gold">Secure Trading Account</span></h1>
    <p>Join thousands of successful traders across Africa. 256-bit SSL encrypted registration.</p>
    <div class="breadcrumb">
      <a href="../index.html">Home</a><span class="sep">›</span><span>Register</span>
    </div>
  </div>
</div>

<div class="auth-page" style="padding:100px 24px 60px;">
    <div class="auth-card fade-in visible" style="max-width:580px;">
        <div class="auth-logo">
            <img src="../assets/logo.png" alt="Pavilon Midas" onerror="this.style.display='none'">
            <div style="font-family:var(--font-display);font-size:0.75rem;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin-top:6px;">Asset Management Ltd</div>
        </div>
        <h2 class="auth-title">Create Your Account</h2>
        <p class="auth-subtitle">Join thousands of investors across Africa.</p>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle" style="margin-right: 8px;"></i>
                <strong>Please correct the following errors:</strong>
                <ul style="margin-top: 8px;">
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo htmlspecialchars($error); ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle" style="margin-right: 8px;"></i>
                <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>

        <!-- PERKS -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:28px;">
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.4rem;margin-bottom:4px;color:var(--gold);"><i class="fas fa-chart-line"></i></div>
                <strong>Free Signals</strong><br>
                <span style="font-size:0.7rem;opacity:0.7;">7-day trial</span>
            </div>
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.4rem;margin-bottom:4px;color:var(--gold);"><i class="fas fa-wallet"></i></div>
                <strong>Pool Access</strong><br>
                <span style="font-size:0.7rem;opacity:0.7;">Start from $100</span>
            </div>
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.4rem;margin-bottom:4px;color:var(--gold);"><i class="fas fa-users"></i></div>
                <strong>Referral Bonus</strong><br>
                <span style="font-size:0.7rem;opacity:0.7;">Earn 5-10%</span>
            </div>
        </div>

        <form action="register.php" method="post" id="registerForm">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
            <!-- Honeypot field for bot protection -->
            <input type="text" name="website" style="display:none;" autocomplete="off" tabindex="-1">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                <div class="form-group">
                    <label class="form-label"><i class="fas fa-user" style="margin-right:6px;color:var(--gold);"></i>First Name</label>
                    <input type="text" class="form-control" placeholder="Kwame" name="first_name" required maxlength="50" value="<?php echo htmlspecialchars($_POST['first_name'] ?? ''); ?>">
                </div>
                <div class="form-group">
                    <label class="form-label"><i class="fas fa-user" style="margin-right:6px;color:var(--gold);"></i>Last Name</label>
                    <input type="text" class="form-control" placeholder="Mensah" name="last_name" required maxlength="50" value="<?php echo htmlspecialchars($_POST['last_name'] ?? ''); ?>">
                </div>
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fas fa-at" style="margin-right:6px;color:var(--gold);"></i>Username</label>
                <input type="text" class="form-control" placeholder="kwamemensah" name="username" required maxlength="30" value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
                <small style="color:var(--gray-500);font-size:0.7rem;">3-30 characters, letters, numbers, and underscores only</small>
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fas fa-envelope" style="margin-right:6px;color:var(--gold);"></i>Email Address</label>
                <input type="email" class="form-control" placeholder="you@example.com" name="email" required maxlength="100" value="<?php echo htmlspecialchars($_POST['email'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fab fa-whatsapp" style="margin-right:6px;color:#25D366;"></i>Phone / WhatsApp</label>
                <input type="tel" class="form-control" placeholder="+233 XX XXX XXXX" name="phone" value="<?php echo htmlspecialchars($_POST['phone'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fas fa-globe-africa" style="margin-right:6px;color:var(--gold);"></i>Country</label>
                <select class="form-control form-select" name="country" required>
                    <option value="">Select your country...</option>
                    <option value="GH" <?php echo ($_POST['country'] ?? '') === 'GH' ? 'selected' : ''; ?>>🇬🇭 Ghana</option>
                    <option value="NG" <?php echo ($_POST['country'] ?? '') === 'NG' ? 'selected' : ''; ?>>🇳🇬 Nigeria</option>
                    <option value="SN" <?php echo ($_POST['country'] ?? '') === 'SN' ? 'selected' : ''; ?>>🇸🇳 Senegal</option>
                    <option value="CI" <?php echo ($_POST['country'] ?? '') === 'CI' ? 'selected' : ''; ?>>🇨🇮 Côte d'Ivoire</option>
                    <option value="KE" <?php echo ($_POST['country'] ?? '') === 'KE' ? 'selected' : ''; ?>>🇰🇪 Kenya</option>
                    <option value="ZA" <?php echo ($_POST['country'] ?? '') === 'ZA' ? 'selected' : ''; ?>>🇿🇦 South Africa</option>
                    <option value="Other" <?php echo ($_POST['country'] ?? '') === 'Other' ? 'selected' : ''; ?>>🌍 Other African Country</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label" style="display:flex;align-items:center;justify-content:space-between;">
                    <span><i class="fas fa-lock" style="margin-right:6px;color:var(--gold);"></i>Password</span>
                    <span id="strengthLabel" style="font-size:0.75rem;color:var(--gray-500);font-weight:400;"></span>
                </label>
                <div style="position:relative;">
                    <input type="password" class="form-control" id="regPassword" placeholder="Min. 12 characters" name="password" required minlength="12" maxlength="128" oninput="checkStrength(this.value)">
                    <button type="button" onclick="togglePassword('regPassword', this)" style="position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:1rem;color:var(--gray-500);"><i class="fas fa-eye"></i></button>
                </div>
                <div class="strength-bar"><div class="strength-fill" id="strengthFill"></div></div>
                <small style="color:var(--gray-500);font-size:0.7rem;display:block;margin-top:4px;">
                    <i class="fas fa-info-circle"></i> Use 12+ characters with uppercase, lowercase, number & symbol
                </small>
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fas fa-check-circle" style="margin-right:6px;color:var(--gold);"></i>Confirm Password</label>
                <div style="position:relative;">
                    <input type="password" class="form-control" id="confirmPassword" placeholder="Re-enter password" name="confirm_password" required minlength="12" maxlength="128">
                    <button type="button" onclick="togglePassword('confirmPassword', this)" style="position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:1rem;color:var(--gray-500);"><i class="fas fa-eye"></i></button>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label"><i class="fas fa-ticket-alt" style="margin-right:6px;color:var(--gold);"></i>Referral Code <span style="font-weight:400;color:var(--gray-500);">(Optional)</span></label>
                <input type="text" class="form-control" placeholder="Enter referral code" name="referral_code" maxlength="20" value="<?php echo htmlspecialchars($_POST['referral_code'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label" style="display:flex;align-items:flex-start;gap:10px;">
                    <input type="checkbox" id="agreeTerms" name="agree_terms" style="accent-color:var(--gold);width:16px;height:16px;margin-top:2px;flex-shrink:0;" required>
                    <span style="font-size:0.88rem;color:var(--gray-700);cursor:pointer;line-height:1.5;">
                        I agree to the <a href="../terms.html" style="color:var(--gold);" target="_blank">Terms & Conditions</a>, <a href="../privacy.html" style="color:var(--gold);" target="_blank">Privacy Policy</a>, and <a href="../disclaimer.html" style="color:var(--gold);" target="_blank">Risk Disclaimer</a>
                    </span>
                </label>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;font-size:1rem;padding:16px;">
                <i class="fas fa-user-plus" style="margin-right:8px;"></i>Create Secure Account
            </button>
        </form>

        <div class="auth-footer">
            Already have an account? <a href="login.php">Sign in <i class="fas fa-arrow-right" style="font-size:0.8rem;"></i></a>
        </div>
        
        <!-- Security Badges -->
        <div style="margin-top:20px;display:flex;justify-content:center;gap:16px;font-size:0.7rem;color:var(--gray-500);">
            <span><i class="fas fa-lock" style="color:#2ecc71;"></i> 256-bit SSL</span>
            <span><i class="fas fa-shield-alt" style="color:#2ecc71;"></i> DDoS Protected</span>
            <span><i class="fas fa-database" style="color:#2ecc71;"></i> Encrypted Storage</span>
        </div>
    </div>
</div>

<style>
.alert {
    padding: 14px 18px;
    border-radius: var(--radius);
    margin-bottom: 24px;
    font-size: 0.9rem;
}
.alert-error {
    background: rgba(231, 76, 60, 0.1);
    border: 1px solid rgba(231, 76, 60, 0.3);
    color: #c0392b;
}
.alert-success {
    background: rgba(46, 204, 113, 0.1);
    border: 1px solid rgba(46, 204, 113, 0.3);
    color: #27ae60;
}
.alert ul {
    margin: 0;
    padding-left: 20px;
}
.strength-bar { 
    height: 5px; 
    border-radius: 3px; 
    background: var(--gray-100); 
    margin-top: 6px; 
    overflow: hidden; 
}
.strength-fill { 
    height: 100%; 
    border-radius: 3px; 
    transition: 0.4s; 
    width: 0%; 
}
</style>

<script src="../js/main.js"></script>
<script>
function togglePassword(id, btn) {
    const input = document.getElementById(id);
    const icon = btn.querySelector('i');
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

function checkStrength(val) {
    const fill = document.getElementById('strengthFill');
    const label = document.getElementById('strengthLabel');
    let score = 0;
    if (val.length >= 12) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[a-z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    
    const colors = ['#e74c3c','#e87a20','#f5a623','#2ecc71','#27ae60'];
    const labels = ['Very Weak','Weak','Fair','Strong','Very Strong'];
    const widths = ['20%','40%','60%','80%','100%'];
    
    if (val.length === 0) {
        fill.style.width = '0';
        label.textContent = '';
        return;
    }
    
    const idx = Math.min(score - 1, 4);
    fill.style.background = colors[idx] || colors[0];
    fill.style.width = widths[idx] || widths[0];
    label.textContent = labels[idx] || labels[0];
    label.style.color = colors[idx] || colors[0];
}
</script>

<?php include '../includes/footer.php'; ?>