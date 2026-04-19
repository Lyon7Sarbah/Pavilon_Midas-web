<?php
// ============================================
// PAVILON MIDAS LTD — REGISTRATION PROCESSING
// ============================================

require_once '../includes/config.php';

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs
    $first_name = sanitize($_POST['first_name'] ?? '');
    $last_name = sanitize($_POST['last_name'] ?? '');
    $username = sanitize($_POST['username'] ?? '');
    $email = sanitize($_POST['email'] ?? '');
    $phone = sanitize($_POST['phone'] ?? '');
    $country = sanitize($_POST['country'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $referral_code = sanitize($_POST['referral_code'] ?? '');
    $agree_terms = isset($_POST['agree_terms']);

    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Security validation failed. Please try again.';
    }

    // Validate required fields
    if (empty($first_name)) $errors[] = 'First name is required.';
    if (empty($last_name)) $errors[] = 'Last name is required.';
    if (empty($username)) $errors[] = 'Username is required.';
    if (empty($email)) $errors[] = 'Email address is required.';
    if (empty($password)) $errors[] = 'Password is required.';
    if (!$agree_terms) $errors[] = 'You must agree to the terms and conditions.';

    // Validate email format
    if (!empty($email) && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }

    // Validate username format
    if (!empty($username) && !preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
        $errors[] = 'Username must be 3-50 characters and contain only letters, numbers, and underscores.';
    }

    // Validate password strength
    if (!empty($password)) {
        if (strlen($password) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
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
    }

    // Validate password confirmation
    if ($password !== $confirm_password) {
        $errors[] = 'Passwords do not match.';
    }

    // Validate phone format (optional but if provided)
    if (!empty($phone) && !preg_match('/^\+?[0-9\s\-\(\)]{10,20}$/', $phone)) {
        $errors[] = 'Please enter a valid phone number.';
    }

    // Check for existing users
    if (empty($errors)) {
        try {
            $pdo = getDBConnection();

            // Check if email exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            if ($stmt->fetch()) {
                $errors[] = 'An account with this email address already exists.';
            }

            // Check if username exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $errors[] = 'This username is already taken.';
            }

            // Validate referral code if provided
            $referrer_id = null;
            if (!empty($referral_code)) {
                $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = ?");
                $stmt->execute([$referral_code]);
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

            // Generate unique referral code
            $user_referral_code = generateReferralCode($pdo);

            // Hash password
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            // Insert user
            $stmt = $pdo->prepare("
                INSERT INTO users (
                    username, email, password_hash, first_name, last_name,
                    phone, country, referral_code, referred_by, account_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
            ");

            $stmt->execute([
                $username, $email, $password_hash, $first_name, $last_name,
                $phone, $country, $user_referral_code, $referrer_id
            ]);

            $user_id = $pdo->lastInsertId();

            // Log registration
            logActivity($user_id, 'registration', 'User account created');

            // Set session
            $_SESSION['user_id'] = $user_id;
            $_SESSION['user_email'] = $email;
            $_SESSION['login_time'] = time();

            // Success message
            $success = 'Account created successfully! Welcome to Pavilon Midas.';

            // Redirect after 2 seconds
            header('refresh:2;url=' . SITE_URL . '/auth/dashboard.php');

        } catch (PDOException $e) {
            error_log('Registration error: ' . $e->getMessage());
            $errors[] = 'Failed to create account. Please try again.';
        }
    }
}

// Generate new CSRF token
$csrf_token = generateCSRFToken();

// Helper function to generate unique referral code
function generateReferralCode($pdo) {
    do {
        $code = strtoupper(substr(md5(uniqid(mt_rand(), true)), 0, 8));
        $stmt = $pdo->prepare("SELECT id FROM users WHERE referral_code = ?");
        $stmt->execute([$code]);
        $exists = $stmt->fetch();
    } while ($exists);

    return $code;
}

// Helper function to log activity
function logActivity($user_id, $action, $details = '') {
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO user_activity_log (user_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $user_id,
            $action,
            $_SERVER['REMOTE_ADDR'] ?? '',
            $_SERVER['HTTP_USER_AGENT'] ?? '',
            $details
        ]);
    } catch (PDOException $e) {
        error_log('Activity logging error: ' . $e->getMessage());
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
      <img src="../assets/logo.png" alt="Pavilon Midas" onerror="this.style.display='none'">
      <div class="nav-logo-text">PAVILON MIDAS<span>Asset Management Ltd</span></div>
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
    <h1>Create Your <span class="text-gold">Trading Account</span> Today</h1>
    <p>Join thousands of successful traders across Ghana and Nigeria. Start with free signals and build your wealth through our proven trading systems.</p>
    <div class="breadcrumb">
      <a href="../index.html">Home</a><span class="sep">›</span><span>Register</span>
    </div>
  </div>
</div>

<div class="auth-page" style="padding:100px 24px 60px;">
    <div class="auth-card fade-in visible" style="max-width:560px;">
        <div class="auth-logo">
            <img src="../assets/logo.png" alt="Pavilon Midas" onerror="this.style.display='none'">
        </div>
        <h2 class="auth-title">Create Your Account</h2>
        <p class="auth-subtitle">Join thousands of investors across Ghana and Nigeria. It's free to register.</p>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-error">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?php echo $error; ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if ($success): ?>
            <div class="alert alert-success"><?php echo $success; ?></div>
        <?php endif; ?>

        <!-- PERKS -->
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:28px;">
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.2rem;margin-bottom:4px;"><i class="fas fa-chart-bar"></i></div>Free Signals Trial
            </div>
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.2rem;margin-bottom:4px;"><i class="fas fa-wallet"></i></div>Pool Access
            </div>
            <div style="text-align:center;padding:12px 8px;background:var(--off-white);border-radius:var(--radius);font-size:0.78rem;color:var(--navy);">
                <div style="font-size:1.2rem;margin-bottom:4px;"><i class="fas fa-handshake"></i></div>Referral Link
            </div>
        </div>

        <form action="register.php" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
                <div class="form-group">
                    <label class="form-label">First Name</label>
                    <input type="text" class="form-control" placeholder="Kwame" name="first_name" required value="<?php echo sanitize($_POST['first_name'] ?? ''); ?>">
                </div>
                <div class="form-group">
                    <label class="form-label">Last Name</label>
                    <input type="text" class="form-control" placeholder="Mensah" name="last_name" required value="<?php echo sanitize($_POST['last_name'] ?? ''); ?>">
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">Username</label>
                <input type="text" class="form-control" placeholder="kwamemensah" name="username" required value="<?php echo sanitize($_POST['username'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label">Email Address</label>
                <input type="email" class="form-control" placeholder="you@example.com" name="email" required value="<?php echo sanitize($_POST['email'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label">Phone / WhatsApp</label>
                <input type="tel" class="form-control" placeholder="+233 XX XXX XXXX" name="phone" value="<?php echo sanitize($_POST['phone'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label">Country</label>
                <select class="form-control form-select" name="country" required>
                    <option value="">Select your country...</option>
                    <option value="GH" <?php echo (sanitize($_POST['country'] ?? '') === 'GH') ? 'selected' : ''; ?>>Ghana</option>
                    <option value="NG" <?php echo (sanitize($_POST['country'] ?? '') === 'NG') ? 'selected' : ''; ?>>Nigeria</option>
                    <option value="SN" <?php echo (sanitize($_POST['country'] ?? '') === 'SN') ? 'selected' : ''; ?>>Senegal</option>
                    <option value="CI" <?php echo (sanitize($_POST['country'] ?? '') === 'CI') ? 'selected' : ''; ?>>Côte d'Ivoire</option>
                    <option value="Other" <?php echo (sanitize($_POST['country'] ?? '') === 'Other') ? 'selected' : ''; ?>>Other</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label" style="display:flex;align-items:center;justify-content:space-between;">
                    Password
                    <span id="strengthLabel" style="font-size:0.75rem;color:var(--gray-500);font-weight:400;"></span>
                </label>
                <div style="position:relative;">
                    <input type="password" class="form-control" id="regPassword" placeholder="Min. 8 characters" name="password" required oninput="checkStrength(this.value)">
                    <button type="button" onclick="togglePassword('regPassword', this)" style="position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:1rem;color:var(--gray-500);"><i class="fas fa-eye"></i></button>
                </div>
                <div class="strength-bar"><div class="strength-fill" id="strengthFill"></div></div>
            </div>
            <div class="form-group">
                <label class="form-label">Confirm Password</label>
                <input type="password" class="form-control" placeholder="Re-enter password" name="confirm_password" required>
            </div>
            <div class="form-group">
                <label class="form-label">Referral Code <span style="font-weight:400;color:var(--gray-500);">(Optional)</span></label>
                <input type="text" class="form-control" placeholder="Enter referral code if you have one" name="referral_code" value="<?php echo sanitize($_POST['referral_code'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label" style="display:flex;align-items:flex-start;gap:10px;">
                    <input type="checkbox" id="agreeTerms" name="agree_terms" style="accent-color:var(--gold);width:16px;height:16px;margin-top:2px;flex-shrink:0;" required>
                    <span style="font-size:0.88rem;color:var(--gray-700);cursor:pointer;line-height:1.5;">
                        I agree to the <a href="../terms.html" style="color:var(--gold);" target="_blank">Terms & Conditions</a>, <a href="../privacy.html" style="color:var(--gold);" target="_blank">Privacy Policy</a>, and <a href="../disclaimer.html" style="color:var(--gold);" target="_blank">Risk Disclaimer</a>
                    </span>
                </label>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;font-size:1rem;padding:16px;">Create My Account <i class="fas fa-rocket"></i></button>
        </form>

        <div class="auth-footer">
            Already have an account? <a href="login.php">Sign in →</a>
        </div>
    </div>
</div>

<script src="../js/main.js"></script>
<script>
function togglePassword(id, btn) {
    const input = document.getElementById(id);
    if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = '<i class="fas fa-lock"></i>';
    } else {
        input.type = 'password';
        btn.innerHTML = '<i class="fas fa-eye"></i>';
    }
}

function checkStrength(val) {
    const fill = document.getElementById('strengthFill');
    const label = document.getElementById('strengthLabel');
    let score = 0;
    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;
    const colors = ['#e74c3c','#e87a20','#f5a623','#2ecc71'];
    const labels = ['Weak','Fair','Good','Strong'];
    const widths = ['25%','50%','75%','100%'];
    if (val.length === 0) {
        fill.style.width = '0';
        label.textContent = '';
        return;
    }
    fill.style.background = colors[score-1] || colors[0];
    fill.style.width = widths[score-1] || widths[0];
    label.textContent = labels[score-1] || labels[0];
    label.style.color = colors[score-1] || colors[0];
}
</script>

<?php include '../includes/footer.php'; ?>