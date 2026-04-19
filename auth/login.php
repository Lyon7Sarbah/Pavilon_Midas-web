<?php
// ============================================
// PAVILON MIDAS LTD — LOGIN PROCESSING
// ============================================

require_once '../includes/config.php';

// Redirect if already logged in
redirectIfLoggedIn();

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize inputs
    $email = sanitize($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']) ? true : false;

    // Validate CSRF token
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $errors[] = 'Security validation failed. Please try again.';
    }

    // Validate inputs
    if (empty($email)) {
        $errors[] = 'Email address is required.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please enter a valid email address.';
    }

    if (empty($password)) {
        $errors[] = 'Password is required.';
    }

    if (empty($errors)) {
        try {
            $pdo = getDBConnection();

            // Check if account is locked
            $stmt = $pdo->prepare("
                SELECT id, password_hash, login_attempts, locked_until, account_status
                FROM users
                WHERE email = ?
            ");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            if ($user) {
                // Check if account is locked
                if ($user['locked_until'] && strtotime($user['locked_until']) > time()) {
                    $remaining = ceil((strtotime($user['locked_until']) - time()) / 60);
                    $errors[] = "Account is temporarily locked due to too many failed attempts. Try again in {$remaining} minutes.";
                }
                // Check account status
                elseif ($user['account_status'] !== 'active') {
                    $errors[] = 'Your account is not active. Please contact support.';
                }
                // Verify password
                elseif (password_verify($password, $user['password_hash'])) {
                    // Successful login
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['user_email'] = $email;
                    $_SESSION['login_time'] = time();

                    // Reset login attempts
                    $pdo->prepare("UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = NOW() WHERE id = ?")
                        ->execute([$user['id']]);

                    // Log successful login
                    logActivity($user['id'], 'login_success', 'User logged in successfully');

                    // Set session cookie parameters
                    $lifetime = $remember ? 2592000 : SESSION_LIFETIME; // 30 days or 30 minutes
                    session_set_cookie_params($lifetime, '/', '', true, true); // HttpOnly, Secure

                    // Redirect to dashboard or intended page
                    $redirect = $_GET['redirect'] ?? SITE_URL . '/auth/dashboard.php';
                    header('Location: ' . $redirect);
                    exit;

                } else {
                    // Failed login attempt
                    $attempts = $user['login_attempts'] + 1;
                    $locked_until = null;

                    if ($attempts >= MAX_LOGIN_ATTEMPTS) {
                        $locked_until = date('Y-m-d H:i:s', time() + LOCKOUT_TIME);
                        logActivity($user['id'], 'account_locked', 'Account locked due to too many failed attempts');
                    }

                    $pdo->prepare("UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?")
                        ->execute([$attempts, $locked_until, $user['id']]);

                    $remaining = MAX_LOGIN_ATTEMPTS - $attempts;
                    if ($remaining > 0) {
                        $errors[] = "Invalid email or password. {$remaining} attempts remaining.";
                    } else {
                        $errors[] = 'Account locked due to too many failed attempts. Try again later.';
                    }

                    logActivity($user['id'], 'login_failed', 'Failed login attempt');
                }
            } else {
                $errors[] = 'Invalid email or password.';
            }

        } catch (PDOException $e) {
            error_log('Login error: ' . $e->getMessage());
            $errors[] = 'A system error occurred. Please try again later.';
        }
    }
}

// Generate new CSRF token
$csrf_token = generateCSRFToken();

// Include header
$page_title = 'Login — Pavilon Midas Ltd';
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
      <a href="login.php" class="btn btn-outline btn-sm active">Login</a>
      <a href="register.php" class="btn btn-primary btn-sm">Register</a>
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
    <div class="page-hero-label"><i class="fas fa-sign-in-alt"></i> Account Access</div>
    <h1>Sign In to Your <span class="text-gold">Pavilon Midas</span> Account</h1>
    <p>Access your signals, track your investments, and manage your referral network from your personalized dashboard.</p>
    <div class="breadcrumb">
      <a href="../index.html">Home</a><span class="sep">›</span><span>Login</span>
    </div>
  </div>
</div>

<div class="auth-page">
    <div class="auth-card fade-in visible">
        <div class="auth-logo">
            <img src="../assets/logo.png" alt="Pavilon Midas" onerror="this.style.display='none'">
            <div style="font-family:var(--font-display);font-size:0.75rem;letter-spacing:2px;text-transform:uppercase;color:var(--gold);margin-top:6px;">Asset Management Ltd</div>
        </div>
        <h2 class="auth-title">Welcome Back</h2>
        <p class="auth-subtitle">Sign in to access your signals, pool investments, and referral dashboard.</p>

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

        <form action="login.php<?php echo isset($_GET['redirect']) ? '?redirect=' . urlencode($_GET['redirect']) : ''; ?>" method="post">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">

            <div class="form-group">
                <label class="form-label">Email Address</label>
                <input type="email" class="form-control" placeholder="you@example.com" name="email" required autocomplete="email" value="<?php echo sanitize($_POST['email'] ?? ''); ?>">
            </div>
            <div class="form-group">
                <label class="form-label" style="display:flex;justify-content:space-between;align-items:center;">
                    Password
                    <a href="forgot-password.php" style="font-weight:400;color:var(--gold);font-size:0.82rem;">Forgot password?</a>
                </label>
                <div style="position:relative;">
                    <input type="password" class="form-control" id="loginPassword" placeholder="••••••••" name="password" required autocomplete="current-password">
                    <button type="button" onclick="togglePassword('loginPassword', this)" style="position:absolute;right:14px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;font-size:1rem;color:var(--gray-500);"><i class="fas fa-eye"></i></button>
                </div>
            </div>
            <div style="display:flex;align-items:center;gap:10px;margin-bottom:24px;">
                <input type="checkbox" id="rememberMe" name="remember" style="accent-color:var(--gold);width:16px;height:16px;">
                <label for="rememberMe" style="font-size:0.88rem;color:var(--gray-700);cursor:pointer;">Remember me for 30 days</label>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;font-size:1rem;padding:16px;">Sign In →</button>
        </form>

        <div class="auth-divider">or continue with</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <button class="btn btn-outline-gold" style="justify-content:center;font-size:0.85rem;"><i class="fab fa-telegram"></i> Telegram</button>
            <button class="btn" style="border:2px solid var(--gray-100);color:var(--navy);justify-content:center;font-size:0.85rem;background:var(--white);"><i class="fas fa-globe"></i> Google</button>
        </div>

        <div class="auth-footer">
            Don't have an account? <a href="register.php">Create one free →</a>
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
</script>

<?php include '../includes/footer.php'; ?>