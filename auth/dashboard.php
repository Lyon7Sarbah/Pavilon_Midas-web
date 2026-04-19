<?php
// ============================================
// PAVILON MIDAS LTD — USER DASHBOARD
// ============================================

require_once '../includes/config.php';

// Require login
requireLogin();

try {
    $pdo = getDBConnection();

    // Get user information
    $stmt = $pdo->prepare("
        SELECT u.*, COUNT(r.id) as referral_count,
               COALESCE(SUM(re.amount), 0) as total_earnings
        FROM users u
        LEFT JOIN users r ON r.referred_by = u.id
        LEFT JOIN referral_earnings re ON re.referrer_id = u.id AND re.status = 'paid'
        WHERE u.id = ?
        GROUP BY u.id
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if (!$user) {
        session_destroy();
        header('Location: login.php');
        exit;
    }

    // Get recent referrals
    $stmt = $pdo->prepare("
        SELECT u.username, u.created_at, COALESCE(SUM(re.amount), 0) as earnings
        FROM users u
        LEFT JOIN referral_earnings re ON re.referred_user_id = u.id AND re.status = 'paid'
        WHERE u.referred_by = ?
        GROUP BY u.id
        ORDER BY u.created_at DESC
        LIMIT 10
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $recent_referrals = $stmt->fetchAll();

} catch (PDOException $e) {
    error_log('Dashboard error: ' . $e->getMessage());
    $error = 'Unable to load dashboard data. Please try again later.';
}

// Include header
$page_title = 'Dashboard — Pavilon Midas Ltd';
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
      <span class="user-greeting">Welcome, <?php echo htmlspecialchars($user['first_name']); ?>!</span>
      <a href="logout.php" class="btn btn-outline btn-sm">Logout</a>
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
  <a href="logout.php" class="btn btn-outline" style="color:#e87a20;border-color:#e87a20;">Logout</a>
</div>

<!-- PAGE HERO -->
<div class="page-hero">
  <div class="container">
    <div class="page-hero-label"><i class="fas fa-tachometer-alt"></i> Member Dashboard</div>
    <h1>Welcome to Your <span class="text-gold">Trading Hub</span></h1>
    <p>Monitor your signals, track investments, and manage your referral network all from one centralized dashboard.</p>
    <div class="breadcrumb">
      <a href="../index.html">Home</a><span class="sep">›</span><span>Dashboard</span>
    </div>
  </div>
</div>

<div class="dashboard-container">
    <!-- Navigation -->
    <nav class="dashboard-nav">
        <div class="nav-container">
            <a href="../index.html" class="nav-logo">
                <img src="../assets/logo.png" alt="Pavilon Midas" onerror="this.style.display='none'">
                <div class="nav-logo-text">PAVILON MIDAS<span>Asset Management Ltd</span></div>
            </a>
            <div class="dashboard-nav-links">
                <a href="#overview" class="active">Overview</a>
                <a href="#signals">Signals</a>
                <a href="#pool">Trading Pool</a>
                <a href="#referrals">Referrals</a>
                <a href="#profile">Profile</a>
            </div>
            <div class="dashboard-actions">
                <span class="user-greeting">Welcome, <?php echo htmlspecialchars($user['first_name']); ?>!</span>
                <a href="logout.php" class="btn btn-outline btn-sm">Logout</a>
            </div>
        </div>
    </nav>

    <div class="dashboard-content">
        <!-- Overview Section -->
        <section id="overview" class="dashboard-section active">
            <h1>Dashboard Overview</h1>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-users"></i></div>
                    <div class="stat-content">
                        <div class="stat-number"><?php echo number_format($user['referral_count']); ?></div>
                        <div class="stat-label">Total Referrals</div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-dollar-sign"></i></div>
                    <div class="stat-content">
                        <div class="stat-number">$<?php echo number_format($user['total_earnings'], 2); ?></div>
                        <div class="stat-label">Referral Earnings</div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-chart-line"></i></div>
                    <div class="stat-content">
                        <div class="stat-number">Premium</div>
                        <div class="stat-label">Signal Access</div>
                    </div>
                </div>

                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-wallet"></i></div>
                    <div class="stat-content">
                        <div class="stat-number">Active</div>
                        <div class="stat-label">Pool Investment</div>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="dashboard-card">
                    <h3>Your Referral Code</h3>
                    <div class="referral-code">
                        <code><?php echo htmlspecialchars($user['referral_code']); ?></code>
                        <button class="btn btn-sm" onclick="copyReferralCode('<?php echo $user['referral_code']; ?>')">
                            <i class="fas fa-copy"></i> Copy
                        </button>
                    </div>
                    <p>Share this code with friends and earn commissions on their investments!</p>
                </div>

                <div class="dashboard-card">
                    <h3>Quick Actions</h3>
                    <div class="action-buttons">
                        <a href="../signals.html" class="btn btn-primary">
                            <i class="fas fa-chart-bar"></i> View Signals
                        </a>
                        <a href="../pool-investment.html" class="btn btn-secondary">
                            <i class="fas fa-wallet"></i> Join Pool
                        </a>
                        <a href="#referrals" class="btn btn-outline">
                            <i class="fas fa-users"></i> Manage Referrals
                        </a>
                    </div>
                </div>
            </div>
        </section>

        <!-- Signals Section -->
        <section id="signals" class="dashboard-section">
            <h2>Trading Signals</h2>
            <div class="dashboard-card">
                <p>Your premium signal access is active. Latest signals are available below.</p>
                <div class="signal-placeholder">
                    <i class="fas fa-chart-bar"></i>
                    <h4>Latest Signals</h4>
                    <p>Signal data would be displayed here from your trading system.</p>
                    <a href="../signals.html" class="btn btn-primary">View All Signals</a>
                </div>
            </div>
        </section>

        <!-- Pool Section -->
        <section id="pool" class="dashboard-section">
            <h2>Trading Pool</h2>
            <div class="dashboard-card">
                <p>Monitor your pool investments and performance.</p>
                <div class="pool-placeholder">
                    <i class="fas fa-wallet"></i>
                    <h4>Pool Investments</h4>
                    <p>Your current pool positions and returns would be shown here.</p>
                    <a href="../pool-investment.html" class="btn btn-primary">Manage Pool</a>
                </div>
            </div>
        </section>

        <!-- Referrals Section -->
        <section id="referrals" class="dashboard-section">
            <h2>Referral Program</h2>
            <div class="dashboard-card">
                <h3>Your Referrals (<?php echo count($recent_referrals); ?>)</h3>
                <?php if (empty($recent_referrals)): ?>
                    <p>No referrals yet. Share your referral code to start earning!</p>
                <?php else: ?>
                    <div class="referrals-table">
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Join Date</th>
                                    <th>Earnings</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($recent_referrals as $referral): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($referral['username']); ?></td>
                                        <td><?php echo date('M j, Y', strtotime($referral['created_at'])); ?></td>
                                        <td>$<?php echo number_format($referral['earnings'], 2); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </section>

        <!-- Profile Section -->
        <section id="profile" class="dashboard-section">
            <h2>Profile Settings</h2>
            <div class="dashboard-card">
                <h3>Account Information</h3>
                <div class="profile-info">
                    <div class="info-row">
                        <span class="label">Name:</span>
                        <span class="value"><?php echo htmlspecialchars($user['first_name'] . ' ' . $user['last_name']); ?></span>
                    </div>
                    <div class="info-row">
                        <span class="label">Username:</span>
                        <span class="value"><?php echo htmlspecialchars($user['username']); ?></span>
                    </div>
                    <div class="info-row">
                        <span class="label">Email:</span>
                        <span class="value"><?php echo htmlspecialchars($user['email']); ?></span>
                    </div>
                    <div class="info-row">
                        <span class="label">Phone:</span>
                        <span class="value"><?php echo htmlspecialchars($user['phone'] ?: 'Not provided'); ?></span>
                    </div>
                    <div class="info-row">
                        <span class="label">Country:</span>
                        <span class="value"><?php echo htmlspecialchars($user['country'] ?: 'Not provided'); ?></span>
                    </div>
                    <div class="info-row">
                        <span class="label">Member Since:</span>
                        <span class="value"><?php echo date('M j, Y', strtotime($user['created_at'])); ?></span>
                    </div>
                </div>
                <div class="profile-actions">
                    <button class="btn btn-outline">Edit Profile</button>
                    <button class="btn btn-outline">Change Password</button>
                </div>
            </div>
        </section>
    </div>
</div>

<style>
.dashboard-container { min-height: 100vh; background: var(--off-white); }
.dashboard-nav { background: white; box-shadow: 0 2px 10px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
.dashboard-nav .nav-container { max-width: 1200px; margin: 0 auto; padding: 0 24px; display: flex; align-items: center; justify-content: space-between; height: 70px; }
.dashboard-nav-links { display: flex; gap: 30px; }
.dashboard-nav-links a { color: var(--navy); text-decoration: none; font-weight: 500; padding: 8px 0; border-bottom: 2px solid transparent; transition: all 0.3s; }
.dashboard-nav-links a.active, .dashboard-nav-links a:hover { border-bottom-color: var(--gold); color: var(--gold); }
.user-greeting { font-weight: 500; color: var(--navy); margin-right: 20px; }

.dashboard-content { max-width: 1200px; margin: 0 auto; padding: 40px 24px; }
.dashboard-section { display: none; }
.dashboard-section.active { display: block; }
.dashboard-section h1 { color: var(--navy); margin-bottom: 30px; }
.dashboard-section h2 { color: var(--navy); margin-bottom: 20px; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }
.stat-card { background: white; padding: 25px; border-radius: var(--radius); box-shadow: 0 2px 10px rgba(0,0,0,0.1); display: flex; align-items: center; gap: 20px; }
.stat-icon { font-size: 2rem; color: var(--gold); }
.stat-number { font-size: 2rem; font-weight: bold; color: var(--navy); }
.stat-label { color: var(--gray-600); font-size: 0.9rem; }

.dashboard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-bottom: 40px; }
.dashboard-card { background: white; padding: 25px; border-radius: var(--radius); box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
.referral-code { display: flex; align-items: center; gap: 15px; margin: 15px 0; }
.referral-code code { background: var(--off-white); padding: 10px 15px; border-radius: 5px; font-family: monospace; font-size: 1.1rem; flex: 1; }
.action-buttons { display: flex; gap: 10px; flex-wrap: wrap; }

.signal-placeholder, .pool-placeholder { text-align: center; padding: 40px; color: var(--gray-600); }
.signal-placeholder i, .pool-placeholder i { font-size: 3rem; color: var(--gold); margin-bottom: 20px; }

.referrals-table table { width: 100%; border-collapse: collapse; }
.referrals-table th, .referrals-table td { padding: 12px; text-align: left; border-bottom: 1px solid var(--gray-200); }
.referrals-table th { background: var(--off-white); font-weight: 600; color: var(--navy); }

.profile-info { margin: 20px 0; }
.info-row { display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid var(--gray-200); }
.label { font-weight: 500; color: var(--navy); }
.value { color: var(--gray-700); }
.profile-actions { margin-top: 20px; display: flex; gap: 10px; }

.alert { padding: 15px; border-radius: var(--radius); margin-bottom: 20px; }
.alert-error { background: #fee; color: #c33; border: 1px solid #fcc; }
.alert-success { background: #efe; color: #363; border: 1px solid #cfc; }

@media (max-width: 768px) {
    .dashboard-nav-links { display: none; }
    .stats-grid { grid-template-columns: 1fr; }
    .dashboard-grid { grid-template-columns: 1fr; }
    .action-buttons { flex-direction: column; }
    .referral-code { flex-direction: column; align-items: stretch; }
}
</style>

<script>
function copyReferralCode(code) {
    navigator.clipboard.writeText(code).then(() => {
        alert('Referral code copied to clipboard!');
    });
}

// Tab navigation
document.querySelectorAll('.dashboard-nav-links a').forEach(link => {
    link.addEventListener('click', function(e) {
        e.preventDefault();
        const targetId = this.getAttribute('href').substring(1);

        // Update active link
        document.querySelectorAll('.dashboard-nav-links a').forEach(l => l.classList.remove('active'));
        this.classList.add('active');

        // Show target section
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });
        document.getElementById(targetId).classList.add('active');
    });
});
</script>

<?php include '../includes/footer.php'; ?>