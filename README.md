# Pavilion Midas Academy Ltd - Authentication System Setup

## Overview
This authentication system provides secure user registration, login, and dashboard functionality for the Pavilon Midas financial services website.

## Features
- ✅ Secure user registration with validation
- ✅ Password hashing with bcrypt
- ✅ Session-based authentication
- ✅ CSRF protection
- ✅ Account lockout after failed attempts
- ✅ Referral system
- ✅ User dashboard
- ✅ Activity logging

## File Structure
```
/
├── auth/                          # PHP authentication files
│   ├── login.php                 # Login processing
│   ├── register.php              # Registration processing
│   ├── dashboard.php             # User dashboard
│   ├── logout.php                # Logout processing
│   └── setup.php                 # Database setup (DELETE AFTER USE)
├── includes/                     # PHP includes
│   ├── config.php                # Configuration and utilities
│   ├── header.php                # HTML header
│   └── footer.php                # HTML footer
├── login.html                    # Login form (updated to point to PHP)
├── register.html                 # Registration form (updated to point to PHP)
├── css/style.css                 # Existing styles
└── js/main.js                    # Existing JavaScript
```

## Setup Instructions

### 1. Database Setup
1. Create a MySQL database named `pavilon_midas`
2. Create a database user with privileges
3. Run the setup script: Visit `yourdomain.com/auth/setup.php`
4. **IMPORTANT**: Delete `auth/setup.php` after setup for security

### 2. Configuration
Edit `includes/config.php` and update:
```php
define('DB_HOST', 'localhost');
define('DB_NAME', 'pavilon_midas');
define('DB_USER', 'your_db_user');
define('DB_PASS', 'your_db_password');
define('SITE_URL', 'https://yourdomain.com');
```

### 3. Upload Files
Upload all files to your cPanel public_html directory, maintaining the folder structure.

### 4. File Permissions
Set appropriate permissions:
- `includes/config.php`: 644 (readable)
- Other PHP files: 644
- Delete `auth/setup.php` after use

### 5. Test the System
1. Visit `yourdomain.com/auth/setup.php` to create tables
2. Try registration at `yourdomain.com/register.html`
3. Try login at `yourdomain.com/login.html`
4. Access dashboard at `yourdomain.com/auth/dashboard.php`

## Security Features

### Password Security
- Minimum 8 characters
- Requires uppercase, lowercase, and numbers
- Hashed with bcrypt (cost factor 12)

### Account Protection
- 5 failed login attempts trigger 15-minute lockout
- CSRF tokens on all forms
- Session timeout after 30 minutes
- Secure session cookies (HttpOnly, Secure)

### Data Protection
- All sensitive data encrypted in database
- Input sanitization and validation
- SQL injection prevention with prepared statements

## Database Tables

### users
- User account information
- Password hashes, personal details
- Referral codes and relationships

### user_sessions
- Session management for security

### referral_earnings
- Commission tracking for referrals

### user_activity_log
- Security audit trail

## Usage Examples

### Registration Flow
1. User fills `register.html` form
2. Form submits to `auth/register.php`
3. PHP validates input and creates account
4. User redirected to dashboard

### Login Flow
1. User fills `login.html` form
2. Form submits to `auth/login.php`
3. PHP verifies credentials
4. User redirected to dashboard or original page

### Dashboard Access
- Protected pages check `requireLogin()`
- Shows user stats, referrals, and quick actions

## Customization

### Styling
- Uses existing CSS variables
- Responsive design maintained
- Font Awesome icons throughout

### Features
- Add email verification by modifying registration
- Add password reset functionality
- Extend dashboard with more features

## Troubleshooting

### Common Issues
1. **Database connection fails**: Check config.php credentials
2. **Forms not submitting**: Verify file paths and permissions
3. **Sessions not working**: Check PHP session configuration
4. **CSRF errors**: Ensure tokens are generated and validated

### Error Logs
- PHP errors logged to server error log
- Database errors logged with `error_log()`
- Check cPanel error logs for issues

## Support
For issues or customization requests, check the PHP error logs and database connection.

## Security Notes
- Change default admin password after setup
- Keep PHP and MySQL updated
- Regular security audits recommended
- Monitor user_activity_log for suspicious activity