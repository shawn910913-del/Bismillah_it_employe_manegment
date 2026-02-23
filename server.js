const express = require('express');
const cors = require('cors');
const path = require('path');
const XLSX = require('xlsx');
const {
    initDatabase,
    addAccount,
    bulkAddAccounts,
    getAllAccounts,
    getStats,
    getAccountsByEmployee,
    incrementDuplicateCount,
    getTotalDuplicates,
    deleteAllAccounts,
    getDuplicatesByEmployee,
    exportAllAccounts,
    loginUser,
    validateToken,
    logoutUser,
    createUser,
    getAllUsers,
    deleteUser,
    toggleUserActive,
    changeUserPassword,
    deleteAccountsByEmployee,
    saveDB,
    flagAccount,
    unflagAccount,
    getFlaggedAccounts,
    getFlaggedByEmployee,
    setEmployeeRate,
    getEmployeeProfile,
    getAllEmployeeProfiles,
    getFlagReport,
    bulkFlagByUsernames,
    unflagAllAccounts
} = require('./database');


const app = express();
const PORT = process.env.PORT || 3000;

// ============ RATE LIMITING ============
const loginAttempts = new Map(); // ip -> { count, lastAttempt }
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_LOGIN_ATTEMPTS = 10;

function checkRateLimit(ip) {
    const now = Date.now();
    const record = loginAttempts.get(ip);
    if (!record) return true;
    if (now - record.lastAttempt > RATE_LIMIT_WINDOW) { loginAttempts.delete(ip); return true; }
    return record.count < MAX_LOGIN_ATTEMPTS;
}

function recordLoginAttempt(ip) {
    const now = Date.now();
    const record = loginAttempts.get(ip) || { count: 0, lastAttempt: now };
    record.count++;
    record.lastAttempt = now;
    loginAttempts.set(ip, record);
}

function resetLoginAttempts(ip) { loginAttempts.delete(ip); }

// ...existing code...
// Delete all accounts for a specific employee (Admin only)
app.delete('/api/accounts/employee/:name', authMiddleware, adminOnly, (req, res) => {
    const employeeName = req.params.name;
    if (!employeeName) {
        return res.status(400).json({ success: false, message: 'Employee name required' });
    }
    res.json(deleteAccountsByEmployee(employeeName));
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ============ AUTH MIDDLEWARE ============
function authMiddleware(req, res, next) {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const user = validateToken(token);
    if (!user) {
        return res.status(401).json({ success: false, message: 'Unauthorized. Please login.' });
    }
    req.user = user;
    next();
}

function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Admin access required' });
    }
    next();
}

// ============ AUTH ROUTES ============
app.post('/api/auth/login', (req, res) => {
    const ip = req.ip || req.connection.remoteAddress;
    if (!checkRateLimit(ip)) {
        return res.status(429).json({ success: false, message: 'Too many login attempts. Try again in 15 minutes.' });
    }

    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    const result = loginUser(username.trim(), password);
    if (result.success) { resetLoginAttempts(ip); }
    else { recordLoginAttempt(ip); }
    res.json(result);
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    res.json({ success: true, user: req.user });
});

app.post('/api/auth/logout', authMiddleware, (req, res) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    logoutUser(token);
    res.json({ success: true, message: 'Logged out' });
});

// Employee can change their own password
app.patch('/api/auth/change-password', authMiddleware, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
        return res.status(400).json({ success: false, message: 'Current password and new password required' });
    }
    if (newPassword.length < 4) {
        return res.status(400).json({ success: false, message: 'New password must be at least 4 characters' });
    }
    // Verify current password
    const loginCheck = loginUser(req.user.username, currentPassword);
    if (!loginCheck.success) {
        return res.json({ success: false, message: 'Current password is incorrect' });
    }
    // Logout the temp token from verification
    if (loginCheck.token) logoutUser(loginCheck.token);
    const result = changeUserPassword(req.user.id, newPassword);
    res.json(result);
});

// ============ USER MANAGEMENT (Admin only) ============
app.post('/api/users', authMiddleware, adminOnly, (req, res) => {
    const { username, password, display_name, role } = req.body;
    if (!username || !password || !display_name) {
        return res.status(400).json({ success: false, message: 'username, password, display_name required' });
    }
    const validRole = (role === 'admin') ? 'admin' : 'employee';
    const result = createUser(username.trim(), password, display_name.trim(), validRole);
    res.json(result);
});

app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
    res.json(getAllUsers());
});

app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
    res.json(deleteUser(parseInt(req.params.id)));
});

app.patch('/api/users/:id/toggle', authMiddleware, adminOnly, (req, res) => {
    res.json(toggleUserActive(parseInt(req.params.id)));
});

app.patch('/api/users/:id/password', authMiddleware, adminOnly, (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ success: false, message: 'password required' });
    res.json(changeUserPassword(parseInt(req.params.id), password));
});

// ============ ACCOUNT ROUTES ============
app.get('/api/ping', (req, res) => {
    res.json({ status: 'online', timestamp: new Date().toISOString() });
});

// Health check for Render
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

app.post('/api/accounts', authMiddleware, (req, res) => {
    const { username, password, tfa_hash } = req.body;
    const employee_name = req.user.display_name;

    if (!username || !password || !tfa_hash) {
        return res.status(400).json({ success: false, message: 'All fields required: username, password, tfa_hash' });
    }

    const result = addAccount(username.trim(), password.trim(), tfa_hash.trim(), employee_name);
    if (result.duplicate) incrementDuplicateCount();
    res.json(result);
});

app.post('/api/accounts/sync', authMiddleware, (req, res) => {
    const { accounts } = req.body;
    if (!accounts || !Array.isArray(accounts) || accounts.length === 0) {
        return res.status(400).json({ success: false, message: 'No accounts to sync' });
    }

    const syncAccounts = accounts.map(a => ({ ...a, employee_name: req.user.display_name }));
    const results = bulkAddAccounts(syncAccounts);
    for (let i = 0; i < results.duplicates; i++) incrementDuplicateCount();

    res.json({
        success: true,
        message: `Synced: ${results.added} added, ${results.duplicates} duplicates, ${results.errors} errors`,
        ...results
    });
});

app.get('/api/accounts', authMiddleware, adminOnly, (req, res) => {
    res.json(getAllAccounts());
});

app.get('/api/stats', authMiddleware, adminOnly, (req, res) => {
    const stats = getStats();
    stats.totalDuplicateAttempts = getTotalDuplicates();
    res.json(stats);
});

app.get('/api/accounts/employee/:name', authMiddleware, adminOnly, (req, res) => {
    res.json(getAccountsByEmployee(req.params.name));
});

// Employee can view their own submissions and stats
app.get('/api/my-accounts', authMiddleware, (req, res) => {
    const accounts = getAccountsByEmployee(req.user.display_name);
    res.json({ success: true, accounts, total: accounts.length });
});

app.get('/api/export', authMiddleware, adminOnly, (req, res) => {
    res.type('text/plain').send(exportAllAccounts());
});

app.delete('/api/accounts', authMiddleware, adminOnly, (req, res) => {
    res.json(deleteAllAccounts());
});

app.get('/api/duplicates', authMiddleware, adminOnly, (req, res) => {
    res.json(getDuplicatesByEmployee());
});

// ============ FLAG / UNFLAG ROUTES (Admin) ============
app.patch('/api/accounts/:id/flag', authMiddleware, adminOnly, (req, res) => {
    const { reason } = req.body;
    res.json(flagAccount(parseInt(req.params.id), reason));
});

app.patch('/api/accounts/:id/unflag', authMiddleware, adminOnly, (req, res) => {
    res.json(unflagAccount(parseInt(req.params.id)));
});

app.get('/api/flagged', authMiddleware, adminOnly, (req, res) => {
    res.json(getFlaggedAccounts());
});

app.get('/api/flag-report', authMiddleware, adminOnly, (req, res) => {
    res.json(getFlagReport());
});

// Bulk flag: admin pastes usernames, system auto-matches and flags
app.post('/api/accounts/bulk-flag', authMiddleware, adminOnly, (req, res) => {
    const { usernames, reason } = req.body;
    if (!usernames || !Array.isArray(usernames) || usernames.length === 0) {
        return res.status(400).json({ success: false, message: 'Provide an array of usernames to flag' });
    }
    res.json(bulkFlagByUsernames(usernames, reason));
});

// Unflag all accounts
app.post('/api/accounts/unflag-all', authMiddleware, adminOnly, (req, res) => {
    res.json(unflagAllAccounts());
});

// ============ RATE & EMPLOYEE PROFILES (Admin) ============
app.patch('/api/users/:id/rate', authMiddleware, adminOnly, (req, res) => {
    const { rate } = req.body;
    if (rate === undefined || rate === null || isNaN(rate) || rate < 0) {
        return res.status(400).json({ success: false, message: 'Valid rate required (>= 0)' });
    }
    res.json(setEmployeeRate(parseInt(req.params.id), parseFloat(rate)));
});

app.get('/api/employee-profiles', authMiddleware, adminOnly, (req, res) => {
    res.json(getAllEmployeeProfiles());
});

// ============ EMPLOYEE SELF PROFILE ============
app.get('/api/my-profile', authMiddleware, (req, res) => {
    const profile = getEmployeeProfile(req.user.display_name);
    if (!profile) return res.status(404).json({ success: false, message: 'Profile not found' });
    res.json({ success: true, profile });
});

app.get('/api/my-flagged', authMiddleware, (req, res) => {
    const flagged = getFlaggedByEmployee(req.user.display_name);
    res.json({ success: true, flagged, total: flagged.length });
});

// ============ XLSX DOWNLOAD ============
app.get('/api/download/xlsx', authMiddleware, adminOnly, (req, res) => {
    const accounts = getAllAccounts();
    const stats = getStats();
    stats.totalDuplicateAttempts = getTotalDuplicates();

    // Accounts sheet
    const wsData = accounts.map((a, i) => ({
        '#': i + 1,
        'Username': a.username,
        'Password': a.password,
        '2FA Hash': a.tfa_hash,
        'Employee': a.employee_name,
        'Submitted At': a.submitted_at
    }));

    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(wsData);
    ws['!cols'] = [{ wch: 5 }, { wch: 20 }, { wch: 16 }, { wch: 42 }, { wch: 18 }, { wch: 20 }];
    XLSX.utils.book_append_sheet(wb, ws, 'Accounts');

    // Summary sheet
    const summaryData = [
        { 'Metric': 'Total Accounts', 'Value': stats.totalAccounts },
        { 'Metric': 'Duplicate Attempts', 'Value': stats.totalDuplicateAttempts },
        { 'Metric': 'Total Employees', 'Value': stats.uniqueEmployees },
        { 'Metric': '', 'Value': '' },
        { 'Metric': '--- By Employee ---', 'Value': '' },
    ];
    stats.byEmployee.forEach(e => summaryData.push({ 'Metric': e.employee_name, 'Value': e.count }));
    const wsSummary = XLSX.utils.json_to_sheet(summaryData);
    wsSummary['!cols'] = [{ wch: 25 }, { wch: 12 }];
    XLSX.utils.book_append_sheet(wb, wsSummary, 'Summary');

    const buf = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });
    const dateStr = new Date().toISOString().slice(0, 10);
    const filename = `2FA_Accounts_${dateStr}.xlsx`;

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.send(buf);
});

// ============ PAGE ROUTES ============
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/submit', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'employee.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 404 handler
app.use((req, res) => {
    if (req.accepts('html')) {
        res.status(404).send(`<!DOCTYPE html><html><head><meta charset="UTF-8"><title>404</title><style>body{background:#0f0f1a;color:#e0e0e0;font-family:'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}.box{text-align:center}.box h1{font-size:4rem;color:#e94560;margin:0}.box p{color:#9e9e9e;margin:12px 0 20px}.box a{color:#448aff;text-decoration:none;padding:10px 24px;border:1px solid #448aff;border-radius:8px;transition:.2s}.box a:hover{background:#448aff;color:#fff}</style></head><body><div class="box"><h1>404</h1><p>Page not found</p><a href="/">Go to Login</a></div></body></html>`);
    } else {
        res.status(404).json({ error: 'Not found' });
    }
});

// ============ START (async init) ============
initDatabase().then(() => {
    app.listen(PORT, '0.0.0.0', () => {
        console.log('');
        console.log('==========================================================');
        console.log('          2FA ACCOUNT SUBMISSION SYSTEM');
        console.log('==========================================================');
        console.log(`  Server running on port ${PORT}`);
        console.log('');
        console.log(`  Login Page:       http://localhost:${PORT}`);
        console.log(`  Admin Dashboard:  http://localhost:${PORT}/admin`);
        console.log('');
        console.log('  Default Admin => username: admin / password: admin123');
        console.log('');
        console.log('  For remote access, use your IP:');
        console.log(`    http://<YOUR_IP>:${PORT}`);
        console.log('==========================================================');
        console.log('');
    });
}).catch(err => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
});

// Graceful shutdown — save DB before exit
process.on('SIGTERM', () => {
    console.log('\n[Server] SIGTERM received. Saving database and shutting down...');
    try { saveDB(); } catch(e) {}
    process.exit(0);
});
process.on('SIGINT', () => {
    console.log('\n[Server] SIGINT received. Saving database and shutting down...');
    try { saveDB(); } catch(e) {}
    process.exit(0);
});
