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
    deleteAccountsByEmployee
} = require('./database');


const app = express();
const PORT = process.env.PORT || 3000;

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
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password required' });
    }
    const result = loginUser(username.trim(), password);
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
