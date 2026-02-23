const initSqlJs = require('sql.js');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const DB_PATH = path.join(__dirname, 'accounts.db');

let db;

// Helper: save DB to disk
function saveDB() {
    const data = db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
}

// Auto-save every 5 seconds
let autoSaveTimer;

async function initDatabase() {
    const SQL = await initSqlJs();

    // Load existing DB or create new
    if (fs.existsSync(DB_PATH)) {
        const fileBuffer = fs.readFileSync(DB_PATH);
        db = new SQL.Database(fileBuffer);
    } else {
        db = new SQL.Database();
    }

    // Create tables
    db.run(`
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            tfa_hash TEXT NOT NULL,
            employee_name TEXT NOT NULL,
            submitted_at TEXT DEFAULT (datetime('now')),
            is_duplicate INTEGER DEFAULT 0
        )
    `);

    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_username ON accounts(username)`);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'employee',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            duplicate_count INTEGER DEFAULT 0
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS duplicate_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username_attempted TEXT NOT NULL,
            employee_name TEXT NOT NULL,
            attempted_at TEXT DEFAULT (datetime('now'))
        )
    `);

    // Create default admin if none exists
    const adminCheck = db.exec("SELECT id FROM users WHERE role = 'admin'");
    if (!adminCheck.length || !adminCheck[0].values.length) {
        const hashedPw = hashPassword('admin123');
        db.run("INSERT INTO users (username, password, display_name, role) VALUES (?, ?, ?, ?)",
            ['admin', hashedPw, 'Administrator', 'admin']);
        console.log('[DB] Default admin created => username: admin / password: admin123');
    }

    saveDB();
    autoSaveTimer = setInterval(() => { if (db) saveDB(); }, 5000);
    console.log('[DB] Database initialized at', DB_PATH);
    return db;
}

// ============ SQL.JS HELPERS ============
function getOne(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        stmt.free();
        const obj = {};
        cols.forEach((c, i) => obj[c] = vals[i]);
        return obj;
    }
    stmt.free();
    return null;
}

function getAll(sql, params = []) {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
        const cols = stmt.getColumnNames();
        const vals = stmt.get();
        const obj = {};
        cols.forEach((c, i) => obj[c] = vals[i]);
        results.push(obj);
    }
    stmt.free();
    return results;
}

function run(sql, params = []) {
    db.run(sql, params);
    saveDB();
}

// ============ PASSWORD & TOKEN ============
function hashPassword(pw) {
    return crypto.createHash('sha256').update(pw).digest('hex');
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

// ============ AUTH ============
function loginUser(username, password) {
    const user = getOne('SELECT * FROM users WHERE username = ? AND is_active = 1', [username]);
    if (!user) return { success: false, message: 'Invalid username or password' };
    if (user.password !== hashPassword(password)) return { success: false, message: 'Invalid username or password' };

    const token = generateToken();
    run('INSERT INTO sessions (token, user_id) VALUES (?, ?)', [token, user.id]);

    return {
        success: true,
        token,
        user: { id: user.id, username: user.username, display_name: user.display_name, role: user.role }
    };
}

function validateToken(token) {
    if (!token) return null;
    return getOne(`
        SELECT s.token, u.id, u.username, u.display_name, u.role
        FROM sessions s JOIN users u ON s.user_id = u.id
        WHERE s.token = ? AND u.is_active = 1
    `, [token]);
}

function logoutUser(token) {
    run('DELETE FROM sessions WHERE token = ?', [token]);
}

// ============ USER MANAGEMENT ============
function createUser(username, password, displayName, role = 'employee') {
    const existing = getOne('SELECT id FROM users WHERE username = ?', [username]);
    if (existing) return { success: false, message: `User "${username}" already exists` };
    try {
        run('INSERT INTO users (username, password, display_name, role) VALUES (?, ?, ?, ?)',
            [username, hashPassword(password), displayName, role]);
        const newUser = getOne('SELECT last_insert_rowid() as id');
        return { success: true, id: newUser.id, message: `User "${username}" created` };
    } catch (err) {
        return { success: false, message: err.message };
    }
}

function getAllUsers() {
    return getAll("SELECT id, username, display_name, role, is_active, created_at FROM users ORDER BY created_at DESC");
}

function deleteUser(userId) {
    const user = getOne('SELECT role FROM users WHERE id = ?', [userId]);
    if (!user) return { success: false, message: 'User not found' };
    if (user.role === 'admin') {
        const cnt = getOne("SELECT COUNT(*) as c FROM users WHERE role = 'admin'");
        if (cnt.c <= 1) return { success: false, message: 'Cannot delete the last admin' };
    }
    run('DELETE FROM sessions WHERE user_id = ?', [userId]);
    run('DELETE FROM users WHERE id = ?', [userId]);
    return { success: true, message: 'User deleted' };
}

function toggleUserActive(userId) {
    const user = getOne('SELECT is_active, role FROM users WHERE id = ?', [userId]);
    if (!user) return { success: false, message: 'User not found' };
    if (user.role === 'admin') {
        const cnt = getOne("SELECT COUNT(*) as c FROM users WHERE role = 'admin' AND is_active = 1");
        if (cnt.c <= 1 && user.is_active === 1) return { success: false, message: 'Cannot deactivate the last active admin' };
    }
    const newState = user.is_active ? 0 : 1;
    run('UPDATE users SET is_active = ? WHERE id = ?', [newState, userId]);
    if (newState === 0) run('DELETE FROM sessions WHERE user_id = ?', [userId]);
    return { success: true, is_active: newState };
}

function changeUserPassword(userId, newPassword) {
    run('UPDATE users SET password = ? WHERE id = ?', [hashPassword(newPassword), userId]);
    run('DELETE FROM sessions WHERE user_id = ?', [userId]);
    return { success: true, message: 'Password changed' };
}

// ============ ACCOUNTS ============
function addAccount(username, password, tfaHash, employeeName) {
    const existing = getOne('SELECT id FROM accounts WHERE username = ?', [username]);
    if (existing) {
        // Log the duplicate attempt with employee name
        run('INSERT INTO duplicate_attempts (username_attempted, employee_name) VALUES (?, ?)', [username, employeeName]);
        return { success: false, duplicate: true, message: `Duplicate: "${username}" already exists` };
    }
    try {
        run('INSERT INTO accounts (username, password, tfa_hash, employee_name) VALUES (?, ?, ?, ?)',
            [username, password, tfaHash, employeeName]);
        return { success: true, message: 'Account added successfully' };
    } catch (err) {
        if (err.message.includes('UNIQUE constraint')) {
            run('INSERT INTO duplicate_attempts (username_attempted, employee_name) VALUES (?, ?)', [username, employeeName]);
            return { success: false, duplicate: true, message: `Duplicate: "${username}" already exists` };
        }
        return { success: false, duplicate: false, message: err.message };
    }
}

function bulkAddAccounts(accounts) {
    const results = { added: 0, duplicates: 0, errors: 0 };
    for (const acc of accounts) {
        const res = addAccount(acc.username, acc.password, acc.tfa_hash, acc.employee_name);
        if (res.success) results.added++;
        else if (res.duplicate) results.duplicates++;
        else results.errors++;
    }
    return results;
}

function getAllAccounts() {
    return getAll('SELECT * FROM accounts ORDER BY submitted_at DESC');
}

function getStats() {
    const total = getOne('SELECT COUNT(*) as count FROM accounts');
    const byEmployee = getAll(`
        SELECT employee_name, COUNT(*) as count
        FROM accounts GROUP BY employee_name ORDER BY count DESC
    `);
    return {
        totalAccounts: total.count,
        uniqueEmployees: byEmployee.length,
        byEmployee
    };
}

function getAccountsByEmployee(employeeName) {
    return getAll('SELECT * FROM accounts WHERE employee_name = ? ORDER BY submitted_at DESC', [employeeName]);
}

function incrementDuplicateCount() {
    run(`INSERT INTO meta (key, duplicate_count) VALUES ('duplicates', 1)
         ON CONFLICT(key) DO UPDATE SET duplicate_count = duplicate_count + 1`);
}

function getTotalDuplicates() {
    const row = getOne("SELECT duplicate_count FROM meta WHERE key = 'duplicates'");
    return row ? row.duplicate_count : 0;
}

function deleteAllAccounts() {
    run('DELETE FROM accounts');
    run('DELETE FROM duplicate_attempts');
    run("UPDATE meta SET duplicate_count = 0 WHERE key = 'duplicates'");
    return { success: true, message: 'All accounts and duplicate logs deleted' };
}

function getDuplicatesByEmployee() {
    const total = getOne('SELECT COUNT(*) as count FROM duplicate_attempts');
    const byEmployee = getAll(`
        SELECT employee_name, COUNT(*) as count
        FROM duplicate_attempts
        GROUP BY employee_name ORDER BY count DESC
    `);
    const details = getAll(`
        SELECT employee_name, username_attempted, attempted_at
        FROM duplicate_attempts ORDER BY attempted_at DESC LIMIT 200
    `);
    return {
        totalDuplicates: total.count,
        byEmployee,
        recentAttempts: details
    };
}

function exportAllAccounts() {
    const accounts = getAll('SELECT username, password, tfa_hash FROM accounts ORDER BY id ASC');
    return accounts.map(a => `${a.username}\t${a.password}\t${a.tfa_hash}`).join('\n');
}

function deleteAccountsByEmployee(employeeName) {
    run('DELETE FROM accounts WHERE employee_name = ?', [employeeName]);
    run('DELETE FROM duplicate_attempts WHERE employee_name = ?', [employeeName]);
    return { success: true, message: `All accounts and duplicate logs for ${employeeName} deleted` };
}

module.exports = {
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
};
