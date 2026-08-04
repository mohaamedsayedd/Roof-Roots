const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'roof_roots_secret_key_2026';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(__dirname));

app.get('/', (req, res) => {
     res.sendFile(path.join(__dirname, 'index.html'));
   });

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

let db;
(async () => {
  db = await open({
    filename: './database.sqlite',
    driver: sqlite3.Database
  });

  // 1. Properties Table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS properties (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      price TEXT NOT NULL,
      location TEXT NOT NULL,
      status TEXT DEFAULT 'Available',
      image TEXT,
      description TEXT
    )
  `);

  // 2. Users Table (Admin & Sales Team)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'sales' -- 'admin' or 'sales'
    )
  `);

  // 3. Leads Table (CRM Data)
  await db.exec(`
    CREATE TABLE IF NOT EXISTS leads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      email TEXT,
      budget TEXT,
      status TEXT DEFAULT 'New', -- New, Contacted, Viewing, Negotiation, Won, Lost
      assigned_to INTEGER, -- User ID of Salesperson
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (assigned_to) REFERENCES users(id)
    )
  `);

  // Create Default Admin User if not exists (Email: admin@roof.com / Pass: admin123)
  const adminExists = await db.get('SELECT * FROM users WHERE role = "admin"');
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await db.run(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      ['مدير النظام (Admin)', 'admin@roof.com', hashedPassword, 'admin']
    );
    console.log('👑 Default Admin Account Created: admin@roof.com / admin123');
  }

  console.log('📦 Database & CRM Tables Ready!');
})();

// Middleware Authentication & Check Roles
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'غير مسموح، يرجي تسجيل الدخول' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'جلسة انتهت، اعد الدخول' });
    req.user = user;
    next();
  });
};

// ==================== AUTH APIs ====================

// Login API
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ success: false, message: 'بيانات الدخول غير صحيحة' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ success: false, message: 'بيانات الدخول غير صحيحة' });

    const token = jwt.sign({ id: user.id, name: user.name, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ success: true, token, user: { id: user.id, name: user.name, role: user.role } });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Admin Only: Add Sales Team Member
app.post('/api/users/add', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'صلاحية أدمن فقط' });

  const { name, email, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.run(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, email, hashedPassword, role || 'sales']
    );
    res.json({ success: true, message: 'تم إضافة موظف جديد بنجاح' });
  } catch (error) {
    res.status(400).json({ success: false, message: 'الإيميل مستخدم بالفعل' });
  }
});

// Get List of Team Members (for dropdowns)
app.get('/api/users/team', authenticateToken, async (req, res) => {
  const users = await db.all('SELECT id, name, role FROM users');
  res.json({ success: true, data: users });
});

// ==================== CRM LEADS APIs ====================

// Get Leads (Admin sees ALL, Sales sees ONLY THEIR OWN)
app.get('/api/crm/leads', authenticateToken, async (req, res) => {
  try {
    let leads;
    if (req.user.role === 'admin') {
      leads = await db.all(`
        SELECT leads.*, users.name as assigned_name 
        FROM leads 
        LEFT JOIN users ON leads.assigned_to = users.id 
        ORDER BY leads.id DESC
      `);
    } else {
      leads = await db.all(`
        SELECT leads.*, users.name as assigned_name 
        FROM leads 
        LEFT JOIN users ON leads.assigned_to = users.id 
        WHERE leads.assigned_to = ? 
        ORDER BY leads.id DESC
      `, [req.user.id]);
    }
    res.json({ success: true, data: leads });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Add New Lead
app.post('/api/crm/leads', authenticateToken, async (req, res) => {
  const { name, phone, email, budget, status, assigned_to, notes } = req.body;
  const assigned = req.user.role === 'admin' ? assigned_to : req.user.id;
  try {
    await db.run(
      `INSERT INTO leads (name, phone, email, budget, status, assigned_to, notes) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name, phone, email, budget, status || 'New', assigned, notes]
    );
    res.json({ success: true, message: 'تم إضافة العميل بنجاح' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Update Lead Status & Notes
app.put('/api/crm/leads/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, notes, assigned_to } = req.body;

  try {
    if (req.user.role === 'admin' && assigned_to) {
      await db.run('UPDATE leads SET status = ?, notes = ?, assigned_to = ? WHERE id = ?', [status, notes, assigned_to, id]);
    } else {
      await db.run('UPDATE leads SET status = ?, notes = ? WHERE id = ? AND (assigned_to = ? OR ? = "admin")', [status, notes, id, req.user.id, req.user.role]);
    }
    res.json({ success: true, message: 'تم تحديث بيانات العميل' });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Website Contact Form Integration (Creates Lead automatically)
app.post('/api/contact', async (req, res) => {
  const { contactName, contactEmail, contactPhone, contactSubject, contactMessage } = req.body;
  
  // Auto-save lead in CRM
  try {
    await db.run(
      `INSERT INTO leads (name, phone, email, notes, status) VALUES (?, ?, ?, ?, 'New')`,
      [contactName, contactPhone, contactEmail, `${contactSubject}: ${contactMessage}`]
    );
  } catch (e) { console.error('Auto CRM insert error:', e); }

  // Send Email Notification
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER,
    subject: `Lead جديد من الموقع: ${contactSubject}`,
    html: `<h3>عميل جديد سجل في الموقع!</h3><p><strong>الاسم:</strong> ${contactName}</p><p><strong>الهاتف:</strong> ${contactPhone}</p><p><strong>الرسالة:</strong> ${contactMessage}</p>`
  };
  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ success: true, message: 'Message sent successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Failed to send message.' });
  }
});

// Public Property APIs
app.get('/api/properties', async (req, res) => {
  const properties = await db.all('SELECT * FROM properties');
  res.json({ success: true, data: properties });
});
app.post('/api/properties', async (req, res) => {
  const { title, price, location, image, description } = req.body;
  const result = await db.run(`INSERT INTO properties (title, price, location, image, description) VALUES (?, ?, ?, ?, ?)`, [title, price, location, image, description]);
  res.json({ success: true, id: result.lastID });
});
app.put('/api/properties/:id/status', async (req, res) => {
  await db.run('UPDATE properties SET status = ? WHERE id = ?', [req.body.status, req.params.id]);
  res.json({ success: true });
});
app.delete('/api/properties/:id', async (req, res) => {
  await db.run('DELETE FROM properties WHERE id = ?', [req.params.id]);
  res.json({ success: true });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));