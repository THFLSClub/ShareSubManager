// app.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const YAML = require('yaml');
const app = express();
const port = process.env.PORT || 3000;

// 配置项（生产环境应使用环境变量）
const config = {
  admin: {
    username: process.env.ADMIN_USER || 'thfls_admin',
    passwordHash: process.env.ADMIN_PASS_HASH || 
      crypto.createHash('sha256').update('thfls@2024').digest('hex')
  },
  database: './subs.db',
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  secret: process.env.SECRET || uuidv4()
};

// 中间件
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: config.secret,
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.set('view engine', 'ejs');

// 数据库初始化
const db = new sqlite3.Database(config.database);
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    type TEXT CHECK(type IN ('vmess', 'vless', 'trojan', 'ss')),
    config TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    url TEXT UNIQUE,
    type TEXT CHECK(type IN ('v2ray', 'clash')),
    last_updated DATETIME
  )`);
});

// 工具函数
const parseNodeLink = (link) => {
  try {
    const [protocol, rest] = link.split('://');
    const configStr = Buffer.from(rest.split('#')[0], 'base64').toString();
    return { protocol, config: JSON.parse(configStr) };
  } catch (e) {
    return null;
  }
};

const generateClashConfig = async (nodes) => {
  const proxies = nodes.map(node => {
    const cfg = JSON.parse(node.config);
    return {
      name: cfg.ps,
      type: node.type,
      server: cfg.add,
      port: cfg.port,
      uuid: cfg.id,
      alterId: cfg.aid,
      cipher: cfg.scy || 'auto',
      tls: cfg.tls === 'tls',
      network: cfg.net,
      'ws-path': cfg.path,
      'ws-headers': { Host: cfg.host }
    };
  });
  
  return YAML.stringify({ proxies });
};

const generateV2rayConfig = (nodes) => 
  JSON.stringify({ outbounds: nodes.map(n => JSON.parse(n.config)) });

// 路由
app.get('/', (req, res) => res.render('index', { 
  clashUrl: `${config.baseUrl}/sub/clash`,
  v2rayUrl: `${config.baseUrl}/sub/v2ray`
}));

app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const passHash = crypto.createHash('sha256').update(password).digest('hex');
  console.log(passHash);
  if (username === config.admin.username && passHash === config.admin.passwordHash) {
    req.session.isAdmin = true;
    res.redirect('/admin');
  } else {
    res.send('Invalid credentials');
  }
});

app.get('/admin', async (req, res) => {
  if (!req.session.isAdmin) return res.redirect('/login');
  
  db.all('SELECT * FROM nodes', (err, nodes) => {
    res.render('admin', { nodes });
  });
});

app.post('/add', async (req, res) => {
  if (!req.session.isAdmin) return res.status(403).send('Forbidden');

  const { type, content } = req.body;
  
  try {
    if (type === 'node') {
      const node = parseNodeLink(content);
      if (!node) throw new Error('Invalid node format');
      
      db.run('INSERT INTO nodes (id, type, config) VALUES (?, ?, ?)', 
        [uuidv4(), node.protocol, JSON.stringify(node.config)]);
    } else if (type === 'subscription') {
      const response = await axios.get(content);
      const nodes = response.data.split('\n').map(link => parseNodeLink(link));
      
      nodes.forEach(node => {
        db.run('INSERT OR IGNORE INTO nodes (id, type, config) VALUES (?, ?, ?)', 
          [uuidv4(), node.protocol, JSON.stringify(node.config)]);
      });
    }
    res.redirect('/admin');
  } catch (e) {
    res.status(400).send(`Error: ${e.message}`);
  }
});

app.get('/sub/:type', (req, res) => {
  db.all('SELECT * FROM nodes', async (err, nodes) => {
    if (req.params.type === 'clash') {
      res.set('Content-Type', 'text/yaml');
      res.send(await generateClashConfig(nodes));
    } else if (req.params.type === 'v2ray') {
      res.set('Content-Type', 'application/json');
      res.send(generateV2rayConfig(nodes));
    } else {
      res.status(400).send('Invalid subscription type');
    }
  });
});

// 启动服务
app.listen(port, () => 
  console.log(`Server running at ${config.baseUrl}`));
