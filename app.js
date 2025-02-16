// app.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const axios = require('axios');
const sqlite3 = require('sqlite3').verbose();
const YAML = require('yaml');
const URL = require('url');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

// 配置项
const config = {
  admin: {
    username: process.env.ADMIN_USER || 'thfls_admin',
    passwordHash: process.env.ADMIN_PASS_HASH || 
      crypto.createHash('sha256').update('thfls@2024').digest('hex')
  },
  database: './subs.db',
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  secret: process.env.SECRET || uuidv4(),
  nodeTypes: ['vmess', 'vless', 'trojan', 'ss']
};

// 中间件
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db' }),
  secret: config.secret,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 3600000
  }
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

// 协议解析器
const nodeParsers = {
  ss: (url) => {
    try {
      const [hashPart, serverPart] = url.split('@');
      const decoded = Buffer.from(hashPart, 'base64').toString();
      const [method, password] = decoded.split(':');
      
      const [hostPort, fragment] = serverPart.split('#');
      const [host, port] = hostPort.includes(':') ? 
        hostPort.split(':') : [hostPort, '8388'];
      
      return {
        protocol: 'ss',
        config: {
          ps: fragment ? decodeURIComponent(fragment) : 'SS Node',
          add: host,
          port: parseInt(port),
          method: method,
          password: password,
          tls: '',
          net: 'tcp'
        }
      };
    } catch (e) {
      return null;
    }
  },

  general: (url, protocol) => {
    try {
      const [base64, fragment] = url.split('#');
      const configStr = Buffer.from(base64, 'base64').toString();
      return {
        protocol,
        config: {
          ...JSON.parse(configStr),
          ps: fragment ? decodeURIComponent(fragment) : `${protocol.toUpperCase()} Node`
        }
      };
    } catch (e) {
      return null;
    }
  }
};

const parseNodeLink = (link) => {
  try {
    const [protocol, url] = link.split('://');
    const lowerProto = protocol.toLowerCase();
    
    if (!config.nodeTypes.includes(lowerProto)) return null;
    if (lowerProto === 'ss') return nodeParsers.ss(url);
    
    return nodeParsers.general(url, lowerProto);
  } catch (e) {
    console.error('Parse error:', e.message);
    return null;
  }
};

// 配置生成器
const generateClashConfig = (nodes) => {
  const proxies = nodes.map(node => {
    const cfg = JSON.parse(node.config);
    
    const base = {
      name: cfg.ps,
      server: cfg.add,
      port: cfg.port,
      udp: true
    };

    switch(node.type) {
      case 'ss':
        return {
          ...base,
          type: 'ss',
          cipher: cfg.method,
          password: cfg.password
        };
      
      case 'vmess':
        return {
          ...base,
          type: 'vmess',
          uuid: cfg.id,
          alterId: cfg.aid || 0,
          cipher: cfg.scy || 'auto',
          tls: cfg.tls === 'tls',
          network: cfg.net,
          'ws-path': cfg.path || '/',
          'ws-headers': { Host: cfg.host || cfg.add }
        };

      case 'trojan':
        return {
          ...base,
          type: 'trojan',
          password: cfg.password,
          sni: cfg.sni || cfg.add
        };

      case 'vless':
        return {
          ...base,
          type: 'vless',
          uuid: cfg.id,
          flow: cfg.flow || '',
          tls: cfg.tls === 'tls'
        };
    }
  }).filter(Boolean);

  return YAML.stringify({ proxies });
};

const generateV2rayConfig = (nodes) => {
  const outbounds = nodes.map(node => {
    const cfg = JSON.parse(node.config);
    return {
      protocol: node.type,
      settings: {
        vnext: [{
          address: cfg.add,
          port: cfg.port,
          users: [{ 
            id: cfg.id || '',
            security: cfg.scy || 'auto',
            alterId: cfg.aid || 0
          }]
        }]
      },
      streamSettings: {
        network: cfg.net,
        security: cfg.tls,
        wsSettings: {
          path: cfg.path,
          headers: { Host: cfg.host }
        }
      },
      tag: cfg.ps
    };
  });

  return JSON.stringify({ outbounds }, null, 2);
};

// 路由
const adminAuth = (req, res, next) => {
  if (!req.session.isAdmin) return res.redirect('/login?error=unauthorized');
  next();
};

app.get('/', (req, res) => res.render('index', {
  clashUrl: `${config.baseUrl}/sub/clash`,
  v2rayUrl: `${config.baseUrl}/sub/v2ray`
}));

app.get('/login', (req, res) => res.render('login', { error: req.query.error }));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.redirect('/login?error=empty');
  }

  const passHash = crypto.createHash('sha256').update(password).digest('hex');
  
  if (username === config.admin.username && passHash.toLowerCase() === config.admin.passwordHash.toLowerCase()) {
    req.session.regenerate(err => {
      req.session.isAdmin = true;
      req.session.save(() => res.redirect('/admin'));
    });
  } else {
    res.redirect('/login?error=credentials');
  }
});

app.get('/admin', adminAuth, (req, res) => {
  db.all('SELECT * FROM nodes ORDER BY created_at DESC', (err, nodes) => {
    res.render('admin', { nodes });
  });
});

app.post('/add', adminAuth, async (req, res) => {
  const { type, content } = req.body;

  try {
    if (type === 'node') {
      const parsed = parseNodeLink(content);
      if (!parsed) throw new Error('不支持的节点格式');

      db.run(
        'INSERT OR IGNORE INTO nodes (id, type, config) VALUES (?, ?, ?)',
        [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)]
      );
    } else if (type === 'subscription') {
      const { data } = await axios.get(content);
      const links = data.split('\n').filter(l => l.startsWith('ss://') || l.startsWith('vmess://'));
      
      links.forEach(link => {
        const parsed = parseNodeLink(link);
        if (parsed) {
          db.run(
            'INSERT OR IGNORE INTO nodes (id, type, config) VALUES (?, ?, ?)',
            [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)]
          );
        }
      });
    }
    
    res.redirect('/admin');
  } catch (e) {
    res.status(400).render('error', { message: e.message });
  }
});

app.get('/sub/:type(clash|v2ray)', (req, res) => {
  db.all('SELECT * FROM nodes', (err, nodes) => {
    if (req.params.type === 'clash') {
      res.set('Content-Type', 'text/yaml').send(generateClashConfig(nodes));
    } else {
      res.set('Content-Type', 'application/json').send(generateV2rayConfig(nodes));
    }
  });
});

// 会话清理
setInterval(() => {
  db.run("DELETE FROM sessions WHERE expires <= datetime('now')");
}, 3600000);

app.listen(port, () => {
  console.log(`Server running at ${config.baseUrl}`);
});
