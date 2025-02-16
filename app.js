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
const path = require('path');
const fs = require('fs');
const app = express();
const port = process.env.PORT || 3000;

// 增强配置项
const config = {
  admin: {
    username: process.env.ADMIN_USER || 'thfls_admin',
    passwordHash: process.env.ADMIN_PASS_HASH || 
      crypto.createHash('sha256').update('thfls@2024').digest('hex')
  },
  database: './subs.db',
  baseUrl: process.env.BASE_URL || 'http://localhost:3000',
  secret: process.env.SECRET || uuidv4(),
  nodeTypes: ['vmess', 'vless', 'trojan', 'ss'],
  maxNodes: 500
};

// 中间件配置
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(session({
  store: new SQLiteStore({ 
    db: 'sessions.db',
    dir: __dirname 
  }),
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
app.set('views', path.join(__dirname, 'views'));

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

// 增强协议解析器
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
          password: password
        }
      };
    } catch (e) {
      return null;
    }
  },

  vless: (url) => {
    try {
      const parsed = new URL.URL(`vless://${url}`);
      const query = Object.fromEntries(parsed.searchParams);
      
      return {
        protocol: 'vless',
        config: {
          ps: parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : 'VLESS Node',
          add: parsed.hostname,
          port: parseInt(parsed.port),
          id: parsed.username,
          net: query.type || 'tcp',
          path: query.path ? decodeURIComponent(query.path) : '',
          host: query.host || parsed.hostname,
          tls: query.security || 'none',
          sni: query.sni || '',
          flow: query.flow || '',
          alpn: query.alpn ? decodeURIComponent(query.alpn) : ''
        }
      };
    } catch (e) {
      return null;
    }
  },

  trojan: (url) => {
    try {
      const parsed = new URL.URL(`trojan://${url}`);
      const query = Object.fromEntries(parsed.searchParams);

      return {
        protocol: 'trojan',
        config: {
          ps: parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : 'Trojan Node',
          add: parsed.hostname,
          port: parseInt(parsed.port),
          password: parsed.username,
          net: query.type || 'tcp',
          path: query.path ? decodeURIComponent(query.path) : '',
          host: query.host || parsed.hostname,
          sni: query.sni || parsed.hostname,
          security: query.security || 'tls'
        }
      };
    } catch (e) {
      return null;
    }
  },

  vmess: (url) => {
    try {
      const [base64, fragment] = url.split('#');
      const configStr = Buffer.from(base64, 'base64').toString();
      return {
        protocol: 'vmess',
        config: {
          ...JSON.parse(configStr),
          ps: fragment ? decodeURIComponent(fragment) : 'VMess Node'
        }
      };
    } catch (e) {
      return null;
    }
  }
};

// 统一解析入口
const parseNodeLink = (link) => {
  try {
    const [protocol, url] = link.split('://');
    const lowerProto = protocol.toLowerCase();
    
    switch(lowerProto) {
      case 'ss': return nodeParsers.ss(url);
      case 'vless': return nodeParsers.vless(url);
      case 'trojan': return nodeParsers.trojan(url);
      case 'vmess': return nodeParsers.vmess(url);
      default: return null;
    }
  } catch (e) {
    console.error('解析错误:', e.message);
    return null;
  }
};

// Clash配置生成器
const generateClashConfig = (nodes) => {
  const proxies = nodes.slice(0, config.maxNodes).map(node => {
    const cfg = JSON.parse(node.config);
    
    const base = {
      name: cfg.ps.replace(/[^\x00-\x7F]/g, '').substring(0, 50), // 过滤非ASCII字符
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
          sni: cfg.sni,
          network: cfg.net,
          'ws-path': cfg.path,
          'ws-headers': { Host: cfg.host }
        };

      case 'vless':
        return {
          ...base,
          type: 'vless',
          uuid: cfg.id,
          flow: cfg.flow,
          tls: cfg.tls !== 'none',
          network: cfg.net,
          servername: cfg.sni || cfg.host,
          'ws-path': cfg.path,
          'ws-headers': { Host: cfg.host }
        };
    }
  }).filter(Boolean);

  return YAML.stringify({ proxies });
};

// V2Ray配置生成器
const generateV2rayConfig = (nodes) => {
  const outbounds = nodes.slice(0, config.maxNodes).map(node => {
    const cfg = JSON.parse(node.config);
    
    const outbound = {
      protocol: node.type,
      settings: {},
      streamSettings: {},
      tag: cfg.ps
    };

    switch(node.type) {
      case 'vmess':
        outbound.settings.vnext = [{
          address: cfg.add,
          port: cfg.port,
          users: [{ 
            id: cfg.id,
            alterId: cfg.aid || 0,
            security: cfg.scy || 'auto'
          }]
        }];
        break;

      case 'vless':
        outbound.settings.vnext = [{
          address: cfg.add,
          port: cfg.port,
          users: [{ 
            id: cfg.id,
            flow: cfg.flow,
            encryption: 'none'
          }]
        }];
        break;

      case 'trojan':
        outbound.settings.servers = [{
          address: cfg.add,
          port: cfg.port,
          password: cfg.password
        }];
        break;

      case 'ss':
        outbound.settings.servers = [{
          address: cfg.add,
          port: cfg.port,
          method: cfg.method,
          password: cfg.password
        }];
        break;
    }

    // 通用流设置
    if (['ws', 'grpc'].includes(cfg.net)) {
      outbound.streamSettings = {
        network: cfg.net,
        security: cfg.tls,
        wsSettings: {
          path: cfg.path,
          headers: { Host: cfg.host }
        }
      };

      if (cfg.tls === 'tls') {
        outbound.streamSettings.tlsSettings = {
          serverName: cfg.sni,
          alpn: cfg.alpn ? cfg.alpn.split(',') : ['h2', 'http/1.1']
        };
      }
    }

    return outbound;
  });

  return JSON.stringify({ outbounds }, null, 2);
};

// 路由控制器
const adminAuth = (req, res, next) => {
  if (!req.session.isAdmin) return res.redirect('/login?error=unauthorized');
  next();
};

// 前端路由
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
  
  if (username === config.admin.username && passHash === config.admin.passwordHash) {
    req.session.regenerate(err => {
      req.session.isAdmin = true;
      req.session.save(() => res.redirect('/admin'));
    });
  } else {
    res.redirect('/login?error=credentials');
  }
});

app.get('/admin', adminAuth, (req, res) => {
  db.all('SELECT * FROM nodes ORDER BY created_at DESC LIMIT ?', [config.maxNodes], 
    (err, nodes) => {
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
        `INSERT OR IGNORE INTO nodes (id, type, config) 
         VALUES (?, ?, ?)`,
        [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)]
      );
    } else if (type === 'subscription') {
      const { data } = await axios.get(content, { timeout: 5000 });
      const links = data.split('\n').filter(l => l.startsWith('ss://') || 
        l.startsWith('vmess://') || 
        l.startsWith('vless://') || 
        l.startsWith('trojan://'));
      
      links.forEach(link => {
        const parsed = parseNodeLink(link);
        if (parsed) {
          db.run(
            `INSERT OR IGNORE INTO nodes (id, type, config) 
             VALUES (?, ?, ?)`,
            [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)]
          );
        }
      });
    }
    
    res.redirect('/admin');
  } catch (e) {
    res.status(400).render('error', { 
      message: `添加失败: ${e.message}` 
    });
  }
});

app.get('/sub/:type(clash|v2ray)', (req, res) => {
  db.all('SELECT * FROM nodes ORDER BY created_at DESC LIMIT ?', 
    [config.maxNodes], (err, nodes) => {
      if (req.params.type === 'clash') {
        res.set('Content-Type', 'text/yaml')
           .send(generateClashConfig(nodes));
      } else {
        res.set('Content-Type', 'application/json')
           .send(generateV2rayConfig(nodes));
      }
  });
});

// 系统维护
setInterval(() => {
  db.run(`DELETE FROM nodes WHERE rowid NOT IN 
    (SELECT rowid FROM nodes ORDER BY created_at DESC LIMIT ?)`, 
    [config.maxNodes]);
}, 3600000);

app.listen(port, () => {
  console.log(`服务已启动: ${config.baseUrl}`);
});
