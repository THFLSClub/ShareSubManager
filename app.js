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
const net = require('net');
import pLimit from 'p-limit';
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
  maxNodes: 500,
  healthCheck: {
    interval: 6 * 60 * 60 * 1000,    // 6小时
    timeout: 5000,                   // 5秒超时
    maxFails: 3,                     // 最大失败次数
    concurrency: 20                  // 并发检测数
  }
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
  // 创建节点表（包含健康监测字段）
  db.run(`CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    type TEXT CHECK(type IN ('vmess', 'vless', 'trojan', 'ss')),
    config TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_check DATETIME,
    latency INTEGER,
    fail_count INTEGER DEFAULT 0
  )`);

  // 创建订阅表
  db.run(`CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    url TEXT UNIQUE,
    type TEXT CHECK(type IN ('v2ray', 'clash')),
    last_updated DATETIME
  )`);

  // 兼容旧表结构
  ['last_check', 'latency', 'fail_count'].forEach(col => {
    db.run(`ALTER TABLE nodes ADD COLUMN ${col}`, () => {}); // 忽略错误
  });
});

// 增强协议解析器
const nodeParsers = {
  ss: (url) => {
    try {
      const [hashPart, serverPart] = url.split('@');
      const decodedHash = decodeBase64Recursively(hashPart);
      const [method, password] = decodedHash.split(':');
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
      const id = decodeBase64Recursively(parsed.username);
      
      return {
        protocol: 'vless',
        config: {
          ps: parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : 'VLESS Node',
          add: parsed.hostname,
          port: parseInt(parsed.port),
          id: id,
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
      const password = decodeBase64Recursively(parsed.username);

      return {
        protocol: 'trojan',
        config: {
          ps: parsed.hash ? decodeURIComponent(parsed.hash.slice(1)) : 'Trojan Node',
          add: parsed.hostname,
          port: parseInt(parsed.port),
          password: password,
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
      const configStr = decodeBase64Recursively(base64);
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

// 添加递归解码函数
function decodeBase64Recursively(str) {
  let decoded = str;
  let prev;
  do {
    prev = decoded;
    try {
      decoded = Buffer.from(decoded, 'base64').toString('utf-8');
    } catch (e) {
      break;
    }
  } while (decoded !== prev);
  return decoded;
}

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
  const clashConfig = {
    'mixed-port': 7890,
    'allow-lan': false,
    mode: 'rule',
    'log-level': 'info',
    ipv6: false,
    'external-controller': '0.0.0.0:9090',
    dns: {
      enable: true,
      listen: '0.0.0.0:53',
      ipv6: false,
      'default-nameserver': [
        '223.5.5.5',
        '114.114.114.114'
      ],
      nameserver: [
        '223.5.5.5',
        '114.114.114.114',
        '119.29.29.29',
        '180.76.76.76'
      ],
      'enhanced-mode': 'fake-ip',
      'fake-ip-range': '198.18.0.1/16',
      'fake-ip-filter': [
        '*.lan',
        '*.localdomain',
        '*.example',
        '*.invalid',
        '*.localhost',
        '*.test',
        '*.local',
        '*.home.arpa',
        'router.asus.com',
        'localhost.sec.qq.com',
        'localhost.ptlogin2.qq.com',
        '+.msftconnecttest.com'
      ]
    },
    tun: {
      enable: true,
      stack: 'system',
      'auto-route': true,
      'auto-detect-interface': true,
      'dns-hijack': [
        '114.114.114.114',
        '180.76.76.76',
        '119.29.29.29',
        '223.5.5.5',
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '1.0.0.1'
      ]
    },
    proxies: []
  };

  // 处理节点名称重复问题
  const nameCounts = {};

  clashConfig.proxies = nodes.slice(0, config.maxNodes).map(node => {
    const cfg = JSON.parse(node.config);
    
    // 生成基础名称并处理特殊字符
    const baseName = cfg.ps.replace(/[^\x00-\x7F]/g, '').substring(0, 50);
    
    // 生成唯一名称
    let count = nameCounts[baseName] || 0;
    nameCounts[baseName] = count + 1;
    const uniqueName = count === 0 ? baseName : `${baseName} ${count}`;

    const base = {
      name: uniqueName,
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
          'ws-headers': { Host: cfg.host || cfg.add },
          sni: cfg.sni || cfg.host
        };

      case 'trojan':
        return {
          ...base,
          type: 'trojan',
          password: cfg.password,
          sni: cfg.sni || cfg.host,
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

  // 添加规则组
  clashConfig['proxy-groups'] = [{
    name: 'PROXY',
    type: 'select',
    proxies: clashConfig.proxies.map(p => p.name)
  }];

  clashConfig.rules = [
    'GEOIP,CN,DIRECT',
    'MATCH,PROXY'
  ];

  return YAML.stringify(clashConfig);
};

// V2Ray配置生成器
const generateV2rayConfig = (nodes) => {
  const links = nodes.slice(0, config.maxNodes).map(node => {
    const cfg = JSON.parse(node.config);
    
    switch(node.type) {
      case 'vmess':
        const vmessObject = {
          v: "2",
          ps: cfg.ps,
          add: cfg.add,
          port: cfg.port,
          id: cfg.id,
          aid: cfg.aid || 0,
          scy: cfg.scy || "auto",
          net: cfg.net,
          type: cfg.type || "none",
          host: cfg.host || cfg.add,
          path: cfg.path || "",
          tls: cfg.tls || "none",
          sni: cfg.sni || ""
        };
        const vmessBase64 = Buffer.from(JSON.stringify(vmessObject)).toString('base64');
        return `vmess://${vmessBase64}#${encodeURIComponent(cfg.ps)}`;

      case 'vless':
        const vlessParams = new URLSearchParams({
          type: cfg.net,
          security: cfg.tls,
          path: cfg.path,
          host: cfg.host,
          sni: cfg.sni,
          flow: cfg.flow
        }).toString();
        return `vless://${cfg.id}@${cfg.add}:${cfg.port}?${vlessParams}#${encodeURIComponent(cfg.ps)}`;

      case 'trojan':
        const trojanParams = new URLSearchParams({
          type: cfg.net,
          path: cfg.path,
          host: cfg.host,
          sni: cfg.sni
        }).toString();
        return `trojan://${cfg.password}@${cfg.add}:${cfg.port}?${trojanParams}#${encodeURIComponent(cfg.ps)}`;

      case 'ss':
        const ssAuth = `${cfg.method}:${cfg.password}`;
        return `ss://${Buffer.from(ssAuth).toString('base64')}@${cfg.add}:${cfg.port}#${encodeURIComponent(cfg.ps)}`;
    }
  }).filter(Boolean);

  return links.join('\n');
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
  db.all('SELECT * FROM nodes ORDER BY created_at DESC LIMIT ?', [config.maxNodes], 
    (err, nodes) => {
      res.render('admin', { nodes });
  });
});

app.post('/add', adminAuth, async (req, res) => {
  const { type, content } = req.body;
  try {
    if (type === 'node') {
      const lines = content.split('\n');
      let hasValid = false;
      lines.forEach(line => {
        const trimmedLine = line.trim();
        if (!trimmedLine) return;
        const parsed = parseNodeLink(trimmedLine);
        if (!parsed) {
          console.error('无法解析链接:', trimmedLine);
          return;
        }
        hasValid = true;
        db.run(
          `INSERT OR IGNORE INTO nodes (id, type, config) 
           VALUES (?, ?, ?)`,
          [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)],
          (err) => { if (err) console.error('插入失败:', err) }
        );
      });
      if (!hasValid) throw new Error('未找到有效节点');
    } else if (type === 'subscription') {
      const response = await axios.get(content, { timeout: 5000 });
      let data = response.data;
      data = decodeBase64Recursively(data);
      const links = data.split('\n').filter(l => 
        l.startsWith('ss://') || 
        l.startsWith('vmess://') || 
        l.startsWith('vless://') || 
        l.startsWith('trojan://')
      );
      
      links.forEach(link => {
        const parsed = parseNodeLink(link.trim());
        if (parsed) {
          db.run(
            `INSERT OR IGNORE INTO nodes (id, type, config) 
             VALUES (?, ?, ?)`,
            [uuidv4(), parsed.protocol, JSON.stringify(parsed.config)],
            (err) => { if (err) console.error('插入失败:', err) }
          );
        }
      });
    }
    res.redirect('/admin');
  } catch (e) {
    res.status(400).render('error', { message: `操作失败: ${e.message}` });
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

app.use('/statics',express.static('public'));

async function testNodeConnectivity(node) {
  return new Promise((resolve) => {
    const cfg = JSON.parse(node.config);
    const socket = net.createConnection({
      host: cfg.add,
      port: cfg.port,
      timeout: config.healthCheck.timeout
    });

    const startTime = Date.now();
    
    socket.on('connect', () => {
      socket.destroy();
      resolve({
        success: true,
        latency: Date.now() - startTime
      });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ success: false, error: 'Connection timeout' });
    });

    socket.on('error', (err) => {
      resolve({ success: false, error: err.message });
    });
  });
}

async function performHealthCheck() {
  const nodes = await new Promise((resolve) => {
    db.all('SELECT * FROM nodes', [], (err, rows) => resolve(rows));
  });

  const limit = pLimit(config.healthCheck.concurrency);
  const checks = nodes.map(node => limit(async () => {
    const result = await testNodeConnectivity(node);
    
    if (result.success) {
      db.run('UPDATE nodes SET last_check = ?, latency = ?, fail_count = 0 WHERE id = ?',
        [new Date().toISOString(), result.latency, node.id]);
    } else {
      db.run('UPDATE nodes SET last_check = ?, fail_count = fail_count + 1 WHERE id = ?',
        [new Date().toISOString(), node.id]);
    }
  }));

  await Promise.all(checks);
}

// 系统维护
setInterval(async () => {
  console.log('正在执行节点健康检查...');
  try {
    await performHealthCheck();
    db.run(`DELETE FROM nodes WHERE fail_count > ?`, 
      [config.healthCheck.maxFails], 
      (err) => {
        if (err) console.error('节点清理失败:', err);
        else console.log(`已清理连续${config.healthCheck.maxFails}次检测失败的节点`);
      }
    );
  } catch (e) {
    console.error('健康检查出错:', e);
  }
}, config.healthCheck.interval);

app.listen(port, () => {
  console.log(`服务已启动: ${config.baseUrl}`);
  console.log(`健康检查间隔: ${config.healthCheck.interval/60000}分钟`);
});
