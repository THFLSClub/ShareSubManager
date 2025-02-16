const express = require('express')
const session = require('express-session')
const crypto = require('crypto')
const axios = require('axios')
const YAML = require('yaml')
const low = require('lowdb')
const FileSync = require('lowdb/adapters/FileSync')
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')

// 配置
const config = {
  admin: {
    username: 'thfls-admin',
    password: bcrypt.hashSync('twsub@2024', 8) // 示例密码，请修改
  },
  port: 3000,
  secret: 'your-secret-key-here'
}

// 初始化数据库
const adapter = new FileSync('db.json')
const db = low(adapter)
db.defaults({
  subscriptions: [],
  nodes: [],
  contributors: []
}).write()

const app = express()

// 中间件
app.use(session({
  secret: config.secret,
  resave: false,
  saveUninitialized: true
}))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
app.set('view engine', 'ejs')

// 登录验证中间件
const requireLogin = (req, res, next) => {
  if (req.session.isAdmin) return next()
  res.redirect('/login')
}

// 路由
app.get('/', (req, res) => {
  res.render('index', { 
    isAdmin: req.session.isAdmin,
    subsCount: db.get('subscriptions').size().value(),
    nodesCount: db.get('nodes').size().value()
  })
})

app.get('/login', (req, res) => {
  res.render('login')
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body
  if (username === config.admin.username && 
      await bcrypt.compare(password, config.admin.password)) {
    req.session.isAdmin = true
    return res.redirect('/admin')
  }
  res.render('login', { error: 'Invalid credentials' })
})

app.get('/logout', (req, res) => {
  req.session.destroy()
  res.redirect('/')
})

app.get('/admin', requireLogin, (req, res) => {
  res.render('admin', {
    subscriptions: db.get('subscriptions').value(),
    nodes: db.get('nodes').value()
  })
})

app.post('/add-subscription', requireLogin, async (req, res) => {
  try {
    const { url, type } = req.body
    console.log(`尝试添加订阅: URL=${url}, Type=${type}`) // 日志1
    const response = await axios.get(url)
    console.log('订阅内容获取成功:', response.data.slice(0, 50) + '...') // 日志2（截取部分内容）
    
    const parsed = await parseSubscription(response.data, type)
    console.log('解析后的节点:', parsed.nodes.length) // 日志3
    
    db.get('subscriptions').push({
      id: crypto.randomUUID(),
      url,
      type,
      nodes: parsed.nodes,
      createdAt: new Date()
    }).write()
    
    res.redirect('/admin')
  } catch (error) {
    console.error('添加订阅失败:', error.stack) // 完整错误堆栈
    res.status(500).send('Error processing subscription')
  }
})

app.post('/add-node', requireLogin, (req, res) => {
  const { link } = req.body;
  let node;

  if (link.startsWith('vmess://')) {
    node = parseV2rayLink(link);
  } else if (link.startsWith('ss://')) {
    node = parseSSLink(link);
  } else {
    return res.status(400).send('Unsupported link type');
  }

  if (node) {
    // 验证必要字段
    if (!node.server || !node.port || !node.method || !node.password) {
      return res.status(400).send('Invalid SS node configuration');
    }
    
    db.get('nodes').push({
      ...node,
      id: crypto.randomUUID(),
      createdAt: new Date()
    }).write();
    res.redirect('/admin');
  } else {
    res.status(400).send('Invalid node link');
  }
});

app.get('/subscribe/:type', async (req, res) => {
  try {
    const type = req.params.type
    const allNodes = [
      ...db.get('subscriptions').map(s => s.nodes).value().flat(),
      ...db.get('nodes').value()
    ]
    
    const uniqueNodes = Array.from(new Set(allNodes.map(n => JSON.stringify(n))))
      .map(s => JSON.parse(s))
    
    if (type === 'clash') {
      const clashConfig = generateClashConfig(uniqueNodes)
      res.set('Content-Type', 'text/yaml')
      res.send(clashConfig)
    } else if (type === 'v2ray') {
      const v2rayConfig = generateVConfig(uniqueNodes)
      res.set('Content-Type', 'text/plain')
      res.send(Buffer.from(v2rayConfig).toString('base64'))
    } else {
      res.status(400).send('Invalid subscription type')
    }
  } catch (error) {
    res.status(500).send('Error generating subscription')
  }
})

// 工具函数
async function parseSubscription(content, type) {
  try {
    if (type === 'clash') {
      const config = YAML.parse(content)
      if (!Array.isArray(config.proxies)) {
        throw new Error('Clash订阅格式错误：缺少proxies数组')
      }
      return { nodes: config.proxies }
    } else if (type === 'v2ray') {
      const decoded = Buffer.from(content, 'base64').toString('utf8')
      const nodes = JSON.parse(decoded)
      if (!Array.isArray(nodes)) {
        throw new Error('V2Ray订阅格式错误：应为节点数组')
      }
      return { nodes }
    }
    throw new Error('未知的订阅类型')
  } catch (error) {
    throw new Error(`解析失败: ${error.message}`)
  }
}

function parseV2rayLink(link) {
  if (!link.startsWith('vmess://')) return null
  const decoded = Buffer.from(link.slice(8), 'base64').toString()
  return JSON.parse(decoded)
}

function parseSSLink(link) {
  if (!link.startsWith('ss://')) return null;

  try {
    // 处理Base64编码部分
    const encoded = link.slice(5).split('#')[0].split('/')[0];
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    
    // 分割方法、密码和服务器信息
    const [auth, server] = decoded.split('@');
    const [method, password] = auth.split(':');
    const [host, port] = server.split(':');

    return {
      type: 'ss',
      name: decodeURIComponent(link.split('#')[1] || 'Unnamed SS Node'),
      server: host,
      port: parseInt(port),
      method: method,
      password: password,
      plugin: link.includes('plugin=') ? parseSSPlugin(link) : undefined
    };
  } catch (error) {
    // 尝试解析明文格式（非Base64）
    const match = link.match(/ss:\/\/(.*?):(.*?)@(.*?):(\d+)/);
    if (match) {
      return {
        type: 'ss',
        name: 'SS Node',
        server: match[3],
        port: parseInt(match[4]),
        method: match[1],
        password: match[2]
      };
    }
    return null;
  }
}

// 解析插件参数（如simple-obfs）
function parseSSPlugin(link) {
  const params = new URLSearchParams(link.split('?')[1]);
  return {
    name: params.get('plugin')?.split(';')[0],
    options: Object.fromEntries(
      params.get('plugin')?.split(';')[1]?.split(',')?.map(p => p.split('=')) || {})
  };
}

function generateClashConfig(nodes) {
  const clashNodes = nodes.map(node => {
    if (node.type === 'ss') {
      return {
        name: node.name,
        type: 'ss',
        server: node.server,
        port: node.port,
        cipher: node.method,
        password: node.password,
        plugin: node.plugin?.name,
        'plugin-opts': node.plugin?.options
      };
    }
    return node;
  });

  return YAML.stringify({
    proxies: clashNodes,
    'proxy-groups': [{
      name: 'TW Public Sub',
      type: 'select',
      proxies: clashNodes.map(n => n.name)
    }]
  });
}

function generateV2rayConfig(nodes) {
  return JSON.stringify(nodes.map(node => {
    if (node.type === 'ss') {
      return `ss://${Buffer.from(`${node.method}:${node.password}@${node.server}:${node.port}`)
        .toString('base64')}#${encodeURIComponent(node.name)}`;
    }
    return node;
  }));
}

// 视图模板
app.engine('ejs', require('ejs').renderFile)

// 启动服务器
app.listen(config.port, () => {
  console.log(`Server running on http://localhost:${config.port}`)
})
