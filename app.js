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
    const response = await axios.get(url)
    const content = response.data
    
    const parsed = await parseSubscription(content, type)
    
    db.get('subscriptions').push({
      id: crypto.randomUUID(),
      url,
      type,
      nodes: parsed.nodes,
      createdAt: new Date()
    }).write()
    
    res.redirect('/admin')
  } catch (error) {
    res.status(500).send('Error processing subscription')
  }
})

app.post('/add-node', requireLogin, (req, res) => {
  const { link } = req.body
  const node = parseV2rayLink(link)
  
  if (node) {
    db.get('nodes').push({
      ...node,
      id: crypto.randomUUID(),
      createdAt: new Date()
    }).write()
    res.redirect('/admin')
  } else {
    res.status(400).send('Invalid node link')
  }
})

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
  if (type === 'clash') {
    const config = YAML.parse(content)
    return { nodes: config.proxies }
  } else if (type === 'v2ray') {
    const decoded = Buffer.from(content, 'base64').toString()
    return { nodes: JSON.parse(decoded) }
  }
  throw new Error('Unsupported subscription type')
}

function parseV2rayLink(link) {
  if (!link.startsWith('vmess://')) return null
  const decoded = Buffer.from(link.slice(8), 'base64').toString()
  return JSON.parse(decoded)
}

function generateClashConfig(nodes) {
  return YAML.stringify({
    proxies: nodes,
    'proxy-groups': [{
      name: 'TW Public Sub',
      type: 'select',
      proxies: nodes.map(n => n.name)
    }]
  })
}

function generateV2rayConfig(nodes) {
  return JSON.stringify(nodes.map(n => ({
    ...n,
    ps: n.name || 'TW Node',
    add: n.address,
    port: n.port,
    id: n.uuid,
    aid: n.alterId || 0
  })))
}

// 视图模板
app.engine('ejs', require('ejs').renderFile)

// 启动服务器
app.listen(config.port, () => {
  console.log(`Server running on http://localhost:${config.port}`)
})
