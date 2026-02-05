import JSEncrypt from 'jsencrypt'

/* ===================== KV 存储 ===================== */

const Database = {
  async getObject(key) {
    const value = await nas.get(key)
    if (!value) return null
    return JSON.parse(value)
  },
  async setObject(key, value) {
    if (!value) {
      await nas.delete(key)
    } else {
      await nas.put(key, JSON.stringify(value))
    }
  }
}

/* ===================== Cookie 工具 ===================== */

const CookieHelper = {
  getSetCookieObject(response) {
    const cookieObject = {}
    const setCookie = response.headers.getSetCookie?.() || []
    for (const cookieStr of setCookie) {
      const eq = cookieStr.indexOf('=')
      const semi = cookieStr.indexOf(';')
      if (eq > 0) {
        const key = cookieStr.slice(0, eq)
        const value = cookieStr.slice(eq + 1, semi > 0 ? semi : cookieStr.length)
        cookieObject[key] = value
      }
    }
    return cookieObject
  },

  getCookieObject(cookieStr) {
    const cookieObject = {}
    if (!cookieStr) return cookieObject
    for (const cookie of cookieStr.split('; ')) {
      const [k, v] = cookie.split('=')
      cookieObject[k] = decodeURIComponent(v || '')
    }
    return cookieObject
  },

  getCookieStr(cookieObject) {
    return Object.entries(cookieObject)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('; ')
  }
}

/* ===================== 绿联 API ===================== */

const getUGreenLink = async ctx => {
  const aliasUrl = 'https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias'
  const res = await fetch(aliasUrl, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ alias: ctx.config.alias })
  }).then(r => r.json())

  return `https://${ctx.config.alias}.${res.data.relayDomain}`
}

const getPublicKey = async ctx => {
  const url = ctx.link + '/ugreen/v1/verify/check'
  const resp = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ username: ctx.config.username })
  })
  return atob(resp.headers.get('x-rsa-token'))
}

const getPassword = async ctx => {
  const encryptor = new JSEncrypt()
  encryptor.setPublicKey(ctx.publicKey)
  return encryptor.encrypt(ctx.config.password)
}

const login = async ctx => {
  const url = ctx.link + '/ugreen/v1/verify/login'
  const resp = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      is_simple: true,
      keepalive: true,
      otp: true,
      username: ctx.config.username,
      password: ctx.password
    })
  })
  const json = await resp.json()
  return json.data.token
}

const getDockerToken = async ctx => {
  const url = new URL(ctx.link + '/ugreen/v1/gateway/proxy/dockerToken')
  url.searchParams.set('token', ctx.token)
  url.searchParams.set('port', ctx.config.port)
  const resp = await fetch(url)
  const json = await resp.json()
  return json.data.redirect_url
}

/* ===================== 核心：获取 proxy token（支持 302 跳转） ===================== */

const getProxyInfo = async ctx => {
  let url = ctx.dockerToken
  let origin = new URL(url).origin
  let token = null

  for (let i = 0; i < 6; i++) {
    const resp = await fetch(url, {
      method: 'GET',
      redirect: 'manual'
    })

    const cookieObject = CookieHelper.getSetCookieObject(resp)
    if (cookieObject['ugreen-proxy-token']) {
      token = cookieObject['ugreen-proxy-token']
      break
    }

    const location = resp.headers.get('location')
    if (!location) break

    url = location.startsWith('http') ? location : origin + location
  }

  if (!token) {
    throw new Error('无法获取 ugreen-proxy-token')
  }

  return { origin, token }
}

/* ===================== 反向代理 ===================== */

const proxy = async (request, origin, token) => {
  const reqUrl = new URL(request.url)
  const targetUrl = new URL(reqUrl.pathname + reqUrl.search, origin)

  const headers = new Headers(request.headers)
  headers.set('host', targetUrl.host)

  const cookieObj = CookieHelper.getCookieObject(request.headers.get('cookie'))
  cookieObj['ugreen-proxy-token'] = token
  headers.set('cookie', CookieHelper.getCookieStr(cookieObj))

  const resp = await fetch(targetUrl, {
    method: request.method,
    headers,
    body: request.body,
    redirect: 'manual'
  })

  return resp
}

/* ===================== EdgeOne 入口 ===================== */

export async function onRequest(context) {
  const { request, env } = context

  const config = {
    alias: env.UG_ALIAS,
    username: env.UG_USERNAME,
    password: env.UG_PASSWORD,
    port: env.UG_PORT
  }

  const key = `${config.alias}:${config.port}`

  // 1️⃣ 优先使用 KV 缓存
  try {
    const cache = await Database.getObject(key)
    if (cache?.origin && cache?.token) {
      const resp = await proxy(request, cache.origin, cache.token)
      resp.headers.set('x-edge-kv', 'hit')
      return resp
    }
  } catch (e) {
    console.log('KV 读取失败', e)
  }

  // 2️⃣ 重新登录获取 token
  try {
    const ctx = { config }

    ctx.link = await getUGreenLink(ctx)
    ctx.publicKey = await getPublicKey(ctx)
    ctx.password = await getPassword(ctx)
    ctx.token = await login(ctx)
    ctx.dockerToken = await getDockerToken(ctx)
    const proxyInfo = await getProxyInfo(ctx)

    const resp = await proxy(request, proxyInfo.origin, proxyInfo.token)
    resp.headers.set('x-edge-kv', 'miss')

    await Database.setObject(key, {
      origin: proxyInfo.origin,
      token: proxyInfo.token,
      ts: Date.now()
    })

    return resp
  } catch (e) {
    console.log('ERROR', e)
    return new Response('代理失败: ' + e.message, { status: 500 })
  }
}
