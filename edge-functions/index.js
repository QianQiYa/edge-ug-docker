import JSEncrypt from 'jsencrypt'

const Database = {
    async getObject(key) {
        const value = await nas.get(key)
        if (value == null) {
            return null
        }
        return JSON.parse(value)
    },
    async setObject(key, value) {
        if (value == null) {
            await nas.delete(key)
        } else {
            await nas.put(this.key, JSON.stringify(value))
        }
    }
}

const CookieHelper = {
    getSetCookieObject(response) {
        const cookieObject = {}
        const setCookie = response.headers.getSetCookie()
        if (setCookie) {
            for (let cookieStr of setCookie) {
                const [key, value] = cookieStr.split(';')[0].split('=')
                cookieObject[key] = value
            }
        }
        return cookieObject
    },
    getCookieObject(cookieStr) {
        const cookieObject = {}
        if (cookieStr == null) {
            return cookieObject
        }
        const cookieArr = cookieStr.split('; ')
        for (let cookie of cookieArr) {
            const cookieObj = cookie.split('=')
            cookieObject[cookieObj[0]] = decodeURIComponent(cookieObj[1])
        }
        return cookieObject
    },
    getCookieStr(cookieObject) {
        const cookieArr = []
        if (cookieObject) {
            for (let key of Object.keys(cookieObject)) {
                cookieArr.push(key + '=' + encodeURIComponent(cookieObject[key]))
            }
        }
        return cookieArr.join('; ')
    }
}

const getUGreenLink = async ctx => {
    const config = ctx.config
    const aliasUrl = new URL('https://api-zh.ugnas.com/api/p2p/v2/ta/nodeInfo/byAlias')
    const response = await fetch(aliasUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alias: config.alias})
    })
    const res = await response.json()
    return 'https://' + config.alias + '.' + res.data.relayDomain
}

const getPublicKey = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/verify/check')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            username: config.username
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const base64Str = response.headers.get('x-rsa-token')
    return atob(base64Str)
}

const getPassword = async ctx => {
    const config = ctx.config
    const encryptor = new JSEncrypt()
    encryptor.setPublicKey(ctx.publicKey)
    return encryptor.encrypt(config.password)
}

const login = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/verify/login')
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify({
            is_simple: true,
            keepalive: true,
            otp: true,
            username: config.username,
            password: ctx.password
        }),
        headers: {'Content-Type': 'application/json'}
    })
    const json = await response.json()
    return json.data
}

const getDockerToken = async ctx => {
    const config = ctx.config
    const url = new URL(ctx.link + '/ugreen/v1/gateway/proxy/dockerToken')
    url.searchParams.set('token', ctx.token)
    url.searchParams.set('port', config.port)
    const response = await fetch(url)
    const json = await response.json()
    return json.data['redirect_url']
}

const getProxyInfo = async ctx => {
    const response = await fetch(ctx.dockerToken, {
        method: 'GET',
        redirect: 'manual',
    })
    const origin = new URL(ctx.dockerToken).origin
    const cookieObject = CookieHelper.getSetCookieObject(response)
    const token = cookieObject['ugreen-proxy-token']
    return {origin, token}
}

const proxy = async (request, origin, token) => {
    const requestUrl = new URL(request.url)
    const requestOrigin = requestUrl.origin
    
    const target = request.url.replace(requestOrigin, origin)
    const targetUrl = new URL(target)
    const targetHeaders = new Headers(request.headers)
    targetHeaders.set('host', targetUrl.host)
    
    const cookieObject = CookieHelper.getCookieObject(request.headers.get('cookie'))
    cookieObject['ugreen-proxy-token'] = token
    targetHeaders.set('cookie', CookieHelper.getCookieStr(cookieObject))
    
    const response = await fetch(targetUrl, {
        method: request.method,
        headers: targetHeaders,
        body: request.body,
        redirect: 'manual'
    })
    
    if (Array.from(response.headers.keys()).length === 1) {
        if (response.headers.get('content-type') === 'text/html; charset=UTF-8') {
            const clone = response.clone()
            const html = await clone.text()
            if (html.includes('https://www.ug.link/errorPage')) {
                throw new Error('访问错误')
            }
        }
    }
    
    return response
}

export async function onRequest(context) {
    const request = context.request
    const env = context.env
    const config = {
        alias: env.UG_LINK,
        username: env.UG_USERNAME,
        password: env.UG_PASSWORD,
        port: env.UG_PORT
    }
    const ctx = {}
    const key = config.alias + ':' + config.port
    try {
        const cache = await Database.getObject(key)
        if (cache) {
            const response = await proxy(request, cache.origin, cache.token)
            response.headers.set('x-edge-kv', 'hit')
            return response
        }
    } catch (error) {
        console.log('缓存访问出错')
    }
    ctx.config = config
    try {
        ctx.link = await getUGreenLink(ctx)
        ctx.publicKey = await getPublicKey(ctx)
        ctx.password = await getPassword(ctx)
        const loginInfo = await login(ctx)
        ctx.token = loginInfo.token
        ctx.dockerToken = await getDockerToken(ctx)
        const proxyInfo = await getProxyInfo(ctx)
        ctx.proxyOrigin = proxyInfo.origin
        ctx.proxyToken = proxyInfo.token
        const response = await proxy(request, ctx.proxyOrigin, ctx.proxyToken)
        response.headers.set('x-edge-kv', 'miss')
        await Database.setObject(key, {origin: ctx.proxyOrigin, token: ctx.proxyToken})
        return response
    } catch (error) {
        console.log('error', error)
        return new Response('访问出错', {status: 500})
    }
}

