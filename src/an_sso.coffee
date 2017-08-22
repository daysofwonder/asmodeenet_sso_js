window.AsmodeeNet = (->

    settings =
        base_is_host: 'https://account.asmodee.net'
        base_is_path: '/main/v2/oauth'
        logout_endpoint: '/main/v2/logout'
        base_url: 'https://api.asmodee.net/main/v1'
        client_id: null
        redirect_uri: null
        cancel_uri: null
        logout_redirect_uri: null
        callback_post_logout_redirect: null
        scope: 'openid+profile'
        response_type: 'id_token token'
        display: 'popup'
        display_options: {}
        callback_signin_success: defaultSuccessCallback
        callback_signin_error: defaultErrorCallback

    state = nonce = null
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = code = null
    checkErrors = []
    localStorageIsOk = null

    getCryptoValue = () ->
        crypto = window.crypto||window.msCrypto
        rnd = 0
        res = []
        if crypto
            rnd = crypto.getRandomValues(new Uint8Array(30))
        else
            rnd = [Math.random()]
        if rnd.constructor == Array
            rnd.forEach( (r) -> res.push(r.toString(36)))
        else
            for key, value of rnd
                if rnd.hasOwnProperty(key)
                    res.push(value.toString(36))
        return (res.join('')+'00000000000000000').slice(2, 16+2)

    disconnect = (callback) ->
        callback ?= false
        clearItems()

        access_token = id_token = access_hash = identity_obj = code = null
        if callback
            callback()
        else
            window.location.reload()

    oauth = (options) ->
        if settings.display == 'popup'
            oauthpopup(options)
        else
            window.location.assign(options.path)

    oauthpopup = (options) ->
        options.width ?= 475
        options.height ?= 500
        options.windowName ?= 'AsmodeeNetConnectWithOAuth'
        options.windowOptions ?= 'location=0,status=0,width=' + options.width +
                                    ',height=' + options.height
        options.callback ?= () -> window.location.reload()
        that = this
        that._oauthWindow = window.open(options.path, options.windowName, options.windowOptions)
        if options.autoclose
            that._oauthAutoCloseInterval = window.setInterval () ->
                that._oauthWindow.close()
                delete that._oauthWindow
                window.clearInterval(that._oauthAutoCloseInterval) if that._oauthAutoCloseInterval
                window.clearInterval(that._oauthInterval) if that._oauthInterval
                options.callback()
            , 500

        that._oauthInterval = window.setInterval () ->
            if that._oauthWindow.closed
                window.clearInterval(that._oauthInterval) if that._oauthInterval
                window.clearInterval(that._oauthAutoCloseInterval) if that._oauthAutoCloseInterval
                options.callback()
        , 1000

    authorized = (access_hash_clt) ->
        access_hash = access_hash_clt
        access_token = access_hash.access_token
        id_token = access_hash.id_token
        if access_hash.code
            code = access_hash.code

    catHashCheck = (b_hash, bcode) ->
        mdHex = KJUR.crypto.Util.sha256(bcode)
        mdHex = mdHex.substr(0, mdHex.length/2)
        while !(b_hash.length % 4 == 0)
            b_hash += '='
        return b_hash == btoa(mdHex)

    checkTokens = (nonce, hash) ->
        if hash.access_token
            try
                at_dec = jwt_decode(hash.access_token)
                at_head = jwt_decode(hash.access_token, { header: true })
            catch errdecode
                checkErrors.push "access_token decode error : "+errdecode
                return false
        if settings.response_type.search('id_token') >= 0
            if typeof hash.id_token == undefined
                return false
            try
                it_dec = jwt_decode(hash.id_token)
                it_head = jwt_decode(hash.id_token, { header: true })
            catch errdecode
                checkErrors.push "id_token decode error : "+errdecode
                return false
            if it_head.typ != 'JWT'
                checkErrors.push 'Invalid type'
                return false
            if it_head.alg != 'RS256'
                checkErrors.push 'Invalid alg'
                return false
            if nonce && (it_dec.nonce != nonce)
                checkErrors.push 'Invalid nonce'
                return false
            if URL(it_dec.iss).normalize().toString() != URI(settings.base_is_host).normalize().toString()
                checkErrors.push 'Invalid issuer'
                return false
            if it_dec.aud != settings.client_id && (!Array.isArray(it_dec.aud) || id_dec.aud.indexOf(settings.client_id) == -1)
                checkErrors.push 'Invalid auditor'
                return false
            if it_dec.exp < (Date.now()/1000).toPrecision(10)
                checkErrors.push 'Invalid expiration date'
                return false
            if typeof it_dec.at_hash == 'string' && !catHashCheck it_dec.at_hash, hash.access_token
                checkErrors.push 'Invalid at_hash'
                return false
            if hash.code && typeof it_dec.c_hash == 'string' && !catHashCheck it_dec.c_hash, hash.code
                checkErrors.push 'Invalid c_hash'
                return false
            alg = [it_head.alg]
            for key in jwks
                return true if KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)
            checkErrors.push 'Invalid JWS key'
            return false
        return true

    checkUrlOptions = () ->
        if settings.base_is_host
            u = URI(settings.base_is_host)
            settings.base_is_host = u.protocol() + '://' + u.host()
        if settings.base_url
            settings.base_url = URI(settings.base_url).normalize().toString()
        if settings.logout_redirect_uri
            settings.logout_redirect_uri = URI(settings.logout_redirect_uri).normalize().toString()

    checkLogoutRedirect = () ->
        if settings.logout_redirect_uri
            re = new RegExp(settings.logout_redirect_uri.replace(/([?.+*()])/g, "\\$1"))
            if re.test(window.location.href)
                found_state = window.location.href.replace(settings.logout_redirect_uri + '&state=', '').replace(/[&#].*$/, '')
                if (found_state ==  getItem ('logout_state')) || (!found_state && !getItem('logout_state'))
                    removeItem 'logout_state'
                    if settings.callback_post_logout_redirect
                        settings.callback_post_logout_redirect()
                    else
                        window.location = '/'

    defaultSuccessCallback = () -> console.log arguments
    defaultErrorCallback = () -> console.error arguments

    # TODO Code duplicated from inside signIn(), to be deduplicated
    signinCallback = (gameThis) ->
        item = getItem('gd_connect_hash')
        if !item
            settings.callback_signin_error("popup closed without signin") if settings.display == 'popup'
        else
            removeItem('gd_connect_hash')
            hash = {}
            splitted = null
            if item.search(/^#/) == 0
                splitted = item.replace(/^#/, '').split('&')
                for t in splitted
                    t = t.split('=')
                    hash[t[0]] = t[1]
                if hash.token_type && hash.token_type == 'bearer'
                    state = getItem('state')
                    nonce = getItem('nonce')
                    if hash.state && hash.state == state
                        hash.scope = hash.scope.split('+')
                        checkErrors = []
                        if checkTokens(nonce, hash)
                            removeItem('state')
                            removeItem('nonce')
                            authorized(hash)
                            gameThis.identity {success: settings.callback_signin_success, error: settings.callback_signin_error}
                        else
                            settings.callback_signin_error("Tokens validation issue : ", checkErrors)

            else if item.search(/^\?/) == 0
                splitted = item.replace(/^\?/, '').split('&')
                for t in splitted
                    t = t.split('=')
                    hash[t[0]] = t[1]
                if hash.state && hash.state == state
                    settings.callback_signin_error(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '))

    checkDisplayOptions = () ->
        if Object.keys(settings.display_options).length > 0
            if settings.display in ['touch', 'popup']
                tmpopts = {noheader: false, nofooter: false, lnk2bt: false, leglnk: true}
                for opt, val of settings.display_options
                    delete settings.display_options[opt] unless opt in Object.keys(tmpopts)
                if Object.keys(settings.display_options).length > 0
                    settings.display_options = AsmodeeNet.extend tmpopts, settings.display_options
            else
                settings.display_options = {}
        if settings.display == 'touch'
            if Object.keys(settings.display_options).length == 0
                settings.display_options = {noheader: true, nofooter: true, lnk2bt: true, leglnk: false}
            settings.cancel_uri = settings.redirect_uri if !settings.cancel_uri

    setCookie = (name, value, secondes) ->
        if secondes
            date = new Date()
            date.setTime date.getTime() + (secondes * 1000)
            expires = "; expires=" + date.toGMTString()
        else
            expires = ""
        document.cookie = name + "=" + value + expires + "; path=/"

    getCookie = (name) ->
        nameEQ = name + "="
        ca = document.cookie.split(";")
        i = 0
        while i < ca.length
            c = ca[i]
            c = c.substring(1, c.length)  while c.charAt(0) is " "
            return c.substring(nameEQ.length, c.length)  if c.indexOf(nameEQ) is 0
            i++
        null

    deleteCookie = (name) ->
        setCookie name, "", -1

    clearCookies = () ->
        cookies = document.cookie.split('; ')
        for cookie in cookies
            cookieBase = encodeURIComponent(cookie.split(";")[0].split("=")[0]) + '=; expires=Thu, 01-Jan-1970 00:00:01 GMT; domain=' + d.join('.') + ' ;path='
            pathBits = location.pathname.split('/')
            while pathBits.length > 0
                document.cookie = cookieBase + pathBits.join('/')
                pathBits.pop()

    setItem = (name, value, minutes) ->
        try
            store.set(name, value, new Date().getTime() + minutes)
        catch error
            console.error "SetItem '"+name+"'", value, error

    getItem = (name) ->
        try
            return store.get(name)
        catch error
            console.error "GetItem '"+name+"'", error
            return null

    removeItem = (name) ->
        store.remove(name)

    clearItems = () ->
        store.clearAll()

    init: (options) ->
        settings = this.extend(settings, options)
        checkUrlOptions()
        checkDisplayOptions()
        checkLogoutRedirect()
        this

    baseSettings: () ->
        crossDomain: true
        dataType: 'json'
        headers:
            'Authorization': 'Bearer '+access_token
            'Accept': 'application/json'

    isConnected: () -> this.getAccessToken() != null
    getAccessToken: () -> access_token
    getIdToken: () -> id_token
    getAccessHash: () -> access_hash
    getDiscovery: () -> discovery_obj
    getCode: () -> code
    getCheckErrors: () -> checkErrors
    isJwksDone: () -> jwks != null
    getConfiguredScope: () -> settings.scope
    getConfiguredAPI: () -> settings.base_url
    getClientId: () -> settings.client_id

    auth_endpoint: () ->
        return URI(discovery_obj.authorization_endpoint).normalize().toString() if discovery_obj
        URI(settings.base_is_host + settings.base_is_path + '/authorize').normalize().toString()

    ident_endpoint: () ->
        return URI(discovery_obj.userinfo_endpoint).normalize().toString() if discovery_obj
        URI(settings.base_is_host + settings.base_is_path + '/identity').normalize().toString()

    ajaxq: (type, url, options) ->
        options ?= {}
        base_url = options.base_url || settings.base_url
        delete options.base_url
        sets = this.extend(options, this.baseSettings(), {type: type})
        if options.auth != undefined && options.auth == false
            delete sets.headers.Authorization if sets.headers.Authorization
            delete sets.auth
        this.ajax(base_url + url, sets)
    get: (url, options) ->
        return this.ajaxq('GET', url, options)
    post: (url, options) ->
        return this.ajaxq('POST', url, options)
    update: (url, options) ->
        return this.ajaxq('PUT', url, options)
    delete: (url, options) ->
        return this.ajaxq('DELETE', url, options)

    discover: (host_port) ->
        host_port = host_port || settings.base_is_host
        gameThis = this
        this.get '/.well-known/openid-configuration',
            base_url: URI(host_port).normalize().toString()
            auth: false
            success: (data) ->
                if typeof data == 'object'
                    discovery_obj = data
                else
                    discovery_obj = JSON.parse(data)
                settings.base_is_host = URI(discovery_obj.issuer).normalize().toString()
                settings.logout_endpoint = URI(discovery_obj.end_session_endpoint).normalize().toString()
                gameThis.getJwks()
            error: () ->
                console.error "error Discovery ", arguments

    getJwks: () ->
        gameThis = this
        this.get '',
            base_url: URI(discovery_obj.jwks_uri).normalize().toString()
            auth: false
            success: (data) ->
                if typeof data == 'object'
                    jwks = data.keys
                else
                    jwks = JSON.parse(data).keys
                if settings.display != 'popup'
                    signinCallback gameThis
            error: () ->
                console.error "error JWKS", arguments
                console.error "error JWKS => "+arguments[0] if arguments.length > 0
                console.error "error JWKS => "+arguments[0].statusText if arguments.length > 0

    signIn: (options) ->
        state = getCryptoValue()
        nonce = getCryptoValue()
        setItem('state', state, 100)
        setItem('nonce', nonce, 100)
        settings.callback_signin_success = options.success || settings.callback_signin_success
        settings.callback_signin_error = options.error || settings.callback_signin_error
        options.path = this.auth_endpoint() +
            '?display=' + settings.display +
            '&response_type=' + encodeURI(settings.response_type) +
            '&state=' + state +
            '&client_id=' + settings.client_id +
            '&scope=' + settings.scope
        options.path += '&redirect_uri=' + encodeURI(settings.redirect_uri) if settings.redirect_uri
        options.path += '&nonce='+nonce if settings.response_type.search('id_token') >= 0
        if Object.keys(settings.display_options).length > 0
            for k,v of settings.display_options
                options.path += '&display_opts['+k+']='+ if v then '1' else '0'
        options.path += '&cancel_uri=' + encodeURI(settings.cancel_uri) if settings.cancel_uri

        gameThis = this
        options.callback = () ->
            item = getItem('gd_connect_hash')
            if !item
                settings.callback_signin_error("popup closed without signin") if settings.display == 'popup'
            else
                removeItem('gd_connect_hash')
                hash = {}
                splitted = null
                if item.search(/^#/) == 0
                    splitted = item.replace(/^#/, '').split('&')
                    for t in splitted
                        t = t.split('=')
                        hash[t[0]] = t[1]
                    if hash.token_type && hash.token_type == 'bearer'
                        state = getItem('state')
                        nonce = getItem('nonce')
                        if hash.state && hash.state == state
                            hash.scope = hash.scope.split('+')
                            checkErrors = []
                            if checkTokens(nonce, hash)
                                removeItem('state')
                                removeItem('nonce')
                                authorized(hash)
                                gameThis.identity {success: settings.callback_signin_success, error: settings.callback_signin_error}
                            else
                                settings.callback_signin_error("Tokens validation issue", checkErrors)

                else if item.search(/^\?/) == 0
                    splitted = item.replace(/^\?/, '').split('&')
                    for t in splitted
                        t = t.split('=')
                        hash[t[0]] = t[1]
                    if hash.state && hash.state == state
                        settings.callback_signin_error(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '))

        oauth(options)

    identity: (options) ->
        if !this.isConnected()
            if options && options.error
                options.error('Identity error. Not connected', null, null, 'Not Connected')
            else
                console.error  'identity error', 'You\'re not connected'
            return false

        if this.isConnected() && identity_obj
            options.success(identity_obj, AsmodeeNet.getCode()) if options && options.success
        else
            this.get '',
                base_url: this.ident_endpoint()
                success: (data) ->
                    identity_obj = data
                    options.success(identity_obj, AsmodeeNet.getCode()) if options && options.success
                error: (context, xhr, type, error) ->
                    if options && options.error
                        options.error(context, xhr, type, error)
                    else
                        console.error  'identity error', context, xhr, type, error

    restoreTokens: (saved_access_token, saved_id_token, call_identity = true, cbdone = null) ->
        if (saved_access_token && access_token)
            saved_access_token = null
        if (saved_id_token && id_token)
            id_token = null
        if (saved_access_token)
            hash = {access_token: saved_access_token, id_token: saved_id_token}
            if (this.isJwksDone())
                if (checkTokens(null, hash))
                    authorized(hash)
                    this.identity({success: settings.callback_signin_success, error: settings.callback_signin_error}) if call_identity
                    if cbdone
                        cbdone(true)
                    else
                        return true
                else
                    if cbdone
                        cbdone(false, checkErrors)
                    else
                        return false
            else
                setTimeout( () ->
                    AsmodeeNet.restoreTokens(saved_access_token, saved_id_token, call_identity, cbdone)
                , 200)

        return null

    setAccessToken: (saved_access_token) ->
        access_token = saved_access_token
    setIdToken: (save_id_token) ->
        id_token = save_id_token

    signOut: (options) ->
        if this.isConnected()
            if settings.logout_redirect_uri
                state = getCryptoValue()
                setItem('logout_state', state, 100)
                window.location = settings.logout_endpoint +
                    '?post_logout_redirect_uri='+encodeURI(settings.logout_redirect_uri)+
                    '&state='+state+
                    '&id_token_hint='+id_token
            else
                disconnect(options.success)

    trackCb: (closeit) ->
        closeit ?= true

        if window.location.hash != ""
            setItem('gd_connect_hash', window.location.hash, 100)
        else if window.location.search != ""
            setItem('gd_connect_hash', window.location.search, 100)

        if window.name == 'AsmodeeNetConnectWithOAuth'
            window.close() if closeit

)()
if typeof window.AN == 'undefined'
    window.AN = window.AsmodeeNet

# For retro compatibility
if typeof window.GamifyDigital == 'undefined'
    window.GamifyDigital = window.AsmodeeNet
if typeof window.GD == 'undefined'
    window.GD = window.AsmodeeNet
