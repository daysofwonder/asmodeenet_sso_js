window.AsmodeeNet = (->

    defaultSuccessCallback = () -> console.log arguments
    defaultErrorCallback = () -> console.error arguments

    acceptableLocales = ['fr', 'de', 'en', 'it', 'es']

    default_settings =
        base_is_host: 'https://account.asmodee.net'
        base_is_path: '/main/v2/oauth'
        logout_endpoint: '/main/v2/logout'
        base_url: 'https://api.asmodee.net/main/v1'
        client_id: null
        redirect_uri: null
        cancel_uri: null # Only used in touch mode by the IS
        logout_redirect_uri: null # if not provided, and not configured in Studio manager for this app, the IS will redirect the user on IS page only!
        callback_post_logout_redirect: null # the only one solution for callback success in 'page' or 'touch' display mode
        base_uri_for_iframe: null
        scope: 'openid+profile'
        response_type: 'id_token token'
        display: 'popup'
        display_options: {}
        iframe_css: null # only used un 'iframe' display mode
        callback_signin_success: defaultSuccessCallback # the only one solution for callback success in 'page' or 'touch' display mode
        callback_signin_error: defaultErrorCallback # the only one solution for callback error in 'page' or 'touch' display mode

    settings = {}
    state = nonce = null
    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = code = null
    checkErrors = []
    localStorageIsOk = null
    popupIframeWindowName = 'AsmodeeNetConnectWithOAuth'
    try_refresh_name = 'try_refresh'
    _oauthWindow = null

    iFrame =
        element: null
        receiveMessageCallback: null
        saveOptions: null

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
            AsmodeeNet.signIn iFrame.saveOptions if settings.display == 'iframe'
        else
            window.location.reload()

    oauth = (options) ->
        if settings.display == 'popup'
            oauthpopup(options)
        else if settings.display == 'iframe'
            oauthiframe(options)
        else
            window.location.assign(options.path)

    getPopup = (options) ->
        options.width ?= 475
        options.height ?= 500
        options.windowName ?= popupIframeWindowName
        options.windowOptions ?= 'location=0,status=0,width=' + options.width +
                                    ',height=' + options.height
        options.callback ?= () -> window.location.reload()
        this._oauthWindow = window.open(options.path, options.windowName, options.windowOptions)

    oauthpopup = (options) ->
        getPopup options
        that = this
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

    oauthiframe = (options) ->
        options.width ?= 475
        options.height ?= 500
        options.callback ?= () -> window.location.reload()
        iFrame.element = if settings.iframe_css.indexOf('#') != -1 then window.document.getElementById(settings.iframe_css.replace('#', '')) else window.document.getElementsByClassName(settings.iframe_css)[0]
        if iFrame.element
            iFrame.element.name = popupIframeWindowName
            iFrame.element.width = options.width
            iFrame.element.height = options.height
            iFrame.element.src = options.path
            redirect_uri = settings.redirect_uri
            iFrame.element.focus() if iFrame.element && !iFrame.element.closed
            iFrame.element.removeEventListener('load', iFrame.receiveMessageCallback) if iFrame.receiveMessageCallback
            iFrame.receiveMessageCallback = (e) ->
                if e.currentTarget.name == popupIframeWindowName
                    d = (e.currentTarget.contentWindow || e.currentTarget.contentDocument)
                    item = getItem('gd_connect_hash')
                    options.callback() if item
            iFrame.element.addEventListener('load', iFrame.receiveMessageCallback, false)

    authorized = (access_hash_clt) ->
        access_hash = access_hash_clt
        access_token = access_hash.access_token
        id_token = access_hash.id_token
        code = access_hash.code if access_hash.code

    catHashCheck = (b_hash, bcode) ->
        mdHex = KJUR.crypto.Util.sha256(bcode)
        mdHex = mdHex.substr(0, mdHex.length/2)
        while !(b_hash.length % 4 == 0)
            b_hash += '='
        window.AsmodeeNet.verifyBHash(b_hash)
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
            if URI(it_dec.iss).normalize().toString() != URI(settings.base_is_host).normalize().toString()
                checkErrors.push 'Invalid issuer'
                return false
            if it_dec.aud != settings.client_id && (!Array.isArray(it_dec.aud) || id_dec.aud.indexOf(settings.client_id) == -1)
                checkErrors.push 'Invalid auditor'
                return false
            if it_dec.exp < window.AsmodeeNet.limit_exp_time()
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
                if key.alg && key.alg == alg[0]
                    try
                        return true if KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)
                    catch e
                        console.error('JWS verify error', e)
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
            if re.test(window.location.href) && settings.display != 'iframe'
                found_state = window.location.href.replace(settings.logout_redirect_uri + '&state=', '').replace(/[&#].*$/, '')
                if (found_state ==  getItem ('logout_state')) || (!found_state && !getItem('logout_state'))
                    removeItem 'logout_state'
                    if settings.callback_post_logout_redirect
                        settings.callback_post_logout_redirect()
                    else
                        window.location = '/'

    getLocation =(href) ->
        l = document.createElement("a")
        l.href = href

    baseLinkAction = (that, endpoint, options) ->
        options = options || {}
        locale = if options.locale then '/' + options.locale else ''
        locale = 'en' if (locale != '' && acceptableLocales.indexOf(locale) == -1)
        iFrame.saveOptions = AsmodeeNet.extend {}, options if settings.display == 'iframe'
        state = getCryptoValue()
        nonce = getCryptoValue()
        setItem('state', state, if settings.display == 'iframe' then 1440 else 20)
        setItem('nonce', nonce, if settings.display == 'iframe' then 1440 else 20)
        settings.callback_signin_success = options.success || settings.callback_signin_success
        settings.callback_signin_error = options.error || settings.callback_signin_error
        urlParsed = getLocation(endpoint)
        localizedEndpoint = endpoint.replace(urlParsed.pathname, options.locale + urlParsed.pathname)
        options.path = localizedEndpoint +
            '?display=' + settings.display +
            '&response_type=' + encodeURI(settings.response_type) +
            '&state=' + state +
            '&client_id=' + settings.client_id +
            '&scope=' + settings.scope
        if settings.redirect_uri
            ruri = settings.redirect_uri
            ruri += options.redirect_extra if options.redirect_extra
            options.path += '&redirect_uri=' + encodeURI(ruri)
        options.path += '&nonce='+nonce if settings.response_type.search('id_token') >= 0
        if Object.keys(settings.display_options).length > 0
            for k,v of settings.display_options
                options.path += '&display_opts['+k+']='+ if v then '1' else '0'
        options.path += '&cancel_uri=' + encodeURI(settings.cancel_uri) if settings.cancel_uri

        gameThis = that
        options.callback = () ->
            removeItem(try_refresh_name)
            signinCallback(gameThis)

        oauth(options)

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
                    if hash.state
                        if hash.state == state
                            hash.scope = hash.scope.split('+')
                            hash.expires = jwt_decode(hash.access_token)['exp']
                            checkErrors = []
                            if checkTokens(nonce, hash)
                                removeItem('state')
                                removeItem('nonce')
                                authorized(hash)
                                gameThis.identity {success: settings.callback_signin_success, error: settings.callback_signin_error}
                            else
                                settings.callback_signin_error('Tokens validation issue : ', checkErrors)
                        else
                            settings.callback_signin_error('Tokens validation issue : ', 'Invalid state')

            else if item.search(/^\?/) == 0
                splitted = item.replace(/^\?/, '').split('&')
                for t in splitted
                    t = t.split('=')
                    hash[t[0]] = t[1]
                state = getItem('state')
                removeItem('state')
                if hash.state && hash.state == state
                    settings.callback_signin_error(parseInt(hash.status), hash.error, hash.error_description.replace(/\+/g, ' '))

    checkDisplayOptions = () ->
        tmpopts = null
        if settings.display in ['touch', 'iframe']
            tmpopts = {noheader: true, nofooter: true, lnk2bt: true, leglnk: false, cookies: true}
        else if settings.display == 'popup'
            tmpopts = {noheader: false, nofooter: false, lnk2bt: false, leglnk: true}
        if Object.keys(settings.display_options).length > 0
            if tmpopts
                for opt, val of settings.display_options
                    delete settings.display_options[opt] unless opt in Object.keys(tmpopts)
        settings.display_options = AsmodeeNet.extend tmpopts, settings.display_options
        delete settings.display_options.cookies if 'cookies' in Object.keys(settings.display_options) && settings.display_options.cookies == true
        if settings.display == 'touch'
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
            store.set(name, value, new Date().getTime() + (minutes * 60000))
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


    verifyBHash: (b_hash) -> b_hash # internal use for tests

    init: (options) ->
        settings = this.extend(default_settings, options)
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
    getSettings: () -> this.extend({}, settings)
    getIdentity: () -> identity_obj

    getScopes: () ->
        return null if !this.isConnected()
        this.getAccessHash()['scope']

    getExpires: () ->
        return null if !this.isConnected()
        this.getAccessHash()['expires']

    getExpiresDate: () ->
        return null if !this.isConnected()
        new Date(this.getAccessHash()['expires']*1000)

    auth_endpoint: () ->
        return URI(discovery_obj.authorization_endpoint).normalize().toString() if discovery_obj
        URI(settings.base_is_host + settings.base_is_path + '/authorize').normalize().toString()

    ident_endpoint: () ->
        return URI(discovery_obj.userinfo_endpoint).normalize().toString() if discovery_obj
        URI(settings.base_is_host + settings.base_is_path + '/identity').normalize().toString()

    ajaxq: (type, url, options) ->
        options ?= {}
        base_url = options.base_url || settings.base_url || default_settings.base_url
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
        host_port = host_port || settings.base_is_host || default_settings.base_is_host
        host_port = URI(host_port)
        host_port = host_port.protocol() + '://' + host_port.host()
        gameThis = this
        this.get '/.well-known/openid-configuration',
            base_url: host_port
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
                console.error "error Discovery on "+host_port, arguments

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

    signUp: (locale, options, special_host, special_path) ->
        locale = 'en' if acceptableLocales.indexOf(locale) == -1
        special_host = discovery_obj.issuer unless special_host
        special_path = '/signup' unless special_path
        baseLinkAction(this, URI(special_host).normalize().toString() + locale + special_path, options)

    resetPass: (locale, options, special_host, special_path) ->
        locale = 'en' if acceptableLocales.indexOf(locale) == -1
        special_host = discovery_obj.issuer unless special_host
        special_path = '/reset' unless special_path
        baseLinkAction(this, URI(discovery_obj.issuer).normalize().toString() + locale + special_path, options)

    signIn: (options, special_host, special_path) ->
        if special_host
            special_host = URI(special_host).normalize().toString() + locale + special_path
        else
            special_host = this.auth_endpoint()
        baseLinkAction(this, special_host, options)

    identity: (options) ->
        if !this.isConnected()
            if options && options.error
                options.error('Identity error. Not connected', null, null, 'Not Connected')
            else
                console.error  'identity error', 'You\'re not connected'
            return false

        if this.isConnected() && identity_obj
            iFrame.element.src = '' if settings.display == 'iframe'
            options.success(identity_obj, AsmodeeNet.getCode()) if options && options.success
        else
            this.get '',
                base_url: this.ident_endpoint()
                success: (data) ->
                    identity_obj = data
                    iFrame.element.src = '' if settings.display == 'iframe'
                    options.success(identity_obj, AsmodeeNet.getCode()) if options && options.success
                error: (context, xhr, type, error) ->
                    if options && options.error
                        options.error(context, xhr, type, error)
                    else
                        console.error  'identity error', context, xhr, type, error

    restoreTokens: (saved_access_token, saved_id_token, call_identity = true, cbdone = null, clear_before_refresh = null, saved_identity = null) ->
        if (saved_access_token && access_token)
            saved_access_token = null
        if (saved_id_token && id_token)
            id_token = null
        if (saved_access_token)
            hash = {access_token: saved_access_token, id_token: saved_id_token}
            if (this.isJwksDone())
                if (checkTokens(null, hash))
                    decoded = jwt_decode(saved_access_token)
                    hash.scope = decoded['scope'].split(' ')
                    hash.expires = decoded['exp']
                    hash.token_type = decoded['token_type']
                    removeItem(try_refresh_name)
                    authorized(hash)
                    this.identity({success: settings.callback_signin_success, error: settings.callback_signin_error}) if call_identity
                    identity_obj = saved_identity if saved_identity
                    if cbdone
                        cbdone(true)
                    else
                        return true
                else
                    already_try_refresh = getItem(try_refresh_name)
                    removeItem(try_refresh_name)
                    if checkErrors[0] == 'Invalid expiration date' && clear_before_refresh && !already_try_refresh
                        console.log 'try refresh token'
                        setItem(try_refresh_name, true)
                        clear_before_refresh() && AsmodeeNet.signIn({success: cbdone})
                    else
                        if cbdone
                            cbdone(false, checkErrors)
                        else
                            return false
            else
                setTimeout( () ->
                    AsmodeeNet.restoreTokens(saved_access_token, saved_id_token, call_identity, cbdone, clear_before_refresh, saved_identity)
                , 200)

        return null

    setAccessToken: (saved_access_token) ->
        access_token = saved_access_token
    setIdToken: (save_id_token) ->
        id_token = save_id_token

    signOut: (options) ->
        successCallback = if options && typeof options.success != 'undefined' then options.success else null
        if this.isConnected() || options.force
            if settings.logout_redirect_uri
                state = getCryptoValue()
                id_token_hint = id_token
                setItem('logout_state', state, 5)
                logout_ep = settings.logout_endpoint +
                    '?post_logout_redirect_uri='+encodeURI(settings.logout_redirect_uri)+
                    '&state='+state+
                    '&id_token_hint='+id_token_hint
                if settings.display == 'iframe'
                    if iFrame.element
                        iFrame.element.src = logout_ep
                        redirect_uri = settings.logout_redirect_uri
                        iFrame.element.removeEventListener('load', iFrame.receiveMessageCallback) if iFrame.receiveMessageCallback
                        iFrame.receiveMessageCallback = (e) ->
                            disconnect(successCallback) if e.currentTarget.name == popupIframeWindowName
                        iFrame.element.addEventListener('load', iFrame.receiveMessageCallback, false)
                else if settings.display == 'popup'
                    options.path = logout_ep
                    options.callback = () ->
                        disconnect(successCallback)
                    oauthpopup(options)
                else
                    window.location = logout_ep
            else
                disconnect(successCallback)

    trackCb: (closeit) ->
        closeit ?= true

        if window.location.hash != ""
            setItem('gd_connect_hash', window.location.hash, 5)
        else if window.location.search != ""
            setItem('gd_connect_hash', window.location.search, 5)

        if window.name == 'AsmodeeNetConnectWithOAuth'
            console.log 'ok try closeit'
            window.close() if closeit

    inIframe: () ->
        return (window.self == window.top)

)()
if typeof window.AN == 'undefined'
    window.AN = window.AsmodeeNet

# For retro compatibility
if typeof window.GamifyDigital == 'undefined'
    window.GamifyDigital = window.AsmodeeNet
if typeof window.GD == 'undefined'
    window.GD = window.AsmodeeNet
