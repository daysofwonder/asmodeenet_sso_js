window.GamifyDigital = (->

    settings =
        base_is_host: 'https://account.gamify-digital.com'
        base_is_path: '/main/v2/oauth'
        base_url: 'https://api.gamify-digital.com/main/v1'
        client_id: null
        redirect_uri: null
        scope: 'openid+profile'
        response_type: 'id_token token'

    access_token = id_token = access_hash = identity_obj = discovery_obj = jwks = null

    disconnect = (callback) ->
        callback ?= false
        window.localStorage.clear()
        access_token = id_token = access_hash = identity_obj = null
        if callback
            callback()
        else
            window.location.reload()

    oauthpopup = (options) ->
        options.windowName ?= 'GamifyConnectWithOAuth'
        options.windowOptions ?= 'location=0,status=0,width=400,height=800'
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

    checkTokens = (nonce, hash) ->
        if hash.access_token
            at_dec = jwt_decode(hash.access_token)
            at_head = jwt_decode(hash.access_token, { header: true })
        if settings.response_type.search('id_token') >= 0
            if typeof hash.id_token == undefined
                return false
            it_dec = jwt_decode(hash.id_token)
            it_head = jwt_decode(hash.id_token, { header: true })
            return false if it_head.typ != 'JWT'
            return false if it_head.alg != 'RS256'
            return false if it_dec.nonce != nonce
            return false if it_dec.iss != settings.base_is_host
            return false if it_dec.aud != settings.client_id
            return false if it_dec.exp < (Date.now()/1000).toPrecision(10)
            alg = [it_head.alg]
            for key in jwks
                return true if KJUR.jws.JWS.verify(hash.id_token, KEYUTIL.getKey(key), alg)
            return false
        return true


    init: (options) ->
        settings = this.extend(settings, options)
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

    auth_endpoint: () ->
        return discovery_obj.authorization_endpoint if discovery_obj
        settings.base_is_host + settings.base_is_path + '/authorize'

    ident_endpoint: () ->
        return discovery_obj.userinfo_endpoint if discovery_obj
        settings.base_is_host + settings.base_is_path + '/identity'

    get: (url, options) ->
        options ?= {}
        base_url = options.base_url || settings.base_url
        delete options.base_url
        sets = this.extend(options, this.baseSettings(), {type: 'GET'})
        if options.auth != undefined && options.auth == false
            delete sets.headers.Authorization if sets.headers.Authorization
            delete sets.auth
        this.ajax(base_url + url, sets)

    discover: (host_port) ->
        host_port = host_port || settings.base_is_host
        gameThis = this
        this.get '/.well-known/openid-configuration',
            base_url: host_port
            auth: false
            success: (data) ->
                discovery_obj = data
                settings.base_is_host = discovery_obj.issuer
                gameThis.getJwks()
            error: () ->
                console.error "error Discovery ", arguments

    getJwks: () ->
        this.get '',
            base_url: discovery_obj.jwks_uri
            auth: false
            success: (data) ->
                jwks = data.keys
            error: () ->
                console.error "error JWKS", arguments

    signIn: (options) ->
        state = (Math.random().toString(36)+'00000000000000000').slice(2, 16+2)
        nonce = (Math.random().toString(36)+'00000000000000000').slice(2, 16+2)
        main_cb = options.success || () -> console.log arguments
        error_cb = options.error || () -> console.error 'error', arguments
        options.path = this.auth_endpoint() + '?response_type='+encodeURI(settings.response_type)+
            '&state='+state+'&client_id='+
            settings.client_id+'&redirect_uri='+
            encodeURI(settings.redirect_uri)+'&scope='+settings.scope
        options.path += '&nonce='+nonce if settings.response_type.search('id_token') >= 0
        gameThis= this
        pr_callback = () ->
            item = window.localStorage.getItem('gd_connect_hash')
            if item
                window.localStorage.removeItem('gd_connect_hash')
                hash = {}
                splitted = null
                if item.search(/^#/) == 0
                    splitted = item.replace(/^#/, '').split('&')
                    for t in splitted
                        t = t.split('=')
                        hash[t[0]] = t[1]
                    # fix until the server return token_type
                    if true || hash.token_type && hash.token_type == 'bearer'
                        if hash.state && hash.state == state
                            # hybrid flow doesn't require the scope
                            if hash.scope
                                hash.scope = hash.scope.split('+')
                            if checkTokens(nonce, hash)
                                authorized(hash)
                                gameThis.identity {success: main_cb, error: error_cb}
                            else
                                error_cb("Tokens validation issue")

                else if item.search(/^\?/) == 0
                    splitted = item.replace(/^\?/, '').split('&')
                    for t in splitted
                        t = t.split('=')
                        hash[t[0]] = t[1]
                    if hash.state && hash.state == state
                        error_cb(hash.error + ' : ' + hash.error_description.replace(/\+/g, ' '))
            else
                error_cb("popup closed without signin")

        options.callback = pr_callback
        oauthpopup(options)

    identity: (options) ->
        if this.isConnected() && identity_obj
            options.success(identity_obj) if options.success
        else
            this.get '',
                base_url: this.ident_endpoint()
                success: (data) ->
                    identity_obj = data
                    options.success(identity_obj) if options.success
                error: (context, xhr, type, error) ->
                    console.error  'identity error', context, xhr, type, error
                    options.error(context, xhr, type, error) if options.error

    signOut: (options) ->
        if this.isConnected()
            so_path = options.path || settings.base_is_host + '/signout'
            cb = options.success || false
            oauthpopup path: so_path, autoclose: true, callback: () -> disconnect(cb)

    trackCb: (closeit) ->
        closeit ?= true
        if window.name == 'GamifyConnectWithOAuth'
            if window.location.hash != ""
                window.localStorage.setItem('gd_connect_hash', window.location.hash)
            else if window.location.search != ""
                window.localStorage.setItem('gd_connect_hash', window.location.search)
            window.close() if closeit
)()
