window.GamifyDigital.extend = () ->
    ret = {}
    for obj in arguments
        for key of obj
            ret[key] = obj[key] if Object::hasOwnProperty.call(obj,key)
    return ret

window.GamifyDigital.jwt_decode = (token, options) ->
    deco = KJUR.jws.JWS.parse(token)
    return deco.headerObj if options && options.header != "undefined" && options.header == true
    return deco.payloadObj

if !window.jwt_decode
    window.jwt_decode = window.GamifyDigital.jwt_decode
