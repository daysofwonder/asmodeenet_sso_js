window.AsmodeeNet.extend = () ->
    ret = {}
    for obj in arguments
        for key of obj
            ret[key] = obj[key] if Object::hasOwnProperty.call(obj,key)
    return ret

window.AsmodeeNet.limit_exp_time = () -> return (Date.now()/1000).toPrecision(10)

window.AsmodeeNet.jwt_decode = (token, options) ->
    deco = KJUR.jws.JWS.parse(token)
    return deco.headerObj if options && options.header != "undefined" && options.header == true
    return deco.payloadObj

if !window.jwt_decode
    window.jwt_decode = window.AsmodeeNet.jwt_decode
