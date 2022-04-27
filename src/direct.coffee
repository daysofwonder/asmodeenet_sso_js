window.AsmodeeNet = AsmodeeNet()

window.AsmodeeNet.ajax = ajaxCl
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

if typeof window.AN == 'undefined'
    window.AN = window.AsmodeeNet

# For retro compatibility
if typeof window.GamifyDigital == 'undefined'
    window.GamifyDigital = window.AsmodeeNet
if typeof window.GD == 'undefined'
    window.GD = window.AsmodeeNet
if !window.jwt_decode
    window.jwt_decode = window.AsmodeeNet.jwt_decode
