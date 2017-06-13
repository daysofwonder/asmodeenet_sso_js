window.AsmodeeNet.ajax = (url, settings) ->
    args = arguments
    settings = if args.length == 1 then args[0] else args[1]

    emptyFunction = () ->
        null

    defaultSettings =
        url: if args.length == 2 && (typeof url == 'string') then url else '.'
        cache: true
        data: {}
        headers: {}
        context: null
        type: 'GET'
        success: emptyFunction
        error: emptyFunction
        complete: emptyFunction

    settings = this.extend(defaultSettings, settings || {})

    mimeTypes =
        'application/json': 'json'
        'text/html': 'html'
        'text/plain': 'text'

    if !settings.cache
        settings.url = settings.url +
                        (settings.url.indexOf('?') ? '&' : '?') +
                        'noCache=' +
                        Math.floor(Math.random() * 9e9)

    success = (data, xhr, settings) ->
        status = 'success'
        settings.success.call(settings.context, data, status, xhr)
        complete(status, xhr, settings)

    error   = (error, type, xhr, settings) ->
        settings.error.call(settings.context, xhr, type, error)
        complete(type, xhr, settings)

    complete = (status, xhr, settings) ->
        settings.complete.call(settings.context, xhr, status)

    xhr = new XMLHttpRequest()

    readyStateChange = () ->
        if xhr.readyState == 4
            result = null
            dataType = null

            if (xhr.status >= 200 && xhr.status < 300) || xhr.status == 304
                mime = xhr.getResponseHeader('content-type')
                dataType = mimeTypes[mime] || 'text'
                result = xhr.responseText

                try
                    if dataType == 'json'
                        result = JSON.parse(result)
                    success(result, xhr, settings)
                    return
                catch e

            error(null, 'error', xhr, settings)

    if xhr.addEventListener
        xhr.addEventListener('readystatechange', readyStateChange, false)
    else if xhr.attachEvent
        xhr.attachEvent('onreadystatechange', readyStateChange)


    xhr.open(settings.type, settings.url)

    if settings.type == 'POST'
        settings.headers = this.extend(settings.headers, {
            'X-Requested-With': 'XMLHttpRequest',
            'Content-type': 'application/x-www-form-urlencoded'
        })

    for key of settings.headers
        xhr.setRequestHeader(key, settings.headers[key])
    xhr.send(settings.data)

    return this
