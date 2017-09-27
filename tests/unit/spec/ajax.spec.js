
describe('Ajax included minitools', function () {
    var request, onSuccess, onFailure, onComplete;

    beforeEach(function () {
        jasmine.Ajax.install();

        onComplete = jasmine.createSpy('onComplete');
        onSuccess = jasmine.createSpy('onSuccess');
        onFailure = jasmine.createSpy('onFailure');
    });

    afterEach(function () {
        jasmine.Ajax.uninstall();
    });

    it('should have an AsmodeeNet.ajax', function () {
        expect(window.AsmodeeNet).toBeDefined();
        expect(window.AsmodeeNet.ajax).toBeDefined();
    });

    it('should be able to handle a simple ajax failure from a GET text/plain query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 404, 'contentType': 'text/plain', 'responseText': 'Not Found'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('error');

        expect(onFailure).toHaveBeenCalled();
        var onFailureArgs = onFailure.calls.mostRecent().args;
        expect(onFailureArgs.length).toBe(3);
        expect(onFailureArgs[0]).toBeObject();
        expect(onFailureArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onFailureArgs[1]).toBeString();
        expect(onFailureArgs[1]).toEqual('error');
        expect(onFailureArgs[2]).toBeString();
        expect(onFailureArgs[2]).toEqual('Not Found');

        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 403, 'contentType': 'text/plain'
        });

        expect(onComplete).toHaveBeenCalled();
        onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('error');

        expect(onFailure).toHaveBeenCalled();
        onFailureArgs = onFailure.calls.mostRecent().args;
        expect(onFailureArgs.length).toBe(3);
        expect(onFailureArgs[0]).toBeObject();
        expect(onFailureArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onFailureArgs[1]).toBeString();
        expect(onFailureArgs[1]).toEqual('error');
        expect(onFailureArgs[2]).toBeString();
        expect(onFailureArgs[2]).toEqual('');
    });

    it('should be able to handle a simple ajax success from a GET text/plain query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 200, 'contentType': 'text/plain', 'responseText': 'BOB'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('success');

        expect(onSuccess).toHaveBeenCalled();
        var onSuccessArgs = onSuccess.calls.mostRecent().args;
        expect(onSuccessArgs.length).toBe(3);
        expect(onSuccessArgs[0]).toBeString();
        expect(onSuccessArgs[0]).toEqual('BOB');
        expect(onSuccessArgs[1]).toBeString();
        expect(onSuccessArgs[1]).toEqual('success');
        expect(onSuccessArgs[2]).toBeObject();
        expect(onSuccessArgs[2]).toBeInstanceOf('FakeXMLHttpRequest');
    });

    it('should be able to handle a simple ajax failure from a GET application/json query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 416, 'contentType': 'application/json', 'responseText': '{"error": "invalid"}'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('error');

        expect(onFailure).toHaveBeenCalled();
        var onFailureArgs = onFailure.calls.mostRecent().args;
        expect(onFailureArgs.length).toBe(3);
        expect(onFailureArgs[0]).toBeObject();
        expect(onFailureArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onFailureArgs[1]).toBeString();
        expect(onFailureArgs[1]).toEqual('error');
        expect(onFailureArgs[2]).toBeObject();
        expect(onFailureArgs[2]).toEqual({error: 'invalid'});

        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 416, 'contentType': 'application/json', 'responseText': '{error: "invalid"}'
        });

        expect(onComplete).toHaveBeenCalled();
        onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('parsererror');

        expect(onFailure).toHaveBeenCalled();
        onFailureArgs = onFailure.calls.mostRecent().args;
        expect(onFailureArgs.length).toBe(3);
        expect(onFailureArgs[0]).toBeObject();
        expect(onFailureArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onFailureArgs[1]).toBeString();
        expect(onFailureArgs[1]).toEqual('parsererror');
        expect(onFailureArgs[2]).toBeString();
    });

    it('should be able to handle a simple ajax success from a GET application/json query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            success: onSuccess,
            error: onFailure,
            complete: onComplete
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('GET');

        request.respondWith({
            'status': 200, 'contentType': 'application/json', 'responseText': '{"result": ["BOB"]}'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('success');

        expect(onSuccess).toHaveBeenCalled();
        var onSuccessArgs = onSuccess.calls.mostRecent().args;
        expect(onSuccessArgs.length).toBe(3);
        expect(onSuccessArgs[0]).toBeObject();
        expect(onSuccessArgs[0]).toEqual({result: ['BOB']});
        expect(onSuccessArgs[1]).toBeString();
        expect(onSuccessArgs[1]).toEqual('success');
        expect(onSuccessArgs[2]).toBeObject();
        expect(onSuccessArgs[2]).toBeInstanceOf('FakeXMLHttpRequest');
    });

    it('should be able to handle a simple ajax success from a POST plain/text query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            type: 'POST',
            success: onSuccess,
            error: onFailure,
            complete: onComplete,
            data: 'form=BOB'
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('POST');
        expect(request.data()).toBeObject();

        request.respondWith({
            'status': 200, 'contentType': 'plain/text', 'responseText': 'OK'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('success');

        expect(onSuccess).toHaveBeenCalled();
        var onSuccessArgs = onSuccess.calls.mostRecent().args;
        expect(onSuccessArgs.length).toBe(3);
        expect(onSuccessArgs[0]).toBeString();
        expect(onSuccessArgs[0]).toEqual('OK');
        expect(onSuccessArgs[1]).toBeString();
        expect(onSuccessArgs[1]).toEqual('success');
        expect(onSuccessArgs[2]).toBeObject();
        expect(onSuccessArgs[2]).toBeInstanceOf('FakeXMLHttpRequest');
    });

    it('should be able to handle a simple ajax success from a POST application/json query', function () {
        window.AsmodeeNet.ajax('http://fake.url/tr', {
            type: 'POST',
            success: onSuccess,
            error: onFailure,
            complete: onComplete,
            data: 'bob=df'
        });

        expect(onComplete).not.toHaveBeenCalled();
        expect(onFailure).not.toHaveBeenCalled();
        expect(onSuccess).not.toHaveBeenCalled();

        request = jasmine.Ajax.requests.mostRecent();
        expect(request.url).toBe('http://fake.url/tr');
        expect(request.method).toBe('POST');
        expect(request.data()).toBeObject();

        request.respondWith({
            'status': 200, 'contentType': 'application/json', 'responseText': '{"result": "BB"}'
        });

        expect(onComplete).toHaveBeenCalled();
        var onCompleteArgs = onComplete.calls.mostRecent().args;
        expect(onCompleteArgs.length).toBe(2);
        expect(onCompleteArgs[0]).toBeObject();
        expect(onCompleteArgs[0]).toBeInstanceOf('FakeXMLHttpRequest');
        expect(onCompleteArgs[1]).toBeString();
        expect(onCompleteArgs[1]).toEqual('success');

        expect(onSuccess).toHaveBeenCalled();
        var onSuccessArgs = onSuccess.calls.mostRecent().args;
        expect(onSuccessArgs.length).toBe(3);
        expect(onSuccessArgs[0]).toBeObject();
        expect(onSuccessArgs[0]).toEqual({result: 'BB'});
        expect(onSuccessArgs[1]).toBeString();
        expect(onSuccessArgs[1]).toEqual('success');
        expect(onSuccessArgs[2]).toBeObject();
        expect(onSuccessArgs[2]).toBeInstanceOf('FakeXMLHttpRequest');
    });
});
