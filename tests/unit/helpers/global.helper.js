beforeEach(function () {
    jasmine.addMatchers({
        toBeInstanceOf: function () {
            return {
                compare: function (actual, expected) {
                    return {
                        pass: typeof actual === 'object' && (typeof expected === 'string' ? actual.constructor.name === expected : actual instanceof expected)
                    };
                }
            };
        }
    });
});
