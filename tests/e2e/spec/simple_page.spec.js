// For authoring Nightwatch tests, see
// http://nightwatchjs.org/guide#usage

module.exports = {
    'simple page test': function (browser) {
        const devServer = browser.globals.devServerURL;
        browser
            .url(devServer + '/index.html')
            .consoleLogging()
            .waitForElementVisible('#connect_bt', 5000)
            .click('#connect_bt')
            .assert.urlContains('https://account.dev.asmodee.net/main/v2/oauth/authorize?display=page&response_type=code')
            .waitForElementVisible('#inputLogin', 5000)
            .setValue('#inputLogin', 'Brice')
            .setValue('#inputPassword', 'test')
            .click('.form-signin button[name="signin"]')
            .assert.urlContains(devServer + '/#code')
            .waitForElementVisible('#disconnect_bt', 1000)
            .assert.containsText('#output', '"sub": 5')
            .assert.containsText('#output', '"nickname": "Brice"')
            .getCookies(function (r) {
                this.assert.equal(r.value[0].name, 'dow');
            })
            .click('#disconnect_bt')
            .pause(1000)
            .assert.visible('#connect_bt')
            .getCookies(function (r) {
                var t = this;
                r.value.forEach(function (c) {
                    t.assert.notEqual(c.name, 'dow');
                });
            })
            .end();
    }
    // ,
    //
    // 'simple touch test': function (browser) {
    //     const devServer = browser.globals.devServerURL;
    //     browser
    //         .url(devServer + '/index_touch.html')
    //         .consoleLogging()
    //         // .printLastResponse()
    //         .waitForElementVisible('#connect_bt', 5000)
    //         .click('#connect_bt')
    //         .assert.urlContains('http://localhost:8009/main/v2/oauth/authorize?display=page&response_type=code')
    //         .waitForElementVisible('#inputLogin', 5000)
    //         .setValue('#inputLogin', 'Brice')
    //         .setValue('#inputPassword', 'yoman1234')
    //         .click('.form-signin button[name="signin"]')
    //         .assert.urlContains(devServer + '/#code')
    //         .assert.elementPresent('#disconnect_bt')
    //         .pause(1000)
    //         .assert.containsText('#output', '"sub": 5')
    //         .assert.containsText('#output', '"nickname": "Brice"')
    //         .end();
    // }
};
