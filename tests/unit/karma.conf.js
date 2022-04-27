// karma.conf.js
module.exports = function (config) {
    config.set({
        browsers: ['PhantomJS'],
        // browsers: ['PhantomJS'],
        // frameworks: ['mocha', 'sinon-chai', 'phantomjs-shim'],
        frameworks: ['jasmine-ajax', 'jasmine', 'jasmine-matchers'], //, 'phantomjs-shim'],
        reporters: ['spec', 'junit'],

        customLaunchers: {
            'PhantomJS_debug': {
                base: 'PhantomJS',
                debug: true
            }
        },
        singleRun: false,

        files: [
            // dependencies
            '/lib/.grunt/grunt-contrib-jasmine/json2.js',
            'bootstrap.js', 'lib/ext/cryptojs-312-core-fix-min.js', 'lib/build/an_sso.ext.js', 'lib/node_modules/es5-shim/es5-shim.min.js', 'lib/ext/base64-min.js', 'lib/ext/jsbn-min.js', 'lib/ext/json-sans-eval-min.js', 'lib/ext/hmac-sha256.js', 'lib/node_modules/store/dist/store.legacy.min.js',

            // src
            'build/an_sso.test.cf.js',
            // 'build/ajax.test.cf.js',

            // helpers
            'helpers/*helper.js',

            // specs
            'spec/*spec.js'
        ],

        junitReporter: {
            outputDir: 'junit'
        },
        preprocessors: {
            'build/*.test.cf.js': ['coverage']
        },
        coverageReporter: {
            dir: './../../',
            reporters: [
                // { type: 'lcov', subdir: '.' },
                { type: 'text-summary' },
                { type: 'clover', subdir: 'reports', file: 'coverage.xml' },
                { type: 'lcov', subdir: 'coverage' }
            ]
        },
        htmlReporter: {
            outputDir: 'coverage_html', // where to put the reports
            focusOnFailures: true, // reports show failures on start
            namedFiles: false, // name files instead of creating sub-directories
            reportName: 'report-summary-coverage' // report summary filename; browser info by default
        }
    });
};
