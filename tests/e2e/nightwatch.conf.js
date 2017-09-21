// var config = require('../../config');

// http://nightwatchjs.org/gettingstarted#settings-file
var chromefinder = require('chrome-launcher/chrome-finder');
console.log(chromefinder[process.platform]()[0]);
module.exports = {
    src_folders: ['spec'],
    output_folder: 'reports',
    custom_commands_path: 'helpers',
    // custom_assertions_path: 'asserts',

    selenium: {
        start_process: true,
        server_path: require('selenium-server').path,
        log_path: '',
        host: '127.0.0.1',
        port: 4445,
        cli_args: {
            'phantomjs.binary.path': require('phantomjs-prebuilt').path
        }
    },

    test_settings: {
        default: {
            selenium_port: 4445,
            selenium_host: '127.0.0.1',
            silent: true,
            log_path: '',
            globals: {
                devServerURL: 'http://localhost:8080'
            }
        },

        phantomjs: {
            desiredCapabilities: {
                browserName: 'phantomjs',
                javascriptEnabled: true,
                acceptSslCerts: true,
                'phantomjs.binary.path': require('phantomjs-prebuilt').path,
                'phantomjs.cli.args': ['--ignore-ssl-errors=true', '--webdriver=8080', '--webdriver-selenium-grid-hub=http://127.0.0.1:4445']
            }
        },

        chrome: {
            desiredCapabilities: {
                browserName: 'chrome',
                // 'webdriver.chrome.driver': require('chromedriver').path,
                javascriptEnabled: true,
                acceptSslCerts: true,
                chromeOptions: {
                    args: ['--headless', '--disable-gpu'],
                    binary: chromefinder[process.platform]()[0]
                }
            }
        },

        firefox: {
            desiredCapabilities: {
                browserName: 'firefox',
                javascriptEnabled: true,
                acceptSslCerts: true
            }
        }
    }
};
