// Generated on 2015-08-17 using generator-angular 0.11.1
'use strict';

// var modRewrite = require('connect-modrewrite');

// # Globbing
// for performance reasons we're only matching one level down:
// 'test/spec/{,*/}*.js'
// use this if you want to recursively match all subfolders:
// 'test/spec/**/*.js'
//
// var phpport, proxyPhp, proxyStatic, PHPMiddle;
// var ISStaticPort = 9144;

module.exports = function (grunt) {
    // Load grunt tasks automatically
    require('load-grunt-tasks')(grunt);
    grunt.loadNpmTasks('grunt-rev-package');
    grunt.loadNpmTasks('grunt-contrib-coffee');
    grunt.loadNpmTasks('grunt-contrib-connect');
    grunt.loadNpmTasks('grunt-contrib-watch');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.loadNpmTasks('grunt-coffeelint');
    grunt.loadNpmTasks('gruntify-eslint');
    grunt.loadNpmTasks('grunt-karma');
    grunt.loadNpmTasks('grunt-nightwatch');
    grunt.loadNpmTasks('grunt-shell-spawn');
    grunt.loadNpmTasks('grunt-exec');

    var sorcery = require('sorcery');
    // var httpProxy = require('http-proxy');

    // var createPhpProxy = function () {
    //     proxyStatic = httpProxy.createProxyServer({
    //         host: '127.0.0.1',
    //         port: ISStaticPort,
    //         https: false,
    //         xforward: false,
    //         headers: {
    //             'x-custom-added-header': 'blob'
    //         },
    //         hideHeaders: ['x-removed-header']
    //     });
    //
    //     PHPMiddle = require('./grunt-is/PHPMiddle.js')(grunt, proxyStatic, 'http://localhost:' + ISStaticPort, ISStaticPort);
    // };
    //
    // var createProxyPhp = function (port) {
    //     phpport = port;
    //     proxyPhp = httpProxy.createProxyServer({
    //         host: '127.0.0.1',
    //         port: 9145,
    //         https: false,
    //         xforward: false,
    //         headers: {
    //             'x-by-proxy-host': 'http://localhost:' + phpport
    //         },
    //         hideHeaders: ['x-removed-header']
    //     });
    //     PHPMiddle.settings(proxyPhp, phpport, 9145);
    // };

    // Define the configuration for all the tasks
    grunt.initConfig({
        exec: {
            ls_files: {
                command: 'ls -l build/ && ls -l tests/unit/build/',
                stdout: true
            }
        },
        babel: {
            options: {
                sourceMap: true,
                presets: ['es2015']
            },
            dist: {
                files: {
                    'build/an_sso.src.cf.js': 'build/an_sso.src.cf.js',
                    // 'build/an_sso-export.src.cf.js': 'build/an_sso-export.src.cf.js',
                    'tests/unit/build/an_sso.test.cf.js': 'tests/unit/build/an_sso.test.cf.js'
                    // 'tests/unit/build/ajax.test.cf.js': 'tests/unit/build/ajax.test.cf.js',
                    // 'tests/unit/build/utils.test.cf.js': 'tests/unit/build/utils.test.cf.js'
                }
            }
        },
        connect: {
            server: {
                options: {
                    keepalive: true
                }
            },
            server_dev: {
                options: {
                    keepalive: false
                }
            },
            options: {
                base: './examples/',
                port: 8080
            },
            server_test_unit: {
                options: {
                    base: ['./tests/unit', './'],
                    port: 8081,
                    open: 'http://localhost:8081/SpecRunner.html',
                    livereload: true,
                    keepalive: false
                }
            },
            server_test_e2e: {
                options: {
                    base: ['./tests/e2e/server/'],
                    port: 8080,
                    keepalive: false
                }
            }
            // fake_is_static_server: {
            //     options: {
            //         port: ISStaticPort,
            //         hostname: '127.0.0.1',
            //         base: 'asmodeenet_platform/identity-server/public'
            //     }
            // },
            // fake_is_server: {
            //     options: {
            //         port: 8209,
            //         keepalive: false,
            //         hostname: '127.0.0.1',
            //         base: 'public',
            //         middleware: [
            //             function (req, res, next) {
            //                 return PHPMiddle.ware(req, res, next);
            //             }
            //         ]
            //     }
            // }
        },
        coffee: {
            compileWithMaps: {
                options: {
                    sourceMap: true,
                    includeSources: true,
                    join: true
                },
                files: {
                    'build/an_sso.src.cf.js': ['src/ajax.coffee', 'src/an_sso.coffee', 'src/direct.coffee'],
                    'build/an_sso-export.src.cf.js': ['src/ajax.coffee', 'src/an_sso.coffee', 'src/export.coffee']
                }
            },
            compileForTest: {
                options: {
                    join: true,
                    expand: true
                },
                files: {
                    'tests/unit/build/an_sso.test.cf.js': ['src/ajax.coffee', 'src/an_sso.coffee', 'src/direct.coffee']
                    // 'tests/unit/build/ajax.test.cf.js': ['src/ajax.coffee'],
                    // 'tests/unit/build/utils.test.cf.js': ['src/utils.coffee']
                }
            }
        },
        uglify: {
            options: {
                compress: {
                    dead_code: true,
                    unused: true
                },
                report: 'gzip',
                sourceMap: {
                    includeSources: true
                },
                sourceMapIn: 'build/an_sso.src.cf.js.map',
                preserveComments: false
            },
            my_target: {
                // options:{
                // },
                files: {
                    'build/an_sso.built.min.js': ['build/an_sso.src.cf.js']
                    // 'build/an_sso-export.built.min.js': ['build/an_sso-export.src.cf.js']
                }
            },
            built_ext: {
                files: {
                    'build/an_sso.ext.min.js': ['build/an_sso.ext.js']
                }
            }
        },
        concat: {
            ext: {
                src: ['node_modules/urijs/src/URI.js', 'node_modules/urijs/src/IPv6.js', 'node_modules/urijs/src/punycode.js', 'node_modules/urijs/src/SecondLevelDomain.js', 'ext/polyfill-addeventlistener.js', 'ext/jws-3.3.js', 'ext/crypto-1.1.js', 'ext/base64x-1.1.js', 'ext/rsa.js', 'ext/rsasign-1.2.js', 'ext/keyutil-1.0.js'],
                dest: 'build/an_sso.ext.js',
                options: {
                    sourceMap: true,
                    sourceMapStyle: 'embed'
                }
            },
            jwt: {
                src: ['node_modules/es5-shim/es5-shim.min.js', 'ext/base64-min.js', 'ext/jsbn-min.js', 'ext/json-sans-eval-min.js', 'ext/cryptojs-312-core-fix-min.js', 'ext/hmac-sha256.js', 'node_modules/store/dist/store.legacy.min.js', 'build/an_sso.ext.min.js', 'build/an_sso.built.min.js'],
                dest: 'build/an_sso.min.js',
                options: {
                    sourceMap: true
                }
            },
            exportable: {
                src: ['node_modules/es5-shim/es5-shim.min.js', 'ext/base64-min.js', 'ext/jsbn-min.js', 'ext/json-sans-eval-min.js', 'ext/cryptojs-312-core-fix-min.js', 'ext/hmac-sha256.js', 'node_modules/store/dist/store.legacy.min.js', 'build/an_sso.ext.min.js', 'build/an_sso-export.src.cf.js'],
                dest: 'build/an_sso-export.js',
                options: {
                    sourceMap: true
                }
            },
            shim: {
                src: 'node_modules/es5-shim/es5-shim.min.js',
                dest: 'dist/es5-shim.min.js'
            },
            sham: {
                src: 'node_modules/es5-shim/es5-sham.min.js',
                dest: 'dist/es5-sham.min.js'
            },
            map: {
                src: 'build/an_sso.min.js.map',
                dest: 'dist/an_sso.min.js.map'
            },
            mapext: {
                src: 'build/an_sso-export.min.js.map',
                dest: 'dist/an_sso-export.min.js.map'
            },
            cpbuild: {
                src: 'build/an_sso.min.js',
                dest: 'dist/an_sso.min.js'
            },
            cpextbuild: {
                src: 'build/an_sso-export.min.js',
                dest: 'dist/an_sso-export.min.js'
            },
            cp: {
                src: 'build/an_sso.min.js',
                dest: 'dist/an_sso.min.js.cp'
            },
            cpext: {
                src: 'build/an_sso-export.min.js',
                dest: 'dist/an_sso-export.min.js.cp'
            },
            cpback: {
                src: 'dist/an_sso.min.js.cp',
                dest: 'dist/an_sso.min.js'
            },
            cpextback: {
                src: 'dist/an_sso-export.min.js.cp',
                dest: 'dist/an_sso-export.min.js'
            }
        },
        clean: {
            build: ['dist/an_sso.min.js.cp', 'dist/an_sso-export.min.js.cp'],
            all: ['build/*.js', 'build/*.js.map', 'build/*.coffee', '!build/an_sso.min.js*']
        },
        revPackage: {
            'ana': 'dist/an_sso.min.js',
            'ana-export': 'dist/an_sso-export.min.js'
        },
        watch: {
            all: {
                files: ['src/*.coffee'],
                tasks: ['dist']
            },
            test: {
                files: ['src/*.coffee', 'tests/unit/spec/*.js', 'tests/unit/helpers/*.js'],
                tasks: ['lint', 'coffee:compileForTest', 'concat:ext'],
                options: {
                    livereload: true
                }
            }
        },
        coffeelint: {
            options: {
                configFile: 'coffeelint.json'
            },
            app: ['src/*.coffee']
        },
        eslint: {
            options: {
                configFile: '.eslintrc.js',
                expand: true
            },
            src: ['tests/unit/spec/*[sS]pec.js', 'tests/unit/helpers/*[hH]elper.js', 'tests/e2e/helpers/*.js', 'tests/e2e/spec/*.js']
        },
        concurrent: {
            options: {
                logConcurrentOutput: true
            },
            watch_test: {
                tasks: ['watch:all', 'watch:test']
            }
        },
        shell: {
            docker_and_test: {
                command: 'bash ./contrib/startTestServer.sh ' + (grunt.option('envtype') || 'local') // envtype could be local or ci
            }
            // is_server_launch: {
            //     command: 'APPLICATION_ENV=localtest php -S 127.0.0.1:9145 -t public',
            //     options: {
            //         async: true,
            //         execOptions: {
            //             cwd: './asmodeenet_platform/identity-server/'
            //         },
            //         stdout: true,
            //         stderr: true,
            //         failOnError: true
            //     }
            // }
            // ,
            // is_server_ci: {
            //     command: 'sh ./contrib/startTestServer.sh ci'
            // }
        },
        karma: {
            unit: {
                configFile: 'tests/unit/karma.conf.js',
                singleRun: true
            },
            coverage: {
                configFile: 'tests/unit/karma.conf.js',
                singleRun: true,
                reporters: ['spec', 'coverage']
            }
        },
        nightwatch: {
            options: {
                config_path: 'tests/e2e/nightwatch.conf.js'
            }
        }
    });
    grunt.registerTask('serve', ['connect:server']);

    // grunt.registerTask('createProxyE2e', '', function () {
    //     createPhpProxy();
    //     createProxyPhp(8209);
    // });
    //
    // grunt.registerTask('closeProxyE2e', '', function () {
    //     proxyStatic.close();
    //     proxyPhp.close();
    // });

    grunt.registerTask('sorcery', '', function () {
        var chain = sorcery.loadSync('build/an_sso.min.js');
        chain.apply();
        chain.writeSync();
    });

    grunt.registerTask('lint', [
        'coffeelint', 'eslint'
    ]);

    grunt.registerTask('build', [
        'lint',
        'coffee:compileWithMaps',
        // 'concat:urijs',
        'concat:ext',
        'babel',
        'uglify',
        'concat:jwt',
        'concat:exportable'
    ]);

    grunt.registerTask('dist', [
        'build',
        // 'merge-source-maps:jwt',
        // 'sorcery',
        'concat:map',
        'concat:mapext',
        'concat:cp',
        'concat:cpext',
        'concat:cpbuild',
        'concat:cpextbuild',
        'revPackage',
        'concat:cpback',
        'concat:cpextback',
        'clean:build'
    ]);

    grunt.registerTask('serve-dev', [
        'dist',
        'connect:server_dev',
        'watch:all'
    ]);

    grunt.registerTask('default', [
        'dist'
    ]);

    grunt.registerTask('test:unit', [
        'lint',
        'coffee:compileWithMaps',
        'concat:ext',
        'coffee:compileForTest',
        'concat:ext',
        'exec:ls_files',
        'babel',
        'karma:unit'
    ]);

    grunt.registerTask('test:coverage', [
        'lint',
        'coffee:compileForTest',
        'concat:ext',
        'babel',
        'karma:coverage'
    ]);

    grunt.registerTask('test:e2eRealtestByCLI', [
        'connect:server_test_e2e',
        'nightwatch:chrome'
    ]);

    grunt.registerTask('test:e2e', [
        'lint',
        'coffee:compileForTest',
        'concat:ext',
        'shell:docker_and_test'
        // 'shell:is_server_launch',
        // 'createProxyE2e',
        // 'connect:fake_is_static_server',
        // 'connect:fake_is_server',
        // 'connect:server_test_e2e',
        // 'nightwatch:phantomjs',
        // 'closeProxyE2e',
        // 'shell:is_server_launch:kill'
    ]);

    grunt.registerTask('test:server', [
        'lint',
        'coffee:compileForTest',
        'concat:ext',
        'babel',
        // 'connect:fake_is_server',
        'connect:server_test_unit',
        'watch:test'
    ]);
};
