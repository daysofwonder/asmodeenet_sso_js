// Generated on 2015-08-17 using generator-angular 0.11.1
'use strict';

// var modRewrite = require('connect-modrewrite');

// # Globbing
// for performance reasons we're only matching one level down:
// 'test/spec/{,*/}*.js'
// use this if you want to recursively match all subfolders:
// 'test/spec/**/*.js'

module.exports = function (grunt) {

  // Load grunt tasks automatically
  require('load-grunt-tasks')(grunt);
  grunt.loadNpmTasks('grunt-rev-package');
  grunt.loadNpmTasks('grunt-contrib-coffee');
  grunt.loadNpmTasks('grunt-contrib-connect');
  grunt.loadNpmTasks('grunt-contrib-watch');

  // Define the configuration for all the tasks
  grunt.initConfig({
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
                port: 8080,
            }
        },
        uglify: {
            options: {
                compress: {
                    dead_code: true,
                    unused: true,
                },
                report: 'gzip',
                preserveComments: false
            },
            my_target: {
                files: {
                    'build/an_sso.min.js': ['build/an_sso.built.js']
                }
            }
        },
        concat: {
            dist: {
                  src: ['ext/polyfill-addeventlistener.js', 'build/an_sso.cf.js', 'build/utils.cf.js', 'build/ajax.cf.js', 'ext/jws-3.3.js', 'ext/crypto-1.1.js', 'ext/base64x-1.1.js', 'ext/rsa.js', 'ext/rsasign-1.2.js', 'ext/keyutil-1.0.js'],
                  dest: 'build/an_sso.built.js',
            },
            jwt: {
                src: ['node_modules/es5-shim/es5-shim.min.js', 'ext/base64-min.js', 'ext/jsbn-min.js', 'ext/json-sans-eval-min.js', 'ext/cryptojs-312-core-fix-min.js', 'ext/hmac-sha256.js', 'node_modules/store/dist/store.legacy.min.js', 'build/an_sso.min.js'],
                // src: ['ext/jsrsasign-latest-all-min.js', 'build/an_sso.min.js'],
                dest: 'dist/an_sso.min.js'
            },
            shim: {
                src: 'node_modules/es5-shim/es5-shim.min.js',
                dest: 'dist/es5-shim.min.js'
            },
            sham: {
                src: 'node_modules/es5-shim/es5-sham.min.js',
                dest: 'dist/es5-sham.min.js'
            }
        },
        revPackage: {
            'ana': 'dist/an_sso.min.js'
        },
        coffee: {
             compileWithMaps: {
                files: {
                    'build/an_sso.cf.js': 'src/an_sso.coffee',
                    'build/ajax.cf.js': 'src/ajax.coffee',
                    'build/utils.cf.js': 'src/utils.coffee'
                 }
             }
        },
        watch: {
          all: {
            files: ['src/*.coffee'],
            tasks: ['build']
          }
        }
  });
  grunt.registerTask('serve', ['connect:server']);

  grunt.registerTask('build', [
    'coffee',
    'concat:dist',
    'uglify',
    'concat:jwt',
    'revPackage'
  ]);

  grunt.registerTask('serve-dev', [
      'build',
      'connect:server_dev',
      'watch'
  ]);

  grunt.registerTask('default', [
    'build'
  ]);
};
