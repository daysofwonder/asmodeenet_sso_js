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

  // Define the configuration for all the tasks
  grunt.initConfig({
        connect: {
            server: {
                options: {
                    base: './examples/',
                    port: 8080,
                    keepalive: true
                }
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
                    'build/gamifyd_sso.min.js': ['build/gamifyd_sso.built.js']
                }
            }
        },
        concat: {
            dist: {
                  src: ['build/gamifyd_sso.cf.js', 'build/utils.cf.js', 'build/ajax.cf.js', 'ext/jws-3.3.js', 'ext/crypto-1.1.js', 'ext/base64x-1.1.js', 'ext/rsa.js', 'ext/rsasign-1.2.js', 'ext/keyutil-1.0.js'],
                  dest: 'build/gamifyd_sso.built.js',
            },
            jwt: {
                src: ['ext/base64-min.js', 'ext/jsbn-min.js', 'ext/json-sans-eval-min.js', 'ext/cryptojs-312-core-fix-min.js', 'ext/hmac-sha256.js', 'build/gamifyd_sso.min.js'],
                // src: ['ext/jsrsasign-latest-all-min.js', 'build/gamifyd_sso.min.js'],
                dest: 'dist/gamifyd_sso.min.js'
            }
        },
        revPackage: {
            'gamifyd': 'dist/gamifyd_sso.min.js'
        },
        coffee: {
             compileWithMaps: {
                files: {
                    'build/gamifyd_sso.cf.js': 'src/gamifyd_sso.coffee',
                    'build/ajax.cf.js': 'src/ajax.coffee',
                    'build/utils.cf.js': 'src/utils.coffee'
                 }
             }
        }
  });
  grunt.registerTask('serve', ['connect']);
  
  grunt.registerTask('build', [
    'coffee',
    'concat:dist',
    'uglify',
    'concat:jwt',
    'revPackage'
  ]);

  grunt.registerTask('default', [
    'build'
  ]);
};
