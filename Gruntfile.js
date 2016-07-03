/*jslint node: true */
"use strict";

var mocha_options = {
    timeout: 15 * 60 * 1000,
    bail: true
};

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        jshint: {
            src: [ 'Gruntfile.js', 'wrap/*.js', 'test/*.js', 'bench/**/*.js' ]
        },

        mochaTest: {
            default: {
                src: 'test/*.js',
                options: mocha_options
            },
            browser: {
                src: ['test/_common.js', 'test/browser_interop_spec.js'],
                options: mocha_options
            },
            generate_key: {
                src: ['test/_common.js', 'test/generate_key_spec.js'],
                options: mocha_options
            },
            main: {
                src: ['test/*.js', '!test/browser_interop_spec.js', '!test/generate_key_spec.js'],
                options: mocha_options
            }
        },

        apidox: {
            input: 'wrap/docs.js',
            output: 'README.md',
            fullSourceDescription: true,
            inputTitle: false,
            extraHeadingLevels: 1,
            sections: {
                createPrivateKey: '## Key functions',
                JWS: '\n## JSON Web Signature functions',
                JWT: '\n## JSON Web Token functions',
                X509: '\n## Certificate functions',
                '': '-----'
            }
        },

        bgShell: {
            cover: {
                cmd: './node_modules/.bin/istanbul cover ./node_modules/.bin/grunt -- test',
                execOpts: {
                    maxBuffer: 1024 * 1024
                }
            },

            check_cover: {
                cmd: './node_modules/.bin/istanbul check-coverage --statement 40 --branch 30 --function 30 --line 44'
            },

            coveralls: {
                cmd: 'cat coverage/lcov.info | coveralls'
            },

            bench: {
                cmd: './node_modules/.bin/bench -c 1000,generate_key:10 -i "$(echo bench/implementations/*.js | tr " " ,)"'
            },

            bench_gfm: {
                cmd: './node_modules/.bin/bench -R gfm -c 1000,generate_key:10 -i "$(echo bench/implementations/*.js | tr " " ,)"'
            },

            start_phantomjs: {
                cmd: './node_modules/.bin/phantomjs --webdriver=4444 --webdriver-loglevel=ERROR --debug=false',
                bg: true
            },

            stop_phantomjs: {
                cmd: 'pkill -g 0 phantomjs'
            },

            build: {
                cmd: './wrap/build.sh'
            },

            install: {
                cmd: 'git submodule init && ' +
                     'git submodule update && ' +
                     'hg clone https://bitbucket.org/adrianpasternak/js-rsa-pem',
                fail: true
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-mocha-test');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-bg-shell');

    grunt.registerTask('lint', 'jshint');
    grunt.registerTask('test', ['bgShell:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'mochaTest:default',
                                'bgShell:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-browser', ['bgShell:start_phantomjs',
                                        'sleep:10000',
                                        'usetheforce_on',
                                        'mochaTest:browser',
                                        'bgShell:stop_phantomjs',
                                        'usetheforce_restore']);
    grunt.registerTask('test-generate-key', 'mochaTest:generate_key');
    grunt.registerTask('test-main', 'mochaTest:main');
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['bgShell:cover'/*, 'exec:check_cover'*/]);
    grunt.registerTask('coveralls', 'bgShell:coveralls');
    grunt.registerTask('bench', 'bgShell:bench');
    grunt.registerTask('bench-gfm', 'bgShell:bench_gfm');
    grunt.registerTask('build', 'bgShell:build');
    grunt.registerTask('install', 'bgShell:install');
    grunt.registerTask('default', ['lint', 'test']);

    grunt.registerTask('sleep', function (ms)
    {
        setTimeout(this.async(), ms);
    });

    // http://stackoverflow.com/questions/16612495/continue-certain-tasks-in-grunt-even-if-one-fails

    grunt.registerTask('usetheforce_on',
                       'force the force option on if needed',
    function()
    {
        if (!grunt.option('force'))
        {
            grunt.config.set('usetheforce_set', true);
            grunt.option('force', true);
        }
    });

    grunt.registerTask('usetheforce_restore',
                       'turn force option off if we have previously set it', 
    function()
    {
        if (grunt.config.get('usetheforce_set'))
        {
            grunt.option('force', false);

            if (grunt.fail.warncount > 0)
            {
                grunt.fail.warn('previous warnings detected');
            }
        }
    });
};
