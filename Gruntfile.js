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
                cmd: "./node_modules/.bin/nyc -x Gruntfile.js -x 'test/**' ./node_modules/.bin/grunt test",
                fail: true,
                execOpts: {
                    maxBuffer: 0
                }
            },

            cover_report: {
                cmd: './node_modules/.bin/nyc report -r lcov',
                fail: true
            },

            cover_check: {
                cmd: './node_modules/.bin/nyc check-coverage --statements 40 --branches 30 --functions 30 --lines 44',
                fail: true
            },

            coveralls: {
                cmd: 'cat coverage/lcov.info | coveralls',
                fail: true
            },

            bench: {
                cmd: './node_modules/.bin/bench -c 1000,generate_key:10 -i "$(echo bench/implementations/*.js | tr " " ,)"',
                fail: true
            },

            bench_gfm: {
                cmd: './node_modules/.bin/bench -R gfm -c 1000,generate_key:10 -i "$(echo bench/implementations/*.js | tr " " ,)"',
                fail: true
            },

            start_phantomjs: {
                cmd: './node_modules/.bin/phantomjs --webdriver=4444 --webdriver-loglevel=ERROR --debug=false',
                bg: true,
                fail: true
            },

            stop_phantomjs: {
                cmd: 'pkill -g 0 phantomjs',
                fail: true
            },

            build: {
                cmd: './wrap/build.sh',
                fail: true
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
    grunt.registerTask('test', ['build',
                                'bgShell:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'mochaTest:default',
                                'bgShell:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-browser', ['build',
                                        'bgShell:start_phantomjs',
                                        'sleep:10000',
                                        'usetheforce_on',
                                        'mochaTest:browser',
                                        'bgShell:stop_phantomjs',
                                        'usetheforce_restore']);
    grunt.registerTask('test-generate-key', ['build',
                                             'mochaTest:generate_key']);
    grunt.registerTask('test-main', ['build', 'mochaTest:main']);
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['bgShell:cover',
                                    'bgShell:cover_report'/*,
                                    'bgShell:cover_check'*/]);
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
