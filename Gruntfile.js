/*jslint node: true */
"use strict";

var mocha_options = { timeout: 15 * 60 * 1000 };

module.exports = function (grunt)
{
    grunt.initConfig(
    {
        jslint: {
            files: [ 'Gruntfile.js', 'wrap/*.js', 'test/*.js', 'bench/**/*.js' ],
            directives: {
                white: true
            }
        },

        cafemocha: {
            all: {
                src: 'test/*.js',
                options: mocha_options
            },
            browser: {
                src: ['test/_common.js', 'test/browser_interop_spec.js'],
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
                '': '-----'
            }
        },

        exec: {
            cover: {
                cmd: './node_modules/.bin/istanbul cover ./node_modules/.bin/grunt -- test',
                maxBuffer: 400 * 1024
            },

            check_cover: {
                cmd: './node_modules/.bin/istanbul check-coverage --statement 65 --branch 50 --function 50 --line 69'
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
                cmd: 'phantomjs --webdriver=4444 --webdriver-loglevel=ERROR --debug=false &'
            },

            stop_phantomjs: {
                cmd: 'pkill -g 0 phantomjs'
            },

            build: {
                cmd: './wrap/build.sh'
            },

            install: {
                cmd: 'git submodule init && git submodule update && svn checkout http://crypto-js.googlecode.com/svn/tags/3.1.2/ crypto-js && hg clone https://bitbucket.org/adrianpasternak/js-rsa-pem && ./patches/patch.sh'
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-jslint');
    grunt.loadNpmTasks('grunt-cafe-mocha');
    grunt.loadNpmTasks('grunt-apidox');
    grunt.loadNpmTasks('grunt-exec');

    grunt.registerTask('lint', 'jslint');
    grunt.registerTask('test', ['exec:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'cafemocha:all',
                                'exec:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('test-browser', ['exec:start_phantomjs',
                                'sleep:10000',
                                'usetheforce_on',
                                'cafemocha:browser',
                                'exec:stop_phantomjs',
                                'usetheforce_restore']);
    grunt.registerTask('docs', 'apidox');
    grunt.registerTask('coverage', ['exec:cover', 'exec:check_cover']);
    grunt.registerTask('coveralls', 'exec:coveralls');
    grunt.registerTask('bench', 'exec:bench');
    grunt.registerTask('bench-gfm', 'exec:bench_gfm');
    grunt.registerTask('build', 'exec:build');
    grunt.registerTask('install', 'exec:install');
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
