pipeline {
    agent any
    stages {
        stage('Debug Firmware') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        rm -rf bin
                        ./scripts/build/docker/device/debug.sh
                        tar cjvf debug.tar.bz2 bin/*'''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'debug.tar.bz2', fingerprint: true
                }
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Release Firmware') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        rm -rf bin
                        ./scripts/build/docker/device/release.sh
                        echo "Bootstrap Size, Bootloader Size (KeepKey), Bootloader Size (SALT), Firmware Size (KeepKey), Firmware Size (SALT)" >> bin/binsize.csv
                        echo "$(du -b bin/bootstrap.bin | cut -f1), $(du -b bin/bootloader.keepkey.bin | cut -f1), $(du -b bin/bootloader.salt.bin | cut -f1), $(du -b bin/firmware.keepkey.bin | cut -f1), $(du -b bin/firmware.keepkey.bin | cut -f1)" >> bin/binsize.csv
                        tar cjvf release.tar.bz2 bin/*'''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'release.tar.bz2,bin/*.bin,bin/*.csv', fingerprint: true
                    plot csvFileName: 'binsize.csv',
                            csvSeries: [[
                                                file: 'bin/binsize.csv',
                                                exclusionValues: '',
                                                displayTableFlag: true,
                                                inclusionFlag: 'OFF',
                                                url: '']],
                            group: 'Binary Sizes',
                            title: 'Binary Sizes',
                            style: 'line',
                            exclZero: false,
                            keepRecords: false,
                            logarithmic: false,
                            numBuilds: '',
                            useDescr: true,
                            yaxis: 'Bytes',
                            yaxisMaximum: '',
                            yaxisMinimum: ''
                }
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Debug Emulator + Unittests') {
            steps {
                ansiColor('xterm') {
                    sh '''
                        ./scripts/build/docker/emulator/debug.sh'''
                }
                step([$class: 'XUnitPublisher',
                        thresholds: [[$class: 'FailedThreshold', unstableThreshold: '1']],
                        tools: [[$class: 'GoogleTestType',
                                   pattern: 'build/unittests/*.xml',
                                   skipNoTestFiles: false,
                                   failIfNotNew: false,
                                   deleteOutputFiles: false,
                                   stopProcessingIfError: false]]])
            }
            post {
                failure {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Failed 🚨")
                        }
                    }
                }
            }
        }
        stage('Post') {
            steps { sh '''echo "Success!"''' }
            post {
                always {
                    script {
                        if (env.CHANGE_ID) {
                            pullRequest.comment("Build ${env.BUILD_ID} - Success! 😍🦊")
                        }
                    }
                }
            }
        }
    }
}
