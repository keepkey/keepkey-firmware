pipeline {
    agent any
    stages {
        stage('Debug Firmware') {
            steps {
                githubNotify status:"PENDING", description:"Debug Build"
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
                    githubNotify status:"FAILURE", description:"Debug Build Failed"
                }
            }
        }
        stage('Release Firmware') {
            steps {
                githubNotify status:"PENDING", description:"Release Build"
                ansiColor('xterm') {
                    sh '''
                        rm -rf bin
                        ./scripts/build/docker/device/release.sh
                        echo "Bootstrap Size, Bootloader Size (KeepKey), Firmware Size (KeepKey), Firmware Size (MFR), Variant Size (KeepKey), Variant Size (SALT)" >> bin/binsize.csv
                        echo "$(du -b bin/bootstrap.bin | cut -f1), $(du -b bin/bootloader.bin | cut -f1), $(du -b bin/firmware.keepkey.bin | cut -f1), $(du -b bin/firmware.mfr.bin | cut -f1), $(du -b bin/variant.keepkey.bin | cut -f1), $(du -b bin/variant.salt.bin | cut -f1)" >> bin/binsize.csv
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
                    githubNotify status:"FAILURE", description:"Release Build Failed"
                }
            }
        }
        stage('Debug Emulator + Unittests') {
            steps {
                githubNotify status:"PENDING", description:"Emulator Build"
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
                    githubNotify status:"FAILURE", description:"Emulator Build Failed"
                }
            }
        }
        stage('Post') {
            steps { sh '''echo "Success!"''' }
            post {
                always {
                    githubNotify status:"SUCCESS", description:"Build Success!"
                }
            }
        }
    }
}
