def output_files = ['staked-relayer', 'oracle', 'vault', 'faucet', 'testdata-gen']

pipeline {
    agent {
        kubernetes {
            yamlFile '.deploy/rust-builder-pod.yaml'
        }
    }
    environment {
        RUSTC_WRAPPER = '/usr/local/bin/sccache'
    }

    options {
        gitLabConnection 'Gitlab-Interlay'
        gitlabBuilds(builds: ['test', 'build'])
    }

    stages {
        stage('Test') {
            steps {
                container('rust') {
                    updateGitlabCommitStatus name: 'test', state: 'running'

                    sh 'rustc --version'
                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo fmt -- --check'
                    sh 'cargo check --workspace --release'
                    sh 'cargo test --workspace --release'

                    sh '/usr/local/bin/sccache -s'
                }
            }
            post {
                success {
                    updateGitlabCommitStatus name: 'test', state: 'success'
                }
                failure {
                    updateGitlabCommitStatus name: 'test', state: 'failed'
                }
                unstable {
                    updateGitlabCommitStatus name: 'test', state: 'failed'
                }
                aborted {
                    updateGitlabCommitStatus name: 'test', state: 'canceled'
                }
            }
        }

        stage('Build binaries') {
            steps {
                container('rust') {
                    updateGitlabCommitStatus name: 'build-parachain', state: 'running'

                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo build --workspace --release'

                    script {
                        def binaries = output_files.collect { "target/release/$it" }.join(',')
                        archiveArtifacts binaries

                        for (bin in output_files) {
                            stash(name: bin, includes: ".deploy/Dockerfile, target/release/${bin}")
                        }
                    }

                    sh '/usr/local/bin/sccache -s'
                }
            }
            post {
                success {
                    updateGitlabCommitStatus name: 'build', state: 'success'
                }
                failure {
                    updateGitlabCommitStatus name: 'build', state: 'failed'
                }
                unstable {
                    updateGitlabCommitStatus name: 'build', state: 'failed'
                }
                aborted {
                    updateGitlabCommitStatus name: 'build', state: 'canceled'
                }
            }
        }

        stage('Build docker images') {
            when {
                anyOf {
                    branch 'master'
                    branch 'dev'
                    branch 'jenkins'
                    tag '*'
                }
            }
            environment {
                PATH        = "/busybox:$PATH"
                REGISTRY    = 'registry.gitlab.com'
                REPOSITORY  = 'interlay/polkabtc-clients'
            }
            steps {
                script {
                    for (bin in output_files) {
                        withEnv(["IMAGE=${bin}"]) {
                            container(name: 'kaniko', shell: '/busybox/sh') {
                                dir('unstash') {
                                    unstash(bin)
                                    runKaniko()
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

def runKaniko() {
    sh '''#!/busybox/sh
    set -x
    GIT_BRANCH_SLUG=$(echo $GIT_BRANCH | sed -e 's/\\//-/g')
    /kaniko/executor -f `pwd`/.deploy/Dockerfile -c `pwd` --build-arg BINARY=${IMAGE} \
        --destination=${REGISTRY}/${REPOSITORY}/${IMAGE}:${GIT_BRANCH_SLUG} \
        --destination=${REGISTRY}/${REPOSITORY}/${IMAGE}:${GIT_BRANCH_SLUG}-${GIT_COMMIT:0:6}
    '''
}
