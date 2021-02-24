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
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Test') {
            steps {
                container('rust') {
                    sh 'rustc --version'
                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo fmt -- --check'
                    sh 'cargo check --workspace --release'
                    sh 'cargo test --workspace --release'

                    sh '/usr/local/bin/sccache -s'
                }
            }
        }

        stage('Build binaries') {
            steps {
                container('rust') {
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

        stage('Create GitHub release') {
            when {
                anyOf {
                    branch 'github'
                    tag '*'
                }
            }
            steps {
                sh 'wget -O - https://github.com/cli/cli/releases/download/v1.6.2/gh_1.6.2_linux_amd64.tar.gz | tar xzf - && mv ./gh_1.6.2_linux_amd64/bin/gh /usr/local/bin'
                sh 'gh auth status'
                sh 'wget -O - https://github.com/git-chglog/git-chglog/releases/download/v0.10.0/git-chglog_0.10.0_linux_amd64.tar.gz | tar xzf -'
                sh './git-chglog --output CHANGELOG.md'
                sh 'gh release -R $GIT_URL create $TAG_NAME --title $TAG_NAME -F CHANGELOG.md -d ' + output_files.collect { "target/release/$it" }.join(' ')
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
