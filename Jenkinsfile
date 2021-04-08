def output_files = ['staked-relayer', 'oracle', 'vault', 'faucet', 'testdata-gen']

pipeline {
    agent none
    environment {
        RUSTC_WRAPPER = '/usr/local/bin/sccache'
        CI = 'true'
        GITHUB_TOKEN = credentials('ns212-github-token')
        DISCORD_WEBHOOK_URL = credentials('discord_webhook_url')
    }

    options {
        timestamps()
        ansiColor('xterm')
    }

    stages {
        stage('Test') {
            agent {
                kubernetes {
                    yamlFile '.deploy/rust-builder-pod.yaml'
                }
            }
            environment {
                BITCOIN_RPC_URL  = "http://localhost:18443"
                BITCOIN_RPC_USER = "rpcuser"
                BITCOIN_RPC_PASS = "rpcpassword"
            }
            steps {
                container('rust') {
                    sh 'rustc --version'
                    sh 'SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache'
                    sh '/usr/local/bin/sccache -s'

                    sh 'cargo fmt -- --check'
                    sh 'cargo check --workspace --release'
                    sh 'cargo test --workspace --release'

                    sh 'cargo test --manifest-path bitcoin/Cargo.toml --test "*" --features uses-bitcoind -- --test-threads=1'

                    sh '/usr/local/bin/sccache -s'
                }
            }
        }
        stage('Build binaries') {
            matrix {
                agent {
                    kubernetes {
                        yamlFile '.deploy/rust-builder-pod.yaml'
                    }
                }
                axes {
                    axis {
                        name 'PLATFORM'
                        values 'x86_64-unknown-linux-gnu', 'x86_64-pc-windows-gnu'
                    }
                }
                stages {
                    stage('build') {
                        steps {
                            container('rust') {
                                sh '''
                                    rustc --version
                                    SCCACHE_START_SERVER=1 SCCACHE_IDLE_TIMEOUT=0 /usr/local/bin/sccache
                                    /usr/local/bin/sccache -s
                                    cargo fmt -- --check
                                    cargo check --workspace --release --target $PLATFORM
                                    cargo build --workspace --release --target $PLATFORM
                                    ls -l target/$PLATFORM/release/
                                '''
                                script {
                                    if (env.PLATFORM.contains('windows')) {
                                        def binaries = output_files.collect { "target/${env.PLATFORM}/release/${it}.exe" }.join(',')
                                        archiveArtifacts binaries
                                    } else {
                                        def binaries = output_files.collect { "target/${env.PLATFORM}/release/$it" }.join(',')
                                        archiveArtifacts binaries
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }


        stage('Build docker images') {
            when {
                anyOf {
                    branch 'master'
                    tag '*'
                }
            }
            agent {
                kubernetes {
                    yamlFile '.deploy/rust-builder-pod.yaml'
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
                sh '''
                    wget -q -O - https://github.com/cli/cli/releases/download/v1.6.2/gh_1.6.2_linux_amd64.tar.gz | tar xzf -
                    ./gh_1.6.2_linux_amd64/bin/gh auth status
                    wget -q -O - https://github.com/git-chglog/git-chglog/releases/download/v0.10.0/git-chglog_0.10.0_linux_amd64.tar.gz | tar xzf -
                    #export PREV_TAG=$(git describe --abbrev=0 --tags `git rev-list --tags --skip=1 --max-count=1`)
                    #export TAG_NAME=$(git describe --abbrev=0 --tags `git rev-list --tags --skip=0 --max-count=1`)
                    ./git-chglog --output CHANGELOG.md $TAG_NAME
                    ./gh_1.6.2_linux_amd64/bin/gh release -R $GIT_URL create $TAG_NAME --title $TAG_NAME -F CHANGELOG.md -d
                '''
            }
        }
    }
    post {
        always {
            script {
                env.GIT_COMMIT_MSG = sh (script: 'git log -1 --pretty=%B ${GIT_COMMIT}', returnStdout: true).trim()
                env.GIT_AUTHOR = sh (script: 'git log -1 --pretty=%cn ${GIT_COMMIT}', returnStdout: true).trim()

                discordSend(
                    title: "${env.JOB_NAME} Finished ${currentBuild.currentResult}",
                    description:  "```${env.GIT_COMMIT_MSG}```",
                    image: '',
                    link: "$env.RUN_DISPLAY_URL",
                    successful: currentBuild.resultIsBetterOrEqualTo("SUCCESS"),
                    thumbnail: 'https://wiki.jenkins-ci.org/download/attachments/2916393/headshot.png',
                    result: currentBuild.currentResult,
                    webhookURL: DISCORD_WEBHOOK_URL
                )
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
