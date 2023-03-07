use cargo_lock::Lockfile;

fn get_unpatched_crate(org: &str, repo: &str) -> Vec<String> {
    let lockfile = Lockfile::load("<edit-this-to-some-path>/Cargo.lock").unwrap();
    let repo_path = org.to_owned() + repo;
    lockfile.packages.into_iter().filter_map(|package| {
        let source = package.source?;
        if source.is_git() {
            if source.url().path().contains(&repo_path) {
                return Some(package.name.as_str().to_string())
            }
        }
        None
    }).collect()
}

fn print_unpatched_repos(org: &str, repo: &str) {
    let repos = get_unpatched_crate(org, repo);
    if repos.len() > 0 {
        println!("Unpatched {repo} dependencies:");
        for repo in repos {
            println!("{repo}");
        }
        println!("");
        println!("");
    }
}

fn main() {
    for repo in ["substrate", "polkadot", "cumulus"] {
        print_unpatched_repos("paritytech/", repo);
    }
    print_unpatched_repos("open-web3-stack/", "open-runtime-module-library");
}
