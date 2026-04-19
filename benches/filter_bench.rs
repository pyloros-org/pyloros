use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pyloros::config::Rule;
use pyloros::filter::{FilterEngine, RequestInfo};

/// Build a realistic set of ~120 rules mixing exact hosts, wildcards, git rules, and websockets.
fn build_rules() -> Vec<Rule> {
    let mut rules = Vec::new();

    // --- Exact host + path rules (package registries, APIs, CDNs) ---
    let exact_urls = [
        "https://registry.npmjs.org/*",
        "https://registry.yarnpkg.com/*",
        "https://pypi.org/*",
        "https://files.pythonhosted.org/*",
        "https://rubygems.org/*",
        "https://api.rubygems.org/*",
        "https://crates.io/*",
        "https://static.crates.io/*",
        "https://index.crates.io/*",
        "https://dl.google.com/*",
        "https://storage.googleapis.com/*",
        "https://maven.google.com/*",
        "https://repo1.maven.org/*",
        "https://jcenter.bintray.com/*",
        "https://plugins.gradle.org/*",
        "https://services.gradle.org/*",
        "https://downloads.gradle-dn.com/*",
        "https://cdn.jsdelivr.net/*",
        "https://unpkg.com/*",
        "https://esm.sh/*",
        "https://deno.land/*",
        "https://api.nuget.org/*",
        "https://www.nuget.org/*",
        "https://hub.docker.com/*",
        "https://registry-1.docker.io/*",
        "https://auth.docker.io/*",
        "https://production.cloudflare.docker.com/*",
        "https://ghcr.io/*",
        "https://pkg.go.dev/*",
        "https://proxy.golang.org/*",
        "https://sum.golang.org/*",
        "https://objects.githubusercontent.com/*",
        "https://raw.githubusercontent.com/*",
        "https://api.github.com/*",
        "https://github.com/*",
        "https://gitlab.com/*",
        "https://bitbucket.org/*",
    ];
    for url in exact_urls {
        rules.push(Rule {
            method: Some("*".into()),
            url: url.into(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- GET-only rules (read-only APIs, status pages) ---
    let get_only_urls = [
        "https://status.github.com/*",
        "https://www.githubstatus.com/*",
        "https://api.openai.com/v1/models",
        "https://api.anthropic.com/v1/messages",
        "https://huggingface.co/api/*",
        "https://cdn.huggingface.co/*",
        "https://ifconfig.me/*",
        "https://checkip.amazonaws.com/*",
        "https://api.ipify.org/*",
        "https://httpbin.org/get",
        "https://jsonplaceholder.typicode.com/*",
        "https://catfact.ninja/*",
    ];
    for url in get_only_urls {
        rules.push(Rule {
            method: Some("GET".into()),
            url: url.into(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- Wildcard subdomain rules (cloud providers, SaaS) ---
    let wildcard_host_urls = [
        "https://*.amazonaws.com/*",
        "https://*.s3.amazonaws.com/*",
        "https://*.execute-api.amazonaws.com/*",
        "https://*.cloudfront.net/*",
        "https://*.azurewebsites.net/*",
        "https://*.blob.core.windows.net/*",
        "https://*.azure-api.net/*",
        "https://*.vault.azure.net/*",
        "https://*.googleapis.com/*",
        "https://*.run.app/*",
        "https://*.cloudfunctions.net/*",
        "https://*.firebaseio.com/*",
        "https://*.appspot.com/*",
        "https://*.vercel.app/*",
        "https://*.netlify.app/*",
        "https://*.herokuapp.com/*",
        "https://*.fly.dev/*",
        "https://*.railway.app/*",
        "https://*.render.com/*",
        "https://*.supabase.co/*",
        "https://*.sentry.io/*",
        "https://*.datadoghq.com/*",
        "https://*.pagerduty.com/*",
        "https://*.launchdarkly.com/*",
        "https://*.split.io/*",
        "https://*.segment.io/*",
        "https://*.segment.com/*",
        "https://*.stripe.com/*",
        "https://*.twilio.com/*",
        "https://*.sendgrid.net/*",
    ];
    for url in wildcard_host_urls {
        rules.push(Rule {
            method: Some("*".into()),
            url: url.into(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- POST-only rules (webhooks, APIs) ---
    let post_urls = [
        "https://hooks.slack.com/services/*",
        "https://discord.com/api/webhooks/*",
        "https://api.telegram.org/*",
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "https://api.cohere.ai/v1/*",
        "https://generativelanguage.googleapis.com/*",
        "https://api.replicate.com/v1/*",
    ];
    for url in post_urls {
        rules.push(Rule {
            method: Some("POST".into()),
            url: url.into(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- Git rules ---
    let git_repos = [
        "https://github.com/org/repo1.git/*",
        "https://github.com/org/repo2.git/*",
        "https://github.com/org/repo3.git/*",
        "https://github.com/org/monorepo.git/*",
        "https://gitlab.com/team/project.git/*",
    ];
    for url in git_repos {
        rules.push(Rule {
            method: None,
            url: url.into(),
            websocket: false,
            git: Some("fetch".into()),
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }
    // Push with branch restrictions
    for url in &git_repos[..3] {
        rules.push(Rule {
            method: None,
            url: url.to_string(),
            websocket: false,
            git: Some("push".into()),
            branches: Some(vec![
                "main".into(),
                "release/*".into(),
                "!release/frozen".into(),
            ]),
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- WebSocket rules ---
    let ws_urls = [
        "wss://stream.example.com/*",
        "wss://realtime.example.com/events",
        "wss://ws.bitstamp.net/*",
        "wss://stream.binance.com/*",
    ];
    for url in ws_urls {
        rules.push(Rule {
            method: Some("GET".into()),
            url: url.into(),
            websocket: true,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    // --- A few more specific API endpoint rules to reach ~120 ---
    let specific_urls = [
        "https://api.stripe.com/v1/charges",
        "https://api.stripe.com/v1/customers",
        "https://api.stripe.com/v1/subscriptions",
        "https://api.twilio.com/2010-04-01/*",
        "https://api.mailgun.net/v3/*",
        "https://api.postmarkapp.com/*",
        "https://oauth2.googleapis.com/token",
        "https://login.microsoftonline.com/*/oauth2/v2.0/token",
        "https://accounts.google.com/*",
        "https://www.googleapis.com/oauth2/*",
    ];
    for url in specific_urls {
        rules.push(Rule {
            method: Some("POST".into()),
            url: url.into(),
            websocket: false,
            git: None,
            branches: None,
            allow_redirects: Vec::new(),
            log_body: false,
        });
    }

    rules
}

fn bench_filter_check(c: &mut Criterion) {
    let rules = build_rules();
    let engine = FilterEngine::new(rules).expect("failed to build filter engine");
    let rule_count = engine.rule_count();

    let mut group = c.benchmark_group(format!("filter_check_{rule_count}_rules"));

    // Best case: matches the very first rule
    group.bench_function("match_first_rule", |b| {
        let req = RequestInfo::http("GET", "https", "registry.npmjs.org", None, "/lodash", None);
        b.iter(|| engine.check(black_box(&req)));
    });

    // Typical case: matches a rule in the middle (wildcard subdomain)
    group.bench_function("match_middle_wildcard", |b| {
        let req = RequestInfo::http(
            "GET",
            "https",
            "my-bucket.s3.amazonaws.com",
            None,
            "/some/object.tar.gz",
            None,
        );
        b.iter(|| engine.check(black_box(&req)));
    });

    // Worst case among matches: matches one of the last rules
    group.bench_function("match_last_rule", |b| {
        let req = RequestInfo::http(
            "POST",
            "https",
            "www.googleapis.com",
            None,
            "/oauth2/token",
            None,
        );
        b.iter(|| engine.check(black_box(&req)));
    });

    // Absolute worst case: no rule matches (full scan)
    group.bench_function("no_match", |b| {
        let req = RequestInfo::http(
            "DELETE",
            "https",
            "evil.example.com",
            None,
            "/exfiltrate",
            None,
        );
        b.iter(|| engine.check(black_box(&req)));
    });

    // WebSocket match (near the end of the rule list)
    group.bench_function("match_websocket", |b| {
        let req = RequestInfo::websocket("https", "stream.binance.com", None, "/ws/btcusdt", None);
        b.iter(|| engine.check(black_box(&req)));
    });

    group.finish();
}

criterion_group!(benches, bench_filter_check);
criterion_main!(benches);
