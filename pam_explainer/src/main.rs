use std::env;

use enum_iterator::all;
use log::info;
use pam_explainer::*;

fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "INFO");
    }
    #[cfg(feature = "cli")]
    pretty_env_logger::init();

    let file = match load_file() {
        Ok(val) => val,
        Err(_) => return,
    };

    let rules = rules_from_vec_string(file);

    for facility in all::<Facility>().collect::<Vec<_>>() {
        let f_rules = rules.clone();
        // filter out the ones we want
        let mut rules: Vec<Rule> = f_rules
            .into_iter()
            .filter_map(|r| {
                if r.facility == facility {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        // sort them just to be sure
        rules.sort_by_key(|item| (item.rule_order));
        let mut ruleset = RuleSet::new(&facility, rules);
        let ruleset_result = ruleset.run_rules();
        info!(
            "{:?} -> {:?} (Ran {} rules)",
            facility, ruleset_result, ruleset.rules_run
        );
    }
}
