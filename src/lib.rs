//! based on <https://www.linux.com/news/understanding-pam/> which is probably wrong in places

use dialoguer::Confirm;
use enum_iterator::Sequence;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize, Serializer};
use std::convert::TryFrom;
use std::env;
use std::io::{Error, ErrorKind};

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq, Sequence)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum Facility {
    /// The ‘auth’ facility is responsible for checking that the user is who they say. The modules that can be listed in this area generally support prompting for a password.
    Auth,
    /// This area is responsible for a wide array of possible account verification functionality. There are many modules available for this facility. Constraints to the use of a service based on checking group membership, time of day, whether a user account is local or remote, etc., are generally enforced by modules which support this facility.
    Account,
    /// The modules in this area are responsible for any functionality needed in the course of updating passwords for a given service. Most of the time, this section is pretty ‘ho-hum’, simply calling a module that will prompt for a current password, and, assuming that’s successful, prompt you for a new one. Other modules could be added to perform password complexity or dictionary checking as well, such as that performed by the pam_cracklib and pam_pwcheck modules.
    Password,
    /// Modules in this area perform any number of things that happen either during the setup or cleanup of a service for a given user. This may include any number of things; launching a system-wide initialization script, performing special logging, mounting the user’s home directory, or setting resource limits.
    Session,
    Invalid,
}

impl ToString for Facility {
    fn to_string(&self) -> String {
        match self {
            Facility::Auth => "auth".to_string(),
            Facility::Account => "account".to_string(),
            Facility::Password => "password".to_string(),
            Facility::Session => "session".to_string(),
            Facility::Invalid => "invalid!".to_string(),
        }
    }
}

impl From<&str> for Facility {
    fn from(value: &str) -> Self {
        match value {
            "auth" => Self::Auth,
            "account" => Self::Account,
            "password" => Self::Password,
            "session" => Self::Session,
            _ => Self::Invalid,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
#[allow(dead_code)]
pub enum Control {
    /// If a ‘required’ module returns a status that is not ‘success’, the operation will ultimately fail, but only after the modules below it are invoked. This seems senseless at first glance I suppose, but it serves the purpose of always acting the same way from the point of view of the user trying to utilize the service. The net effect is that it becomes impossible for a potential cracker to determine which module caused the failure – and the less information a malicious user has about your system, the better. Important to note is that even if all of the modules in the stack succeed, failure of one ‘required’ module means the operation will ultimately fail. Of course, if a required module succeeds, the operation can still fail if a ‘required’ module later in the stack fails.
    Required,
    /// If a ‘requisite’ module fails, the operation not only fails, but the operation is immediately terminated with a failure without invoking any other modules: ‘do not pass go, do not collect $200’, so to speak.
    Requisite,
    /// If a sufficient module succeeds, it is enough to satisfy the requirements of sufficient modules in that facility for use of the service, and modules below it that are also listed as ‘sufficient’ are not invoked. If it fails, the operation fails unless a module invoked after it succeeds. Important to note is that if a ‘required’ module fails before a ‘sufficient’ one succeeds, the operation will fail anyway, ignoring the status of any ‘sufficient’ modules.
    Sufficient,
    /// An ‘optional’ module, according to the pam(8) manpage, will only cause an operation to fail if it’s the only module in the stack for that facility.
    Optional,
    Invalid,
}

impl From<&str> for Control {
    fn from(value: &str) -> Self {
        match value {
            "required" => Self::Required,
            "requisite" => Self::Requisite,
            "sufficient" => Self::Sufficient,
            "optional" => Self::Optional,
            _ => Self::Invalid,
        }
    }
}

impl ToString for Control {
    fn to_string(&self) -> String {
        match self {
            Control::Required => "required".to_string(),
            Control::Requisite => "requisite".to_string(),
            Control::Sufficient => "sufficient".to_string(),
            Control::Optional => "optional".to_string(),
            Control::Invalid => "invalid!".to_string(),
        }
    }
}

fn serialize_rules<S>(input: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&input.join(" "))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(dead_code)]
pub struct Rule {
    pub facility: Facility,
    pub control: Control,
    pub module: String,
    #[serde(default = "Vec::new", serialize_with = "serialize_rules")]
    arguments: Vec<String>,
    pub final_result: Option<FinalResult>,
    pub rule_order: Option<u32>,
    pub rulehash: Option<String>,
}

impl Rule {
    pub fn hash(&self) -> String {
        let mut hash_string = String::new();
        hash_string.push_str(&self.facility.to_string());
        hash_string.push_str(&self.control.to_string());
        hash_string.push_str(&self.module.to_string());
        hash_string.push_str(&self.arguments.join(" ").to_string());
        // if let Some(final_result) = self.final_result {
        //     hash_string.push_str(final_result.to_string());
        // }
        sha256::digest(hash_string)
    }

    pub fn new(value: &str, rule_order: &u32, results: &[Rule]) -> Result<Self, Error> {
        if value.trim().is_empty() {
            return Err(Error::new(ErrorKind::Other, "Empty line"));
        }
        // check it's long enough
        if value.split_whitespace().collect::<Vec<&str>>().len() < 3 {
            return Err(Error::new(ErrorKind::Other, "Not enough parts to the rule"));
        }
        // go through and make the rule naow
        let mut parts = value.split_whitespace();

        let facility = parts.next().unwrap();
        let control = parts.next().unwrap();
        let module = parts.next().unwrap();
        let arguments = parts.collect::<Vec<&str>>();

        let mut rule = Rule {
            facility: Facility::from(facility),
            control: Control::try_from(control)
                .unwrap_or_else(|f| panic!("Failed to parse {} as a control", f)),
            module: module.to_string(),
            arguments: arguments.iter().map(|s| s.to_string()).collect(),
            final_result: None,
            rule_order: Some(rule_order.to_owned()),
            rulehash: None,
        };
        rule.final_result = try_find_matching_rule_result(results, &rule);
        // can't hash it until it's made
        rule.rulehash = Some(rule.hash());
        Ok(rule)
    }
    pub fn to_shortstring(&self) -> String {
        format!(
            "{} {} {}",
            self.control.to_string(),
            self.module,
            self.arguments.join(" ")
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FinalResult {
    Success,
    Failure,
}

impl From<FinalResult> for bool {
    fn from(value: FinalResult) -> Self {
        match value {
            FinalResult::Success => true,
            FinalResult::Failure => false,
        }
    }
}

pub struct RuleSet {
    #[allow(dead_code)]
    facility: Facility,
    pub rules: Vec<Rule>,
    pub finalresult: FinalResult,
    pub had_sufficient: bool,
    pub rules_run: usize,
}

impl RuleSet {
    pub fn get_rule_result(&self, rule: &Rule) -> bool {
        match &rule.final_result {
            Some(val) => val.to_owned().into(),
            None => {
                info!(
                    "Did this succeed: {} {}",
                    rule.facility.to_string(),
                    rule.to_shortstring()
                );

                match Confirm::new().interact() {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(_) => false,
                }
            }
        }
    }

    pub fn new(facility: &Facility, rules: Vec<Rule>) -> Self {
        RuleSet {
            facility: facility.clone(),
            rules,
            finalresult: FinalResult::Success,
            had_sufficient: false,
            rules_run: 0,
        }
    }
    pub fn run_rules(&mut self) -> FinalResult {
        let rules_iter = self.rules.iter().enumerate();
        // println!("Facility: {:?}", self.facility);
        for (index, rule) in rules_iter {
            match rule.control {
                Control::Invalid => {}
                Control::Required => {
                    if let FinalResult::Failure = self.finalresult {
                        info!(
                            "Don't have to process \"{}\" because we already failed, and this won't change the state.",
                            rule.to_shortstring(),
                        );
                        continue;
                    };
                    let rule_result = self.get_rule_result(rule);
                    if !rule_result {
                        self.finalresult = FinalResult::Failure;
                        warn!(
                            "Rule #{} was required, so {:?} will fail!",
                            rule.rule_order
                                .map(|i| i.to_string())
                                .unwrap_or("?".to_string()),
                            self.facility
                        );
                    }
                    self.rules_run += 1;
                }
                Control::Requisite => {
                    self.rules_run += 1;
                    if !self.get_rule_result(rule) {
                        warn!(
                            "Rule #{} was requisite, so {:?} will fail regardless!",
                            rule.rule_order
                                .map(|i| i.to_string())
                                .unwrap_or("?".to_string()),
                            self.facility
                        );
                        return FinalResult::Failure;
                    }
                }
                Control::Sufficient => {
                    if self.had_sufficient {
                        info!(
                            "Don't have to process {} {} {} because we already had a 'sufficient' rule",
                            rule.control.to_string(),
                            rule.module,
                            rule.arguments.join(" "),
                        );
                        continue;
                    } else if self.get_rule_result(rule) {
                        self.had_sufficient = true;
                    }

                    self.rules_run += 1;
                }
                Control::Optional => {
                    if !self.get_rule_result(rule) {
                        self.rules_run += 1;
                        // first in the facility, doesn't have to be the first *rule*
                        if index == 0 {
                            return FinalResult::Failure;
                        } else {
                            println!("Optional rule {} failed, but wasn't the first rule, so we'll continue", rule.rule_order
                            .map(|i| i.to_string())
                            .unwrap_or("?".to_string()),);
                        }
                    }
                }
            }
        }
        self.finalresult.to_owned()
    }
}

pub fn loadresults() -> Vec<Rule> {
    let filename = match env::args().nth(2) {
        Some(filename) => filename,
        None => {
            debug!("No results file given, please tell me which file to read if you want them!");
            return vec![];
        }
    };

    let input_string = match std::fs::read_to_string(&filename) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to read {}: {:?}", filename, err);
            return vec![];
        }
    };
    serde_json::from_str(&input_string).expect("Failed to load results")
}

pub fn load_file() -> Result<Vec<String>, std::io::Error> {
    // load filename specified on the command line as argv[1] as a stirng
    let filename = match env::args().nth(1) {
        Some(filename) => filename,
        None => {
            error!("No filename given, please tell me which file to read!");
            return Err(Error::new(
                ErrorKind::Other,
                "No filename given, please tell me which file to read!",
            ));
        }
    };
    info!("Loading file: {}", filename);

    // read the file into a string
    let input_string = std::fs::read_to_string(&filename).map_err(|err| {
        error!("Failed to read {}: {:?}", filename, err);
        err
    })?;

    Ok(input_string
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                // ignore blank lines
                None
            } else if line.starts_with('#') {
                // comments
                info!("Skipping comment: {}", line);
                None
            } else {
                Some(line.to_string())
            }
        })
        .collect::<Vec<String>>())
}

pub fn try_find_matching_rule_result(rules: &[Rule], rule: &Rule) -> Option<FinalResult> {
    rules.iter().find_map(|r| {
        if r.facility == rule.facility
            && r.control == rule.control
            && r.module == rule.module
            && r.arguments == rule.arguments
        {
            r.final_result.clone().map(|r| r.to_owned())
        } else {
            None
        }
    })
}

pub fn rules_from_vec_string(value: Vec<String>) -> Vec<Rule> {
    let mut rule_order: u32 = 0;
    let results_vec = loadresults();
    let rules: Vec<Rule> = value
        .into_iter()
        .filter_map(|line| {
            debug!("handling line: '{}'", line);
            if line.trim().is_empty() {
                return None;
            }
            if line.trim().starts_with('#') {
                return None;
            }

            if let Ok(rule) = Rule::new(&line, &rule_order, &results_vec) {
                rule_order += 1;
                Some(rule)
            } else {
                None
            }
        })
        .collect();
    rules.iter().for_each(|r| debug!("{:?}", r));
    rules
}
