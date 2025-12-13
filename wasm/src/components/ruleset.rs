use crate::prelude::*;
use pam_explainer::{Facility, FinalResult, RuleSet as pam_ruleset};
use wasm_bindgen::JsCast;
use web_sys::{Event, HtmlInputElement};

#[derive(Properties, PartialEq)]
pub struct RuleSetProps {
    pub ruleset: pam_ruleset,
    pub rulecallback: Callback<(String, bool)>,
}

#[allow(dead_code)]
pub enum RuleSetMessage {
    RuleUpdate {
        rulehash: String,
        final_result: bool,
    },
    Nothing,
}

pub struct RuleSet(pub pam_ruleset);

impl Component for RuleSet {
    type Message = RuleSetMessage;

    type Properties = RuleSetProps;

    fn create(ctx: &yew::Context<Self>) -> Self {
        Self(ctx.props().ruleset.clone())
    }

    fn changed(&mut self, ctx: &yew::Context<Self>, old_props: &Self::Properties) -> bool {
        if ctx.props().ruleset.clone() != old_props.ruleset {
            self.0 = ctx.props().ruleset.clone();
            true
        } else {
            false
        }
    }

    fn view(&self, ctx: &yew::Context<Self>) -> yew::Html {
        let mut ruleset = self.0.clone();

        let ruleset_final_result = if let Facility::Invalid(_) = ruleset.facility {
            "".to_string()
        } else {
            format!(
                "Final result: {:?} (Ran {} rules)",
                ruleset.run_rules(),
                ruleset.rules_run
            )
        };

        let rules_html = ruleset
            .rules
            .into_iter()
            .map(|rule| {
                let final_result_string: String = rule.result_string();
                let checked = match rule.final_result {
                    Some(value) => match value {
                        FinalResult::Success => true,
                        FinalResult::Failure => false,
                    },
                    None => false,
                };
                html! {
                    <tr>
                        <td>{rule.rule_order.unwrap_or(0).to_string()}</td>
                        { if let Facility::Invalid(value) = rule.facility {
                            html!{<th>{value}</th>}
                        } else {
                            html!{<></>}
                        }}

                        <td>{rule.control.to_string()}</td>
                        <td>{rule.module.clone()}</td>
                        <td>{rule.arguments.join(" ")}</td>
                        <td><input type="checkbox"
                            id={rule.rulehash.clone().unwrap_or("foo".to_string())}
                            checked={checked}
                            onchange={ctx.link().callback(move |event: Event| {
                            if let Some(event) = event.target(){
                                if let Some(rulehash) = rule.rulehash.as_ref() {

                                    let input = event.dyn_into::<HtmlInputElement>().expect("Failed to cast event target to HtmlInputElement");
                                    let checked = input.checked();
                                    debug!("Sending rule update", rule.rulehash.clone(), checked);
                                    RuleSetMessage::RuleUpdate{rulehash: rulehash.clone(), final_result: checked}
                                } else {
                                    debug !("No rulehash found for rule, cannot send update");
                                    RuleSetMessage::Nothing
                                }
                            } else {
                                RuleSetMessage::Nothing
                            }
                        })}/></td>
                        <td>{final_result_string}</td>
                    </tr>
                }
            })
            .collect::<Html>();

        html! {

        <div><h2 class="facilityTitle">{self.0.facility.to_string()}</h2>
        <table id="data">
        <thead>
        <th>{"#"}</th>
        { if let Facility::Invalid(_) = self.0.facility {
                html!{<th>{"Facility"}</th>}
        } else {
            html!{<></>}
        }}
        <th>{"Control"}</th>
        <th>{"Module"}</th>
        <th>{"Arguments"}</th>
        <th>{"Success?"}</th>
        <th>{"Explanation"}</th>
        </thead>
        <tbody>
        {rules_html}
        </tbody>
        </table>
        {ruleset_final_result}
        </div>}
    }

    fn update(&mut self, ctx: &yew::Context<Self>, msg: Self::Message) -> bool {
        match msg {
            RuleSetMessage::RuleUpdate {
                rulehash,
                final_result,
            } => {
                ctx.props().rulecallback.emit((rulehash, final_result));
                true
            }
            RuleSetMessage::Nothing => false,
        }
    }
}
