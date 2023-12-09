use std::collections::HashMap;

use pam_explainer::{Facility, FinalResult, RuleSets};
#[allow(unused_imports)]
use wasm_bindgen::prelude::*;

pub(crate) mod components;

const EXAMPLE_CONFIG: &str = include_str!("../../testfile.txt");

mod prelude {
    pub use gloo_console::*;
    pub use web_sys::HtmlTextAreaElement;
    pub use yew::prelude::*;
}

use prelude::*;

struct PamSplainer {
    config_ref: NodeRef,
    config: AttrValue,
    rulesets: RuleSets,
}

enum PamSplainerMessage {
    Config(AttrValue),
    View,
    RuleUpdate {
        rulehash: String,
        final_result: bool,
    },
}

impl Component for PamSplainer {
    type Message = PamSplainerMessage;
    type Properties = ();

    fn create(_ctx: &Context<Self>) -> Self {
        Self {
            config_ref: NodeRef::default(),
            config: String::new().into(),
            rulesets: HashMap::new(),
        }
    }

    fn view(&self, ctx: &Context<Self>) -> Html {
        let mut sorted_keys: Vec<Facility> = self.rulesets.keys().cloned().collect();
        sorted_keys.sort();

        html! {
            <>
            <div>
                <h1>{"PAM-Splainer"}</h1>
                <p>{"This runs completely in the browser, allowing you to figure out how your PAM config rules get run."}</p>
                <p>{"Check the boxes next to the rules to specify which ones succeeded/failed, and it'll show the outcome."}</p>
            </div>
            <div id="inputData" class="bodyDivs configBackground">
            <h2>{"Paste your config here"}</h2>
            <button onclick={ctx.link().callback(|_| PamSplainerMessage::Config(EXAMPLE_CONFIG.into()))}>{"Load Example Config"}</button>{" "}
            <button onclick={ctx.link().callback(|_| PamSplainerMessage::Config("".into()))}>{"Clear Config"}</button>
            <textarea id="pamconfig" rows=20 class="textareaInput"
                ref={self.config_ref.clone()}
                value={self.config.clone()}
                oninput={ctx.link().callback(move |event:  InputEvent| {
                    let input = event.target_dyn_into::<HtmlTextAreaElement>();
                    if let Some(input) = input {
                        let value = input.value();
                        PamSplainerMessage::Config(value.into())
                    } else {
                        PamSplainerMessage::View
                    }
                })}
                />
            </div>
            <div class="bodyDivs resultsBackground">
                {
                    sorted_keys.into_iter().map(|facility| {
                    html! {
                        <components::ruleset::RuleSet
                            ruleset={self.rulesets.get(&facility).unwrap().clone()}
                            rulecallback={ctx.link().callback(|(rulehash, final_result)| {
                                PamSplainerMessage::RuleUpdate{rulehash, final_result}
                            })
                            } />

                    }
                }).collect::<Html>()}
            </div>
            <footer>{"Made by James Hodgkinson | "}<a href="https://github.com/yaleman/pam_explainer">{"Github"}</a>
            </footer>
            </>
        }
    }

    fn update(&mut self, _ctx: &Context<Self>, msg: PamSplainerMessage) -> bool {
        match msg {
            PamSplainerMessage::Config(value) => {
                if value != self.config {
                    // config changed
                    info!("{}", "config - changed".to_string());
                    self.config = value.clone();
                    self.rulesets = pam_explainer::rulesets_from_string(
                        value.to_string(),
                        FinalResult::Success,
                    );
                    true
                } else {
                    info!("{}", "config - no change".to_string());
                    false
                }
            }
            PamSplainerMessage::View => {
                gloo_console::info!("{}", "view".to_string());
                true
            }
            PamSplainerMessage::RuleUpdate {
                rulehash,
                final_result,
            } => {
                info!("PamSplainer Update ", rulehash.clone(), final_result);
                let mut rulesets = self.rulesets.clone();
                for (_facility, ruleset) in rulesets.iter_mut() {
                    for rule in ruleset.rules.iter_mut() {
                        if rule.rulehash.clone() == Some(rulehash.clone()) {
                            info!("PamSplainer Updating rule: ", rulehash.clone());
                            rule.final_result = Some(final_result.into());
                        }
                    }
                }
                self.rulesets = rulesets;
                true
            }
        }
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub fn pamsplain() {
    yew::Renderer::<PamSplainer>::new().render();
}
