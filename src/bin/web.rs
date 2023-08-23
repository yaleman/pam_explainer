use axum::{
    response::Html,
    routing::{get, post},
    Json, Router,
};
use log::error;
use pam_explainer::{rules_from_vec_string, Rule};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};

#[tokio::main]
async fn main() {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "DEBUG");
    }
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // `POST /users` goes to `create_user`
        .route("/parse", post(parse_pam));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// basic handler that responds with a static string
async fn root() -> Html<String> {
    // read the file into a string
    let filename = "./src/bin/index.html";
    let input_string = match std::fs::read_to_string(&filename) {
        Ok(val) => val,
        Err(err) => {
            error!("Failed to read {}: {:?}", filename, err);
            return Html("Failed".to_string());
        }
    };
    Html(input_string)
}
#[derive(Debug, Deserialize, Serialize)]
struct FormData {
    data: String,
}
#[derive(Debug, Deserialize, Serialize)]
struct ParsedResponse {
    parsed: Vec<Rule>,
}

async fn parse_pam(Json(payload): Json<FormData>) -> Json<ParsedResponse> {
    log::debug!("{:?}", &payload);
    let rules = rules_from_vec_string(
        payload
            .data
            .lines()
            .into_iter()
            .map(|l| l.to_string())
            .collect::<Vec<String>>(),
    );
    ParsedResponse{parsed: rules}.into()
}
