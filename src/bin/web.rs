use axum::{
    response::Html,
    routing::{get, post},
    Json, Router,
};
use log::{debug, error};
use pam_explainer::{rules_from_vec_string, Rule};
use serde::{Deserialize, Serialize};
use std::{env, net::SocketAddr};
use tower_http::services::ServeDir;

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
        .route("/parse", post(parse_pam))
        .route("/results", post(handle_results))
        .nest_service("/static", ServeDir::new("./src/static/").precompressed_br())
        ;

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
    let input_string = match std::fs::read_to_string(filename) {
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
            .map(|l| l.to_string())
            .collect::<Vec<String>>(),
    );
    ParsedResponse { parsed: rules }.into()
}

async fn handle_results(Json(payload): Json<serde_json::Value>) -> String {
    log::debug!("payload: {:?}", &payload);
    if let Some(payload) = payload.as_object() {
        for field in payload.iter() {
            debug!("{}: {:?}", field.0, field.1);
        }

        format!("{:?}", payload)
    } else {
        "failed to parse payload as JSON blob!".to_string()
    }
}
