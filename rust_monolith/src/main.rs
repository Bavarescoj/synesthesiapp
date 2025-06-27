use std::fs::OpenOptions;
use actix_session::{Session, SessionMiddleware};
use actix_session::storage::RedisSessionStore;
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use actix_web::http::header::LOCATION;
use actix_web::cookie::Key;
use base64::Engine;
use oauth2::{AuthUrl, Client, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenUrl, basic::{
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    BasicRevocationErrorResponse,
}, StandardRevocableToken, EndpointNotSet, EndpointSet, AuthorizationCode};
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use dotenv::dotenv;
use base64::engine::general_purpose;
use serde::Deserialize;

/*
    Type that represents the Client created for the Authentication
    TODO: Is this the best way to represent this?
 */
pub type OAuth2Client = Client<
    BasicErrorResponse,
    BasicTokenResponse,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
>;

//TODO: implement Optionality and Error message from Spotify when user rejects the request
#[derive(Deserialize)]
struct AuthResponse {
    code: String,
    //error: Option<String>,
    state: String,
}

/*
    This method handles the PCKE Challenge and Verifier creation, and generates the authorization URL
    TODO: Define the desired scopes somewhere else, maybe on the .env file?
    Then, the generated CsrfToken generated and the PCKE Verifier are saved on the session so they can be used
    on the /callback for security measurements.
 */
#[get("/")]
async fn login(session: Session, authorize_client: web::Data<OAuth2Client>) -> impl Responder {
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL
    let (auth_url, csrf_token) = authorize_client
        .authorize_url(CsrfToken::new_random)
        // Set the desired scopes.
        .add_scope(Scope::new("user-read-recently-played".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Save CSRF and verifier to session – TODO: Improve error handling!
    session.insert("csrf_token", csrf_token.secret()).unwrap();
    session.insert("pkce_verifier", pkce_verifier.secret()).unwrap();

    // Redirect the user to Spotify's authorization URL
    HttpResponse::Found()
        .insert_header((LOCATION, auth_url.to_string()))
        .finish()
}

/*
    Here, the PCKE Verifier and CsrfToken are retrieved from the session and used for security measurements
    A Web Query is used to retrieve both the authorization code and the state that will be compared to the CsrfToken
 */
#[get("/callback")]
async fn callback(session: Session, query: web::Query<AuthResponse>, authorize_client: web::Data<OAuth2Client>)
    -> impl Responder {

    let pkce_verifier: String = match session.get("pkce_verifier").unwrap_or(None) {
        Some(val) => val,
        None => return HttpResponse::BadRequest().body("Missing PKCE verifier"),
    };

    let csrf_token: String = match session.get("csrf_token").unwrap_or(None) {
        Some(val) => val,
        None => return HttpResponse::BadRequest().body("Missing CSRF token"),
    };

    //TODO: Create error handling
    let code = AuthorizationCode::new(query.code.clone());
    let state = query.state.clone();

    println!("Code {:?} and state {:?}", code, state);

    if csrf_token != state {
        return HttpResponse::BadRequest().body("CSRF token mismatch");
    }

    // Creating an HTTP client with redirects disabled that will be used for requesting the access token
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Using the OAuth2Client and the HTTP Client to get the access token
    let token_result = authorize_client
        .exchange_code(AuthorizationCode::new(code.into_secret()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier))
        .request_async(&http_client)
        .await;

    // Retrieving the token if all is successful, or returning an Error otherwise
    match token_result {
        Ok(token) => {
            println!("Successfully received token: {:?}", token);
            HttpResponse::Ok().body(format!("Token: {:?}", token))
        }
        Err(err) => {
            eprintln!("Error retrieving token: {}", err);
            HttpResponse::InternalServerError().body(format!("Error: {}", err))
        }
    }
}

/*
    Main is in charge of retrieving the data from the .env, creating a Redis Session,
    creating the OAuth2 Client, and initializing the server
 */
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let client_id = std::env::var("SPOTIFY_CLIENT_ID").expect("SPOTIFY_CLIENT_ID must be set.");
    let client_secret = std::env::var("SPOTIFY_CLIENT_SECRET").expect("SPOTIFY_CLIENT_SECRET must be set.");
    let redirect_uri = std::env::var("SPOTIFY_REDIRECT_URI").expect("SPOTIFY_REDIRECT_URI must be set.");
    let redis_url = std::env::var("LOCAL_REDIS").expect("LOCAL_REDIS must be set.");


    let secret_key = get_secret_key();

    let redis_store = RedisSessionStore::new(redis_url.to_string())
        .await
        .unwrap();

    println!("Redis store initialized");

    let authorize_client = web::Data::new(oauth2_auth(client_id, client_secret, redirect_uri)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?);

    println!("Client initialized");

    HttpServer::new(move || {
        App::new()
            .wrap(SessionMiddleware::new(redis_store.clone(), secret_key.clone()))
            .app_data(authorize_client.clone())
            .service(login)
            .service(callback)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}

/*
    Creating the OAuth2 Client based on the Client ID, Client Secret and Redirect URI from
    Spotify, and setting both the Auth URI and the Token URI
 */
pub fn oauth2_auth(client_id: String, client_secret: String, redirect_uri: String)
    -> Result<OAuth2Client, Box<dyn std::error::Error>> {
    // Creating an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.

    let client = BasicClient::new(ClientId::new(client_id))
        .set_client_secret(ClientSecret::new(client_secret))
        .set_auth_uri(AuthUrl::new("https://accounts.spotify.com/authorize".to_string())?)
        .set_token_uri(TokenUrl::new("https://accounts.spotify.com/api/token".to_string())?)
        // Set the URL the user will be redirected to after the authorization process.
        .set_redirect_uri(RedirectUrl::new(redirect_uri)?);

    Ok(client)
}

/*
    Reading the Secret Key needed for the Middleware from the .env file, or generating one
    if it doesn't exist – TODO: Improve the error handling!
 */
fn get_secret_key() -> Key {
    match std::env::var("SECRET_KEY") {
        Ok(key_str) if !key_str.is_empty() => {
            if let Ok(decoded) = general_purpose::STANDARD.decode(&key_str) {
                if decoded.len() == 64 {
                    return Key::from(&decoded);
                }
            }
        }
        _ => {
            eprintln!("No SECRET_KEY found in .env; generating a new one.");
        }
    }

    let new_key = Key::generate();
    let encoded = general_purpose::STANDARD.encode(new_key.master());

    if let Err(err) = {
        let mut file = OpenOptions::new()
            .append(true)
            .open(".env");

        match file {
            Ok(mut f) => writeln!(f, "SECRET_KEY={}", encoded),
            Err(e) => Err(e),
        }
    } {
        eprintln!("Failed to write SECRET_KEY to .env: {err}");
    }

    new_key
}
