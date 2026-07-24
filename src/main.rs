use rand::{RngCore, rngs::OsRng}; //Generates cryptographically secure random bytes. This is what we use for PKCE code_verifier
use sha2::{Digest, Sha256}; //Computes SHA-256 hash - Used for PKCE challenge
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _}; //Encodes bytes into URL-safe strings which spotify requires
use warp::Filter; //Lightweight http server framework
use std::sync::{Arc, Mutex}; //Shared memory across async server + main thread since we are using awaits based on browser auth
use urlencoding;
use serde::Deserialize;
use serde::Serialize;
use clap::{Parser, Subcommand, Args, ArgGroup};
use std::collections::hash_set::HashSet;

#[derive(Parser)]
#[command(name = "spotty")]
#[command(version = "1.0")]
#[command(about = "Interact with Spotify from the terminal")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

//TODO: Make app part have a cute feature that fills a jar with block representing all the songs you've played since openign the app

#[derive(Subcommand)]
enum Commands {
    Login,

    Recent(RecentArgs),

    Refresh
}

#[derive(Args)]
#[command(group(
    ArgGroup::new("source")
    .required(true)
    .args(["name", "prefix"])
))]
struct RecentArgs {
    #[arg(default_value_t = 10)]
    num_songs: u32,
    #[arg(short, long)]
    name: Option<String>,
    #[arg(short, long)]
    prefix: Option<String>
}

const CLIENT_ID: &str = "029dec42942148988a90b86aa92756dd";
const REDIRECT_URI: &str = "http://127.0.0.1:8888/callback";

//PCKE stands for Proof Key for Code Exchange - It is a security feature of OAuth 2.0 which protects auth codes from being intercepted in transit
//It ensures that the app requesting a login is the same app that receives the auth token

//Code Verifier - The client app generates a random high-entropy string
//Code Challenge - The app runs that string through a cryptographic hash function (i.e SHA-256) to create a "challenge". This chalenge is sent to the auth server during the initial login request

//When the server returns the auth code, the app sends the originial unhashed Code Verifier back to the server. The server verifies it against the originial hashed challenge. If they don't match, the token request is denied

#[derive(Debug, Deserialize, Serialize)]
struct SpotifyTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
}

#[derive(Debug, Deserialize)]
struct SpotifyRecentlyPlayedResponse {
    limit: u64,
    next: String,
    items: Vec<PlayHistoryObject>
}

#[derive(Debug, Deserialize)]
struct PlayHistoryObject {
    track: TrackObject,
    played_at: String,
}

#[derive(Deserialize)]
struct PlaylistItemsResponse {
    items: Vec<PlaylistTrackObject>,
    next: Option<String>
}

#[derive(Deserialize)]
struct PlaylistTrackObject {
    item: TrackObject
}

#[derive(Debug, Deserialize)]
struct TrackObject {
    name: String,
    artists: Vec<Artist>,
    album: Album,
    uri: String
}

#[derive(Debug, Deserialize)]
struct Artist {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Album {
    name: String,
    images: Vec<Image>,
}

#[derive(Debug, Deserialize)]
struct Image {
    url: String,
}

#[derive(Serialize)]
struct AddTracksRequest {
    uris: HashSet<String>,
    position: u32
}

#[derive(Serialize)]
struct CreatePlaylistRequest {
    name: String,
    description: String
}

#[derive(Deserialize)]
struct CreatePlaylistResponse {
    id: String,
    uri: String
}

#[derive(Deserialize)]
struct SimplifiedPlaylistObject {
    name: String,
    id: String,
    uri: String
}

#[derive(Deserialize)]
struct GetUserPlaylistsResponse {
    items: Vec<SimplifiedPlaylistObject>,
    next: Option<String>
}

fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

async fn get_token(use_refresh: bool) -> Result<Option<SpotifyTokenResponse>, Box<dyn std::error::Error>> {
    let refresh_token = std::fs::read_to_string("refresh_token.txt");

    let mut token_response: Option<SpotifyTokenResponse> = None;
    let client = reqwest::Client::new();

    let pair = (refresh_token, use_refresh);

    match pair {
    (Ok(token), true) => {
        println!("Using saved refresh token");
        
        
        let refresh_params = [
            ("grant_type", "refresh_token"),
            ("refresh_token", &token),
            ("client_id", CLIENT_ID)
        ];

        let res = client
            .post("https://accounts.spotify.com/api/token")
            .form(&refresh_params)
            .send()
            .await?;
        //------------------------------------------------------------------------

        println!("Status: {}", res.status());
        token_response = res.json().await?;
    }

    _ => {
        println!("No refresh token, starting browser login");

        // 1. PKCE setup
        let code_verifier = generate_code_verifier();
        let code_challenge = generate_code_challenge(&code_verifier); //Here we create our challenge to send to the Spotify server

        // Shared state to capture callback
        let code_store = Arc::new(Mutex::new(None::<String>)); //Arc = shared ownership across threads, Mutex = safe mutable access, Option<string> = May or may not have code yet
        //We do this since the HTTP server runs asynchronously while the main thread is waiting, but they need to communicate so the server can give the main thread the auth token once Spotify responds

        let code_store_filter = warp::any().map({
            let code_store = code_store.clone();
            move || code_store.clone()
        });

        // 2. Local callback server
        let callback_route = warp::path("callback")
            .and(warp::query::<std::collections::HashMap<String, String>>())
            .and(code_store_filter.clone())
            .map(|params: std::collections::HashMap<String, String>, store: Arc<Mutex<Option<String>>>| {
                if let Some(code) = params.get("code") {
                    let mut locked = store.lock().unwrap();
                    *locked = Some(code.clone());
                    return "Login successful. You can close this window.";
                }
                "Missing code"
            });

        let server = warp::serve(callback_route).run(([127, 0, 0, 1], 8888)); //This creates a future that will start the server when activated

        // 3. Build Spotify auth URL

        //client id identifies our app
        //response_type=code => OAuth authorization code flow
        //redirect_uri = Where spotify sends the user back
        //scope == permissions acquired
        let auth_url = format!(
            "https://accounts.spotify.com/authorize\
            ?client_id={}\
            &response_type=code\
            &redirect_uri={}\
            &scope=user-read-recently-played%20playlist-modify-public%20playlist-read-private\
            &code_challenge={}\
            &code_challenge_method=S256", 
            CLIENT_ID,
            urlencoding::encode(REDIRECT_URI),
            code_challenge
        );

        // 4. Open browser
        webbrowser::open(&auth_url).expect("failed to open browser");

        println!("Waiting for Spotify callback...");


        //What is tokio::select! actually doing?
        //Runs multiple async futures at the same time on the same task, and waits until one completes - It is not spawning multiple threads, it is just using a scheduler to poll futures
        //Whichever task completes first wins and the other is stopped

        // 5. Run server concurrently and wait for code

        tokio::select! {
            _ = server => {}, //Starts the server by activating the future. htpp://127.0.0.0.1:8888 is now waiting for the spotify redirect
            _ = async {
                loop { //Loops every 200ms until we find auth code
                    if let Some(code) = &*code_store.lock().unwrap() { //mutex is unlocked automatically once guard goes out of scope
                        println!("Got authorization code: {}", code);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            } => {}
        }

        println!("Done. Now exchange code for token using POST /api/token");


        if let Some(code) = code_store.lock().unwrap().take() {
            let params = [
                ("grant_type", "authorization_code"),
                ("code", code.as_str()),
                ("redirect_uri", REDIRECT_URI),
                ("client_id", CLIENT_ID),
                ("code_verifier", code_verifier.as_str()),
            ];

            let res = client
                .post("https://accounts.spotify.com/api/token")
                .form(&params)
                .send()
                .await?;
            //------------------------------------------------------------------------

            println!("Status: {}", res.status());
            token_response = res.json().await?;
        }
    }
    }

    return Ok(token_response);

}

//Returns access token
async fn login(use_refresh: bool) -> Result<String, Box<dyn std::error::Error>> {
    let token_response: Option<SpotifyTokenResponse> = get_token(use_refresh).await?;

    if let Some(token_response) = token_response {
        println!("Access token: {}", token_response.access_token);

        if let Some(refresh_token) = token_response.refresh_token {
        std::fs::write(
            "refresh_token.txt",
            refresh_token
        )?;
        }

        Ok(token_response.access_token)
    } else {
        Err("Failed to get token".into())
    }
}

async fn get_recently_played_songs(num_songs: u32, access_token: &String) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let response = client
        .get("https://api.spotify.com/v1/me/player/recently-played")
        .header(
            "Authorization",
            format!("Bearer {}", access_token)
        )
        .query(&[
            ("limit", num_songs.to_string()),
        ])
        .send()
        .await?;

    let out: SpotifyRecentlyPlayedResponse = response.json().await?;

    let mut recently_played_uris: HashSet<String> = HashSet::new();

    for item in out.items.iter() {
        println!("{}", item.track.name);
        recently_played_uris.insert(item.track.uri.clone());
    }

    Ok(recently_played_uris)
}

async fn get_songs_in_playlist(playlist_id: &String, access_token: &String) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let mut url = Some(format!("https://api.spotify.com/v1/playlists/{}/items", playlist_id)
    );

    let mut recently_played_uris: Vec<String> = vec![];

    while let Some(current_url) = url {
        let response = client
            .get(&current_url)
            .header(
                "Authorization",
                format!("Bearer {}", access_token)
            )
            .query(&[
                ("limit", "50"),
            ])
            .send()
            .await?;

        let out: PlaylistItemsResponse = response.json().await?;
        

        for item in out.items.iter() {
            println!("{}", item.item.name);
            recently_played_uris.push(item.item.uri.to_string());
        }

        url = out.next;
    }

    Ok(recently_played_uris)
}

async fn post_new_playlist(params: CreatePlaylistRequest, access_token: &String) -> Result<CreatePlaylistResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let create_playlist_req = client
        .post("https://api.spotify.com/v1/me/playlists")
        .header(
            "Authorization",
            format!("Bearer {}", access_token)
        )
        .json(&params)
        .send()
        .await?;

    let status = create_playlist_req.status();
    println!("Status: {}", status);

    let create_result: CreatePlaylistResponse = create_playlist_req.json().await?;

    Ok(create_result)
}

async fn delete_playlist(playlist_uri: String, access_token:& String) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    client
        .delete("https://api.spotify.com/v1/me/library")
        .header(
                "Authorization",
                format!("Bearer {}", access_token)
            )
        .query(&[
                ("uris", &playlist_uri),
            ])
        .send()
        .await?;
    
    Ok(())
}

async fn put_songs_into_playlist(playlist_id: &String, add_tracks_request: AddTracksRequest, access_token: &String) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let put_request = client
        .post(format!("https://api.spotify.com/v1/playlists/{}/items", playlist_id))
        .header(
            "Authorization",
            format!("Bearer {}", access_token)
        )
        .json(&add_tracks_request)
        .send()
        .await?;

    let status = put_request.status();
    println!("Status: {}", status);

    Ok(())
}

async fn put_refresh(playlist_id: &String, access_token: &String) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    client
        .put(format!("https://api.spotify.com/v1/playlists/{}/followers", playlist_id))
        .header(
            "Authorization",
            format!("Bearer {}", access_token)
        )
        .send()
        .await?;
    Ok(())
}

async fn get_user_playlists(access_token: &String) -> Result<Vec<SimplifiedPlaylistObject>, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();

    let mut url: Option<String> = Some("https://api.spotify.com/v1/me/playlists".to_string());

    let mut playlist_objects: Vec<SimplifiedPlaylistObject> = vec![];

    while let Some(current_url) = url {
        let response = client
            .get(current_url)
            .header(
                "Authorization",
                format!("Bearer {}", access_token)
            )
            .query(&[
                ("limit", "50"),
            ])
            .send()
            .await?;
        let out: GetUserPlaylistsResponse = response.json().await?;
        
        playlist_objects.extend(out.items);

        url = out.next;
    }

    Ok(playlist_objects)
}

async fn get_playlists_matching_prefix(prefix: &String, access_token: &String) -> Result<Vec<SimplifiedPlaylistObject>, Box<dyn std::error::Error>> {
    let playlists: Vec<SimplifiedPlaylistObject> = get_user_playlists(&access_token).await?;

    let mut matching_playlists: Vec<SimplifiedPlaylistObject> = vec![];

    for playlist_obj in playlists {
        if playlist_obj.name.to_lowercase().starts_with(&prefix.to_lowercase()) {
            println!("MATCH FOUND: {}", playlist_obj.name);
            matching_playlists.push(playlist_obj);
        }
    }

    Ok(matching_playlists)
}


#[tokio::main] //Starts a Tokio async runtime which allows for: Running HTTP server, waiting without blocking, handling browser callback
async fn main() -> Result<(), Box<dyn std::error::Error>> { //Means that on success we return nothing (unit type = "()") and on error we return the boxed error
    let args = Cli::parse();

    match args.command {
        Commands::Login {} => {
            login(false).await?;
        }

        Commands::Refresh {} => {
           let access_token: String = login(true).await?;

            let playlist_params: CreatePlaylistRequest = CreatePlaylistRequest { name: "TEMP".to_string(), description: "TEMP".to_string() };
            let create_response: CreatePlaylistResponse = post_new_playlist(playlist_params, &access_token).await?;
            delete_playlist(create_response.uri, &access_token).await?;
        }

        Commands::Recent(args) => {
            let access_token: String = login(true).await?;

            println!("Access token: {}", &access_token);

            //BELOW ARE API Requests

            //Query params are not the same as body json
            //Query params are for filtering/modifying the data you want back

            //Request body (for POST/PUT) are used to SEND data to spotify (i.e. creating a playlist)

            let mut recently_played_uris: HashSet<String> = get_recently_played_songs(args.num_songs, &access_token).await?;

            let mut playlist_id: Option<String> = None;

            if let Some(prefix) = args.prefix {
                let matching_playlists = get_playlists_matching_prefix(&prefix, &access_token).await?;

                if matching_playlists.len() >= 1 {
                    playlist_id = Some(matching_playlists[0].id.clone());
                    println!("Found {} matching prefix", matching_playlists[0].name.to_string());
                }

            } else if let Some(name) = args.name {
                let playlist_params: CreatePlaylistRequest = CreatePlaylistRequest { name: name, description: "NA".to_string() };

                let create_result = post_new_playlist(playlist_params, &access_token).await?;

                println!("Playlist ID: {}", &create_result.uri);

                playlist_id = Some(create_result.id);
            }

            if let Some(desired_playlist_id) = playlist_id {

                let songs_in_playlist: Vec<String> = get_songs_in_playlist(&desired_playlist_id, &access_token).await?;

                recently_played_uris.retain(|x| !songs_in_playlist.contains(x));

                let body = AddTracksRequest {
                    uris: recently_played_uris.clone(),
                    position: 0 
                };

                println!("Adding {} songs to playlist", recently_played_uris.len());
                if recently_played_uris.len() > 0 {
                    put_songs_into_playlist(&desired_playlist_id, body, &access_token).await?;
                    put_refresh(&desired_playlist_id, &access_token).await?;
                }
            }
        }
    }

    Ok(())
}