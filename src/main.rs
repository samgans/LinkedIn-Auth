use std::io;
use std::error::Error;
use std::fmt;

use base64::encode_config;
use clap::{Arg, ArgMatches, App};
use rand::{Rng, thread_rng};
use reqwest::Error as ReqError;
use reqwest::blocking::{Client};
use serde_json::Value;

const AUTH_URL: &str = "https://www.linkedin.com/oauth/v2/authorization";
const ACCESS_TOKEN_URL: &str = "https://www.linkedin.com/oauth/v2/accessToken";


#[derive(Debug)]
struct ValueError;

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cannot retrieve access key value from the response")
    }
}

impl Error for ValueError {}


fn cli() -> ArgMatches<'static> {
    App::new("LinkedIn Auth")
        .version("0.0.1")
        .author("Anton Zhyltsou")
        .about("Automates the process of LinkedIn app authentication")
        .arg(
            Arg::with_name("client-id")
            .short("c")
            .long("client-id")
            .help(
                concat!(
                    "Client ID of the application. Can be retrieved",
                    "from the apps list in the LIN service account."
                )
            )
            .takes_value(true)
            .required(true)
        )
        .arg(
            Arg::with_name("client-secret")
            .short("s")
            .long("client-secret")
            .help(
                concat!(
                    "Client secret of the application. Can be retrieved",
                    "from the apps list in the LIN service account."
                )
            )
            .takes_value(true)
            .required(true)
        )
        .arg(
            Arg::with_name("permissions")
            .short("p")
            .long("permissions")
            .help("A list of permissions of the application.")
            .multiple(true)
            .takes_value(true)
            .default_value("r_ads")
        )
        .arg(
            Arg::with_name("redirect-url")
            .short("r")
            .long("redirect-url")
            .help(
                concat!(
                    "Redirect URL in 'https://{url}' format to which the needed",
                    "parameters for authentication",
                    "will be provided as query params."
                )
            )
            .takes_value(true)
            .default_value("https://localhost:8000")
        )
        .get_matches()
}


fn generate_csrf() -> String {
    let random_bytes: Vec<u8> = (0..256).map(|_| thread_rng().gen::<u8>()).collect();
    encode_config(&random_bytes, base64::URL_SAFE_NO_PAD)
}


fn request_access_key(client_id: &str, client_secret: &str,
                      auth_code: &str, redirect_url: &str, csrf: &str)
                        -> Result<String, Box<dyn Error>> {

    let response = Client::new()
        .get(ACCESS_TOKEN_URL)
        .query(
            &[("response_type", "code"), ("client_id", client_id),
              ("client_secret", client_secret), ("code", auth_code),
              ("redirect_uri", redirect_url), ("state", csrf),
              ("grant_type", "authorization_code")]
        )
        .send()?;

    let data: Value = response.json().unwrap();

    let data = match &data["access_token"] {
        Value::String(key) => key,
        _ => return Err(ValueError.into()),
    };
    Ok(data.clone())
}


fn generate_auth_code_url(client_id: &str, redirect_url: &str,
                          permissions: &Vec<&str>, csrf: &str)
                              -> Result<String, ReqError> {

    let permissions_str = permissions.join(" ");

    let response = Client::new()
        .get(AUTH_URL)
        .query(
            &[("response_type", "code"), ("client_id", client_id),
              ("redirect_uri", redirect_url), ("state", csrf), 
              ("scope", &permissions_str)]
        );

    let url = response.build()?.url().as_str().to_string();
    Ok(url)
}


fn controller(args: &ArgMatches) -> Result<(), Box<dyn Error>> {
    let csrf = generate_csrf();
    let client_id = args.value_of("client-id").unwrap();
    let redirect_url = args.value_of("redirect-url").unwrap();
    let permissions: Vec<&str> = args.values_of("permissions").unwrap().collect();
    let client_secret = args.value_of("client-secret").unwrap();

    let url = generate_auth_code_url(client_id, redirect_url,
                                     &permissions, &csrf)?;

    println!(
        "\nGenerated URL to request the LIN authorization code for your application:\n\n\
        {}\n\n\
        Please, proceed with it and sign in with your account. \
        After authorization, you'll be redirected to the page requested in CLI. \n\n\
        Please, copy the 'code' value from the request parameters and pass it here:\n",
        url
    );

    let mut authorization_code = String::new();
    io::stdin().read_line(&mut authorization_code)?;

    let access_key = request_access_key(client_id, client_secret,
                                        &authorization_code, redirect_url, &csrf)?;
    
    println!("\nAccess key retrieved successfuly:\n\n{}.\n\nYou can now use it.",
             access_key);
    Ok(())
}


fn main() {
    let jira_auth = cli();

    match controller(&jira_auth) {
        Ok(()) => {},
        Err(err) => eprintln!("\nApplication error: {}.", err)
    }
}
