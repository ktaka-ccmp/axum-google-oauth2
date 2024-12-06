# axum google oauth2 example

- [What is in this Repository](#what-is-in-this-repository)
- [How to use App](#how-to-use-app)

## What is in this Repository

An example implementation of Google OAuth2/OIDC authentication for Axum.
This was inspired by [example implimentation for discord](https://github.com/tokio-rs/axum/blob/main/examples/oauth/src/main.rs).

I wrote [a blog post](https://ktaka.blog.ccmp.jp/2024/12/axum-google-oauth2oidc-implementation.html) about this repository.

https://github.com/user-attachments/assets/64d5265d-13fe-4aba-a82c-91234ab2f9b8

## How to use App

- Obtain Client ID and Client Secret from Google <https://console.cloud.google.com/apis/credentials>
- Add "https://localhost:3443/auth/authorized" to "Authorized redirect URIs"
  - You can replace `localhost:3443` with your host's FQDN
  - You can also use ngrok hostname
- Edit .env file

```text
CLIENT_ID=$client_id
CLIENT_SECRET=$client_secret
ORIGIN='https://localhost:3443'

#(Optional: Run ngrok by `ngrok http 3000`)
#ORIGIN="https://xxxxx.ngrok-free.app"
```

- Start the application

```text
cargo run
```
