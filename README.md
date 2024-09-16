# Auth-rs

This is a Rust implementation of the [supabase js auth client](https://github.com/supabase/gotrue-js). As of now, this is alpha software and breaking changes are a certainty. The goal is to have feature parity and an easy-to-use API. 

## Installation

### Cargo

```bash
cargo add supabase-auth 
```

## Differences to the JS client

It should be noted there are, and will likely always be, differences to the [JS client](https://github.com/supabase/gotrue-js). If something bothers you enough, contributions are welcome.

Any features which are currently deprecated in the [JS client](https://github.com/supabase/gotrue-js) will not be supported.

## Usage (Won't be updated until 1.0.0)

```rust

// We're doing cool stuff in here
```

## Features
- [x] Create Client
- [x] Sign In with Email & Password
- [x] Sign In with Phone & Password
- [x] Sign Up with Email & Password
- [x] Sign Up with Phone & Password
- [] Sign In with Third Party Auth (OAuth)
- [] Sign In with Magic Link 
- [x] Send Sign-In OTP (Email, SMS, Whatsapp)
- [] Sign In with OTP
- [] Refresh Session
- [] Resend OTP Tokens (Email & SMS)
- [x] Retrieve User
- [] Reset Password
- [] Change User Data (e.g., Email or password)
- [] SSO

## Contributions

Contributors are always welcome. I only ask that you add tests to cover any new functionality, and that any changes pass the existing tests before you put it on my plate. Until this crate reaches 1.0.0 we're in the "move fast and break things" phase. Don't concern yourself with elegance.
