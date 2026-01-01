# Passkey Authentication Server

A Rust-based web server prototype demonstrating passwordless authentication using WebAuthn/FIDO2 passkeys.

## Features

- 🔐 **Passwordless Authentication** - Secure login using biometrics or security keys
- 🚀 **Modern Stack** - Built with Axum, SQLite, and webauthn-rs
- 🎨 **Demo UI** - Interactive frontend for testing passkey registration and authentication
- 🔒 **Secure** - Follows WebAuthn standards with proper challenge management
- 📦 **Self-contained** - Single binary with embedded frontend

## Technology Stack

- **Web Framework**: Axum 0.8
- **Database**: SQLite with SQLx
- **WebAuthn**: webauthn-rs 0.5 (security audited)
- **Sessions**: tower-sessions with SQLite store
- **Frontend**: Vanilla HTML/CSS/JavaScript with WebAuthn API

## Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- A WebAuthn-compatible browser (Chrome, Firefox, Safari, or Edge)
- A compatible authenticator (Touch ID, Face ID, Windows Hello, or hardware security key)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd passkey
cp .env.example .env
```

### 2. Build and Run

```bash
cargo build --release
cargo run --release
```

The server will start on `http://localhost:8080`

### 3. Try It Out

1. Open your browser to `http://localhost:8080`
2. **Register**: Create a new account with a passkey
   - Enter a username (e.g., `alice@example.com`)
   - Enter a display name (e.g., `Alice Smith`)
   - Click "Register with Passkey"
   - Follow your browser's prompts to create a passkey
3. **Login**: Authenticate with your passkey
   - Enter your username
   - Click "Login with Passkey"
   - Authorize with your authenticator

## Configuration

Edit `.env` to customize settings:

```env
# Server Configuration
HOST=127.0.0.1
PORT=8080

# Database
DATABASE_URL=sqlite:passkey.db?mode=rwc

# WebAuthn Configuration
RP_ID=localhost
RP_ORIGIN=http://localhost:8080
RP_NAME=Passkey Demo

# Logging
RUST_LOG=info,passkey_auth_server=debug
```

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/register/start` - Begin passkey registration
- `POST /api/auth/register/finish` - Complete passkey registration
- `POST /api/auth/authenticate/start` - Begin authentication
- `POST /api/auth/authenticate/finish` - Complete authentication
- `POST /api/auth/logout` - Logout (clear session)
- `GET /api/auth/session` - Get current session info

### User Management

- `GET /api/users/me` - Get current user info (protected)

### Health

- `GET /health` - Server health check

## Architecture

```
passkey-auth-server/
├── src/
│   ├── main.rs                 # Server entry point
│   ├── config.rs               # Configuration management
│   ├── state.rs                # App state (DB, WebAuthn)
│   ├── error.rs                # Error handling
│   ├── db/                     # Database layer
│   │   ├── models.rs           # Data models
│   │   ├── users.rs            # User operations
│   │   ├── credentials.rs      # Credential operations
│   │   └── challenges.rs       # Challenge management
│   ├── webauthn/               # WebAuthn logic
│   │   ├── registration.rs     # Registration flow
│   │   ├── authentication.rs   # Authentication flow
│   │   └── types.rs            # Request/response types
│   ├── handlers/               # HTTP handlers
│   │   ├── auth.rs             # Auth endpoints
│   │   ├── users.rs            # User endpoints
│   │   └── health.rs           # Health check
│   └── middleware/
│       └── auth.rs             # Auth middleware
├── static/                     # Frontend files
│   ├── index.html
│   ├── app.js
│   └── style.css
└── migrations/                 # Database migrations
    └── 001_initial_schema.sql
```

## Security Features

### Implemented

- ✅ Server-side challenge storage (not in cookies)
- ✅ Automatic challenge expiration (5 minutes)
- ✅ Signature counter tracking for clone detection
- ✅ Proper session management with expiration
- ✅ CORS configuration for local development
- ✅ Input validation
- ✅ Secure error messages (no information leakage)

### Production Recommendations

For production deployment, ensure:

- [ ] Use HTTPS (required for WebAuthn)
- [ ] Configure proper domain in RP_ID and RP_ORIGIN
- [ ] Enable secure cookie flags
- [ ] Implement rate limiting
- [ ] Add monitoring and alerting
- [ ] Restrict CORS to your domain
- [ ] Regular security audits
- [ ] Database backups

## Database Schema

The server uses SQLite with the following tables:

- **users** - User accounts
- **passkey_credentials** - Stored passkey credentials
- **registration_challenges** - Temporary registration state
- **authentication_challenges** - Temporary auth state
- **sessions** - Session data

Challenges are automatically cleaned up every 10 minutes.

## Development

### Running Tests

```bash
cargo test
```

### Building for Production

```bash
cargo build --release
./target/release/passkey-auth-server
```

### Logging

Set `RUST_LOG` environment variable for logging control:

```bash
RUST_LOG=debug cargo run
```

## Browser Compatibility

| Browser | Platform | Support |
|---------|----------|---------|
| Chrome/Edge | All | ✅ Full |
| Firefox | All | ✅ Full |
| Safari | macOS/iOS | ✅ Full |

## Troubleshooting

### "WebAuthn not supported"

- Ensure you're using a modern browser
- For localhost, HTTP is allowed. For other domains, HTTPS is required

### "Registration failed"

- Check that your authenticator is working
- Try clearing browser data and re-registering
- Check server logs for detailed errors

### Database errors

- Ensure the database file is writable
- Check `DATABASE_URL` in `.env`
- Try deleting `passkey.db` to start fresh

## Resources

- [WebAuthn Guide](https://webauthn.guide/)
- [webauthn-rs Documentation](https://docs.rs/webauthn-rs/)
- [W3C WebAuthn Specification](https://www.w3.org/TR/webauthn-2/)
- [FIDO Alliance](https://fidoalliance.org/)

## License

MIT

## Contributing

This is a prototype/demo project. Feel free to fork and adapt for your needs!

## Acknowledgments

- Built with [webauthn-rs](https://github.com/kanidm/webauthn-rs) by the Kanidm team
- Powered by [Axum](https://github.com/tokio-rs/axum) web framework
- Uses [SQLx](https://github.com/launchbadge/sqlx) for type-safe SQL

---

**Note**: This is a demonstration project for learning purposes. For production use, conduct a thorough security review and follow best practices for your specific requirements.
