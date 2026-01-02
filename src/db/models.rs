//! # Database Models
//!
//! This module defines the data structures that map to database tables.
//! These structs represent rows in the database and include serialization/deserialization
//! for JSON APIs and database mapping.
//!
//! ## Key Concepts
//! - **ORM (Object-Relational Mapping)**: These structs map to database tables
//! - **Serialization**: Converting Rust structs to/from JSON
//! - **UUIDs**: Universally Unique Identifiers for database primary keys

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize}; // For JSON conversion
use uuid::Uuid; // For generating unique IDs

/// User account information
///
/// Represents a user in the system. Each user can have multiple passkey credentials.
///
/// ## Derive Macros Explained
/// - `Debug`: Allows printing with {:?} for debugging
/// - `Clone`: Allows creating copies of the struct
/// - `Serialize`: Converts struct to JSON (for API responses)
/// - `Deserialize`: Converts JSON to struct (for API requests)
/// - `sqlx::FromRow`: Automatically maps database rows to this struct
///
/// ## Why Strings for dates?
/// We use String instead of DateTime<Utc> because:
/// - SQLite stores timestamps as text (RFC3339 format)
/// - Simpler serialization to JSON
/// - In production, you might use proper DateTime types with sqlx chrono support
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    /// Unique identifier (UUID v4)
    /// Example: "550e8400-e29b-41d4-a716-446655440000"
    pub id: String,

    /// Unique username for the user
    /// Used for login/lookup
    pub username: String,

    /// Human-readable display name
    /// Shown to the user during passkey creation
    pub display_name: String,

    /// When the user account was created (RFC3339 timestamp)
    /// Example: "2024-01-15T10:30:00Z"
    pub created_at: String,

    /// When the user account was last updated (RFC3339 timestamp)
    pub updated_at: String,
}

impl User {
    /// Create a new user with generated ID and timestamps
    ///
    /// This constructor:
    /// 1. Generates a random UUID for the user ID
    /// 2. Sets both created_at and updated_at to the current time
    /// 3. Stores the provided username and display_name
    ///
    /// ## Example
    /// ```rust
    /// let user = User::new("alice".to_string(), "Alice Smith".to_string());
    /// println!("Created user with ID: {}", user.id);
    /// ```
    pub fn new(username: String, display_name: String) -> Self {
        // Get current time in RFC3339 format (ISO 8601)
        // Example: "2024-01-15T10:30:00+00:00"
        let now = Utc::now().to_rfc3339();

        Self {
            // Generate a new random UUID version 4
            // This ensures globally unique IDs without coordination
            id: Uuid::new_v4().to_string(),
            username,
            display_name,
            // Clone the timestamp string for both fields
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

/// Passkey credential stored for a user
///
/// This represents a registered WebAuthn/passkey credential. Each credential
/// contains the public key and metadata needed to verify authentication attempts.
///
/// ## What is stored?
/// - **Public Key**: Used to verify cryptographic signatures during authentication
/// - **Counter**: Prevents replay attacks (increments with each use)
/// - **Metadata**: Transport methods, backup state, attestation info
///
/// ## Security Note
/// We only store the PUBLIC key, never the private key. The private key stays
/// on the user's device (phone, security key, etc.) and never leaves it.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PasskeyCredential {
    /// Unique credential identifier
    /// This ID is returned by the WebAuthn API during registration
    pub id: String,

    /// ID of the user who owns this credential
    /// Foreign key to users table
    pub user_id: String,

    /// Serialized public key (as bytes)
    /// In this implementation, we store the entire Passkey object serialized
    /// This includes the public key and other WebAuthn metadata
    /// Vec<u8> = byte array, stored as BLOB in SQLite
    pub credential_public_key: Vec<u8>,

    /// Signature counter
    /// Increments each time the credential is used for authentication
    /// Used to detect cloned credentials (replay attack prevention)
    /// If the counter goes backwards, the credential may be compromised
    pub counter: i64,

    /// Supported transports (optional, JSON string)
    /// Examples: "usb", "nfc", "ble", "internal"
    /// Stored as JSON string: ["usb", "nfc"]
    pub transports: Option<String>,

    /// Whether the credential is eligible for backup
    /// True if the credential can be synced across devices
    /// (e.g., iCloud Keychain, Google Password Manager)
    pub backup_eligible: bool,

    /// Whether the credential is currently backed up
    /// True if the credential is synced to cloud
    pub backup_state: bool,

    /// Attestation format (optional)
    /// Describes how the authenticator proved its authenticity
    /// Examples: "packed", "fido-u2f", "none"
    pub attestation_format: Option<String>,

    /// Attestation data (optional, as bytes)
    /// Cryptographic proof of the authenticator's authenticity
    pub attestation_data: Option<Vec<u8>>,

    /// When the credential was created (RFC3339 timestamp)
    pub created_at: String,

    /// When the credential was last used for authentication (optional)
    /// Updated each time the user logs in with this credential
    pub last_used_at: Option<String>,
}

/// Registration challenge for passkey creation
///
/// When a user starts registering a passkey, the server generates a cryptographic
/// challenge. The challenge must be completed within a short time window (5 minutes).
///
/// ## Why challenges?
/// - **Prevent replay attacks**: Each registration is unique
/// - **Prove freshness**: Ensures the client is responding to a current request
/// - **Security**: Random, unpredictable challenges prevent prediction attacks
///
/// ## Challenge Lifecycle
/// 1. Server creates challenge → stored in database
/// 2. Client receives challenge → creates credential with authenticator
/// 3. Client returns signed response → server verifies against stored challenge
/// 4. If valid → save credential, delete challenge
/// 5. If expired → reject, user must restart
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RegistrationChallenge {
    /// Unique challenge identifier (UUID)
    pub id: String,

    /// ID of the user registering a new credential
    /// Foreign key to users table
    pub user_id: String,

    /// Serialized challenge state (as bytes)
    /// Contains the cryptographic challenge and other state needed for verification
    /// This is the PasskeyRegistration struct from webauthn-rs, serialized
    pub challenge_state: Vec<u8>,

    /// When the challenge was created (RFC3339 timestamp)
    pub created_at: String,

    /// When the challenge expires (RFC3339 timestamp)
    /// Default: 5 minutes from creation
    /// After this time, the challenge cannot be used
    pub expires_at: String,
}

impl RegistrationChallenge {
    /// Create a new registration challenge with auto-generated expiry
    ///
    /// This constructor:
    /// 1. Generates a unique ID for the challenge
    /// 2. Stores the user ID and serialized challenge state
    /// 3. Sets expiration to 5 minutes from now
    ///
    /// ## Security Note
    /// Short expiration windows (5 minutes) reduce the attack window.
    /// If a challenge is stolen, it's only useful for a short time.
    pub fn new(user_id: String, challenge_state: Vec<u8>) -> Self {
        let now = Utc::now();
        // Set expiration to 5 minutes from now
        // This is a security best practice - short-lived challenges
        let expires = now + chrono::Duration::minutes(5);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            challenge_state,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        }
    }
}

/// Authentication challenge for passkey login
///
/// When a user tries to log in, the server generates a challenge that must be
/// signed by the user's authenticator. Similar to registration challenges but
/// used for login instead of credential creation.
///
/// ## Authentication Flow
/// 1. User enters username
/// 2. Server looks up user's credentials
/// 3. Server creates challenge → stored in database
/// 4. Client receives challenge and list of allowed credentials
/// 5. User interacts with authenticator (Face ID, Touch ID, security key)
/// 6. Authenticator signs the challenge with private key
/// 7. Client returns signed response → server verifies signature
/// 8. If valid → create session, delete challenge
///
/// ## Why separate from registration challenges?
/// - Different cryptographic operations (assertion vs attestation)
/// - Different state data (allowed credentials vs registration options)
/// - Clearer code separation and database queries
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuthenticationChallenge {
    /// Unique challenge identifier (UUID)
    pub id: String,

    /// ID of the user trying to authenticate
    /// Foreign key to users table
    pub user_id: String,

    /// Serialized challenge state (as bytes)
    /// Contains the cryptographic challenge and authentication state
    /// This is the PasskeyAuthentication struct from webauthn-rs, serialized
    pub challenge_state: Vec<u8>,

    /// When the challenge was created (RFC3339 timestamp)
    pub created_at: String,

    /// When the challenge expires (RFC3339 timestamp)
    /// Default: 5 minutes from creation
    pub expires_at: String,
}

impl AuthenticationChallenge {
    /// Create a new authentication challenge with auto-generated expiry
    ///
    /// Same pattern as RegistrationChallenge but for authentication.
    /// Challenges expire after 5 minutes for security.
    pub fn new(user_id: String, challenge_state: Vec<u8>) -> Self {
        let now = Utc::now();
        // 5 minute expiration - balance between security and user experience
        // Too short: users might not complete login in time
        // Too long: larger attack window if challenge is intercepted
        let expires = now + chrono::Duration::minutes(5);

        Self {
            id: Uuid::new_v4().to_string(),
            user_id,
            challenge_state,
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
        }
    }
}
