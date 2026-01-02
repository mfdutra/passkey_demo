/**
 * Passkey Authentication Demo - Client-Side JavaScript
 *
 * This file implements the client-side WebAuthn logic for passwordless authentication.
 * It uses the browser's native WebAuthn API (navigator.credentials) to create and use passkeys.
 *
 * ## Key Concepts
 * - WebAuthn API: Browser API for passkey/FIDO2 authentication
 * - ArrayBuffer: Binary data format used by WebAuthn
 * - Base64url: Text encoding for binary data (URL-safe, no padding)
 * - Challenge: Random value from server that must be signed
 *
 * ## Security
 * - Private keys NEVER leave the user's device (phone, laptop, security key)
 * - Server only sees and stores public keys
 * - Each operation requires user interaction (Face ID, fingerprint, PIN)
 */

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Show a status message to the user
 *
 * @param {string} message - The message to display
 * @param {boolean} isError - Whether this is an error (red) or success (green)
 */
function showStatus(message, isError = false) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = 'status ' + (isError ? 'error' : 'success');
    status.style.display = 'block';

    // Auto-hide after 5 seconds
    setTimeout(() => {
        status.style.display = 'none';
    }, 5000);
}

/**
 * Convert base64url string to ArrayBuffer
 *
 * WebAuthn uses ArrayBuffers (binary data) but we send/receive them as
 * base64url strings over HTTP. This function converts back to binary.
 *
 * ## Base64url vs Base64
 * - base64url is URL-safe (uses - and _ instead of + and /)
 * - base64url has no padding (no = at the end)
 * - Standard for WebAuthn to avoid encoding issues
 *
 * ## Process
 * 1. Replace base64url characters with standard base64
 * 2. Add padding if needed
 * 3. Decode base64 to binary string using atob()
 * 4. Convert binary string to Uint8Array
 * 5. Return as ArrayBuffer
 *
 * @param {string} base64url - Base64url encoded string
 * @returns {ArrayBuffer} - Binary data
 */
function base64urlToBuffer(base64url) {
    // Convert base64url to standard base64
    // Replace URL-safe characters with standard base64 characters
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding (base64url removes it, standard base64 needs it)
    // Base64 strings must be multiples of 4 characters
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');

    // Decode base64 to binary string
    // atob() is a browser function: ASCII to Binary
    const binary = atob(padded);

    // Convert binary string to byte array
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    // Return as ArrayBuffer (WebAuthn expects this type)
    return bytes.buffer;
}

/**
 * Convert ArrayBuffer to base64url string
 *
 * WebAuthn returns data as ArrayBuffers. We need to convert to base64url
 * to send over HTTP as JSON.
 *
 * ## Process
 * 1. Convert ArrayBuffer to Uint8Array
 * 2. Convert bytes to binary string
 * 3. Encode to base64 using btoa()
 * 4. Convert standard base64 to base64url format
 *
 * @param {ArrayBuffer} buffer - Binary data
 * @returns {string} - Base64url encoded string
 */
function bufferToBase64url(buffer) {
    // Convert ArrayBuffer to Uint8Array (array of bytes)
    const bytes = new Uint8Array(buffer);

    // Build binary string from bytes
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    // Encode to base64 and convert to base64url format
    // btoa() is a browser function: Binary to ASCII
    // Then replace standard base64 characters with URL-safe ones
    // and remove padding
    return btoa(binary)
        .replace(/\+/g, '-')    // Replace + with -
        .replace(/\//g, '_')    // Replace / with _
        .replace(/=/g, '');     // Remove padding
}

// ============================================================================
// Registration Flow
// ============================================================================

/**
 * Register a new passkey for a user
 *
 * This function implements the complete passkey registration flow:
 * 1. Ask server for registration challenge
 * 2. Prompt user to create credential with their authenticator
 * 3. Send credential back to server for verification
 *
 * ## What happens on the device?
 * - User is prompted to authenticate (Face ID, fingerprint, PIN, etc.)
 * - Device generates a new public/private key pair
 * - Private key is stored securely on device (never leaves it!)
 * - Public key and signed data sent to server
 *
 * ## WebAuthn API
 * navigator.credentials.create() is the browser's WebAuthn API
 * It returns a credential containing the public key
 */
async function register() {
    // Get form values
    const username = document.getElementById('reg-username').value;
    const displayName = document.getElementById('reg-displayname').value;

    // Validate input
    if (!username || !displayName) {
        showStatus('Please fill in all fields', true);
        return;
    }

    try {
        // ====================================================================
        // Step 1: Request registration challenge from server
        // ====================================================================
        showStatus('Starting registration...');
        const startResp = await fetch('/api/auth/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, display_name: displayName })
        });

        if (!startResp.ok) {
            const error = await startResp.json();
            throw new Error(error.error || 'Registration failed');
        }

        // Get the challenge from server
        // This contains:
        // - challenge: Random bytes to sign
        // - user info: ID, name, display name
        // - RP info: Relying Party (our server) details
        // - pubKeyCredParams: Which algorithms are acceptable
        const creationOptions = await startResp.json();

        // Save user ID for later (we need it for the finish step)
        // It comes as base64url, we decode then re-encode to keep it consistent
        const userId = bufferToBase64url(base64urlToBuffer(creationOptions.publicKey.user.id));

        // Convert base64url strings to ArrayBuffers
        // The server sends data as base64url strings (text)
        // WebAuthn API expects ArrayBuffers (binary)
        creationOptions.publicKey.challenge = base64urlToBuffer(creationOptions.publicKey.challenge);
        creationOptions.publicKey.user.id = base64urlToBuffer(creationOptions.publicKey.user.id);

        // ====================================================================
        // Step 2: Create credential using WebAuthn API
        // ====================================================================
        showStatus('Please use your authenticator...');

        // This is where the magic happens!
        // navigator.credentials.create() will:
        // 1. Prompt the user to authenticate (Face ID, fingerprint, etc.)
        // 2. Generate a new key pair on the device
        // 3. Sign the challenge with the private key
        // 4. Return a credential containing the public key
        //
        // The private key NEVER leaves the device!
        const credential = await navigator.credentials.create(creationOptions);

        // ====================================================================
        // Step 3: Send credential to server for verification
        // ====================================================================

        // Convert the credential to JSON format for sending
        // The credential contains ArrayBuffers which can't be sent as JSON
        // So we convert all ArrayBuffers to base64url strings
        const credentialJSON = {
            id: credential.id,  // Credential ID (string)
            rawId: bufferToBase64url(credential.rawId),  // Raw credential ID (bytes → base64url)
            type: credential.type,  // Always "public-key" for WebAuthn
            response: {
                // Client data: contains challenge, origin, type
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                // Attestation: contains authenticator data and public key
                attestationObject: bufferToBase64url(credential.response.attestationObject)
            }
        };

        // Send credential to server for verification
        const finishResp = await fetch('/api/auth/register/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId,
                credential: credentialJSON
            })
        });

        if (!finishResp.ok) {
            const error = await finishResp.json();
            throw new Error(error.error || 'Registration completion failed');
        }

        // Success! The server has verified and stored the public key
        showStatus('✅ Registration successful! You can now login.');
        document.getElementById('register-form').reset();

    } catch (error) {
        console.error('Registration error:', error);
        showStatus('❌ ' + error.message, true);
    }
}

// ============================================================================
// Authentication Flow
// ============================================================================

/**
 * Authenticate (log in) with an existing passkey
 *
 * This function implements the complete passkey authentication flow:
 * 1. Ask server for authentication challenge
 * 2. Prompt user to sign challenge with their authenticator
 * 3. Send signed assertion to server for verification
 *
 * ## What happens on the device?
 * - User is prompted to authenticate (Face ID, fingerprint, PIN, etc.)
 * - Device uses the private key to sign the challenge
 * - Signed data sent to server (private key never leaves device!)
 * - Server verifies signature with stored public key
 *
 * ## WebAuthn API
 * navigator.credentials.get() is the browser's WebAuthn API for authentication
 * It returns an assertion (signed challenge)
 */
async function authenticate() {
    // Get form value
    const username = document.getElementById('auth-username').value;

    // Validate input
    if (!username) {
        showStatus('Please enter your username', true);
        return;
    }

    try {
        // ====================================================================
        // Step 1: Request authentication challenge from server
        // ====================================================================
        showStatus('Starting authentication...');
        const startResp = await fetch('/api/auth/authenticate/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!startResp.ok) {
            const error = await startResp.json();
            throw new Error(error.error || 'Authentication failed');
        }

        // Get the challenge from server
        // This contains:
        // - challenge: Random bytes to sign
        // - allowCredentials: Which passkeys can be used
        // - RP ID: Must match the domain
        // - timeout: How long user has to respond
        const requestOptions = await startResp.json();

        // Convert base64url strings to ArrayBuffers
        // Challenge: the random bytes to sign
        requestOptions.publicKey.challenge = base64urlToBuffer(requestOptions.publicKey.challenge);

        // Allowed credentials: list of credential IDs the user can use
        // Each credential ID must be converted from base64url to ArrayBuffer
        requestOptions.publicKey.allowCredentials = requestOptions.publicKey.allowCredentials.map(cred => ({
            ...cred,  // Keep type and transports
            id: base64urlToBuffer(cred.id)  // Convert ID to ArrayBuffer
        }));

        // ====================================================================
        // Step 2: Get assertion using WebAuthn API
        // ====================================================================
        showStatus('Please use your authenticator...');

        // This is where the magic happens!
        // navigator.credentials.get() will:
        // 1. Prompt the user to authenticate (Face ID, fingerprint, etc.)
        // 2. Find the private key matching one of the allowed credentials
        // 3. Sign the challenge with the private key
        // 4. Return an assertion (signed challenge + metadata)
        //
        // The private key NEVER leaves the device!
        const assertion = await navigator.credentials.get(requestOptions);

        // ====================================================================
        // Step 3: Send assertion to server for verification
        // ====================================================================

        // Convert the assertion to JSON format for sending
        // The assertion contains ArrayBuffers which can't be sent as JSON
        // So we convert all ArrayBuffers to base64url strings
        const assertionJSON = {
            id: assertion.id,  // Credential ID that was used (string)
            rawId: bufferToBase64url(assertion.rawId),  // Raw credential ID (bytes → base64url)
            type: assertion.type,  // Always "public-key" for WebAuthn
            response: {
                // Client data: contains challenge, origin, type
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                // Authenticator data: contains RP ID hash, flags, counter
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                // Signature: cryptographic proof using private key
                signature: bufferToBase64url(assertion.response.signature),
                // User handle: identifies which user (may be null if not needed)
                userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
            }
        };

        // Extract user ID from userHandle
        // This identifies which user is authenticating
        const userIdBuffer = assertion.response.userHandle;
        const userId = userIdBuffer ? bufferToBase64url(userIdBuffer) : '';

        // Send assertion to server for verification
        const finishResp = await fetch('/api/auth/authenticate/finish', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                user_id: userId,
                credential: assertionJSON
            })
        });

        if (!finishResp.ok) {
            const error = await finishResp.json();
            throw new Error(error.error || 'Authentication completion failed');
        }

        // Success! The server has verified the signature
        // A session cookie is set by the server
        const result = await finishResp.json();
        showStatus('✅ Login successful!');
        document.getElementById('login-form').reset();

        // Update UI to show logged-in state
        await checkSession();

    } catch (error) {
        console.error('Authentication error:', error);
        showStatus('❌ ' + error.message, true);
    }
}

// ============================================================================
// Session Management
// ============================================================================

/**
 * Log out the current user
 *
 * Calls the server to delete the session, then updates the UI
 * to show the logged-out state.
 */
async function logout() {
    try {
        const resp = await fetch('/api/auth/logout', { method: 'POST' });
        if (resp.ok) {
            showStatus('Logged out successfully');

            // Update UI to show logged-out state
            // Hide user info section
            document.getElementById('session-info').classList.add('hidden');
            // Show registration and login forms
            document.getElementById('registration-section').classList.remove('hidden');
            document.getElementById('authentication-section').classList.remove('hidden');
        }
    } catch (error) {
        console.error('Logout error:', error);
        showStatus('Logout failed', true);
    }
}

/**
 * Check if user is logged in
 *
 * Queries the server to check session status.
 * If logged in, fetches and displays user profile.
 *
 * Called on page load to restore session after page refresh.
 */
async function checkSession() {
    try {
        // Check session status
        const resp = await fetch('/api/auth/session');
        const session = await resp.json();

        if (session.authenticated) {
            // User is logged in!
            // Fetch full user profile from protected endpoint
            const userResp = await fetch('/api/users/me');
            if (userResp.ok) {
                const user = await userResp.json();

                // Display user information
                document.getElementById('user-details').innerHTML = `
                    <p><strong>Username:</strong> ${user.username}</p>
                    <p><strong>Display Name:</strong> ${user.display_name}</p>
                    <p><strong>User ID:</strong> ${user.id}</p>
                `;

                // Update UI to show logged-in state
                // Show user info section
                document.getElementById('session-info').classList.remove('hidden');
                // Hide registration and login forms
                document.getElementById('registration-section').classList.add('hidden');
                document.getElementById('authentication-section').classList.add('hidden');
            }
        }
        // If not authenticated, UI already shows registration/login forms
    } catch (error) {
        console.error('Session check error:', error);
    }
}

// ============================================================================
// Initialization
// ============================================================================

// Check session on page load
// This restores the logged-in state if the user refreshes the page
checkSession();
