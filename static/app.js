// Status display helper
function showStatus(message, isError = false) {
    const status = document.getElementById('status');
    status.textContent = message;
    status.className = 'status ' + (isError ? 'error' : 'success');
    status.style.display = 'block';
    setTimeout(() => {
        status.style.display = 'none';
    }, 5000);
}

// Convert base64url to ArrayBuffer
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Convert ArrayBuffer to base64url
function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Registration function
async function register() {
    const username = document.getElementById('reg-username').value;
    const displayName = document.getElementById('reg-displayname').value;

    if (!username || !displayName) {
        showStatus('Please fill in all fields', true);
        return;
    }

    try {
        // Step 1: Start registration
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

        const creationOptions = await startResp.json();

        // Extract user ID for the finish step
        const userId = bufferToBase64url(base64urlToBuffer(creationOptions.publicKey.user.id));

        // Convert challenge and user ID from base64url to ArrayBuffer
        creationOptions.publicKey.challenge = base64urlToBuffer(creationOptions.publicKey.challenge);
        creationOptions.publicKey.user.id = base64urlToBuffer(creationOptions.publicKey.user.id);

        // Step 2: Create credential using WebAuthn API
        showStatus('Please use your authenticator...');
        const credential = await navigator.credentials.create(creationOptions);

        // Step 3: Finish registration
        const credentialJSON = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject)
            }
        };

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

        showStatus('✅ Registration successful! You can now login.');
        document.getElementById('register-form').reset();
    } catch (error) {
        console.error('Registration error:', error);
        showStatus('❌ ' + error.message, true);
    }
}

// Authentication function
async function authenticate() {
    const username = document.getElementById('auth-username').value;

    if (!username) {
        showStatus('Please enter your username', true);
        return;
    }

    try {
        // Step 1: Start authentication
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

        const requestOptions = await startResp.json();

        // Store user ID for later (we'll get it from the response)
        // Convert challenge and allowed credentials from base64url to ArrayBuffer
        requestOptions.publicKey.challenge = base64urlToBuffer(requestOptions.publicKey.challenge);
        requestOptions.publicKey.allowCredentials = requestOptions.publicKey.allowCredentials.map(cred => ({
            ...cred,
            id: base64urlToBuffer(cred.id)
        }));

        // Step 2: Get credential using WebAuthn API
        showStatus('Please use your authenticator...');
        const assertion = await navigator.credentials.get(requestOptions);

        // Step 3: Finish authentication
        const assertionJSON = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
            }
        };

        // We need to get the user ID - it should be in userHandle or we can fetch session
        const userIdBuffer = assertion.response.userHandle;
        const userId = userIdBuffer ? bufferToBase64url(userIdBuffer) : '';

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

// Logout function
async function logout() {
    try {
        const resp = await fetch('/api/auth/logout', { method: 'POST' });
        if (resp.ok) {
            showStatus('Logged out successfully');
            document.getElementById('session-info').classList.add('hidden');
            document.getElementById('registration-section').classList.remove('hidden');
            document.getElementById('authentication-section').classList.remove('hidden');
        }
    } catch (error) {
        console.error('Logout error:', error);
        showStatus('Logout failed', true);
    }
}

// Check session status
async function checkSession() {
    try {
        const resp = await fetch('/api/auth/session');
        const session = await resp.json();

        if (session.authenticated) {
            // User is logged in - fetch user details
            const userResp = await fetch('/api/users/me');
            if (userResp.ok) {
                const user = await userResp.json();
                document.getElementById('user-details').innerHTML = `
                    <p><strong>Username:</strong> ${user.username}</p>
                    <p><strong>Display Name:</strong> ${user.display_name}</p>
                    <p><strong>User ID:</strong> ${user.id}</p>
                `;
                document.getElementById('session-info').classList.remove('hidden');
                document.getElementById('registration-section').classList.add('hidden');
                document.getElementById('authentication-section').classList.add('hidden');
            }
        }
    } catch (error) {
        console.error('Session check error:', error);
    }
}

// Check session on page load
checkSession();
