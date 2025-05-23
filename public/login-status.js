// login-status.js
(async () => {
    // DOM refs
    const statusEl   = document.getElementById('login-status');
    const deviceEl   = document.getElementById('device-id');
    const sessionsEl = document.getElementById('sessions-list');

    // grab creds
    const sessionId = localStorage.getItem('session_id');
    const deviceId  = localStorage.getItem('device_id');
    const secretHex = localStorage.getItem('shared_secret');
    if (!sessionId || !deviceId || !secretHex) {
        return window.location.replace('/login');
    }

    // prepare HMAC
    const ts      = Date.now().toString();
    const path    = '/a/status';
    const payload = `${ts}|GET|${path}|${sessionId}`;

    function hexToArrayBuffer(hex) {
        const buf = new Uint8Array(hex.length/2);
        for (let i = 0; i < hex.length; i += 2) {
            buf[i/2] = parseInt(hex.substr(i,2),16);
        }
        return buf.buffer;
    }

    async function sign(secret, text) {
        const key = await crypto.subtle.importKey(
            'raw',
            hexToArrayBuffer(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        const sig = await crypto.subtle.sign(
            'HMAC',
            key,
            new TextEncoder().encode(text)
        );
        return Array.from(new Uint8Array(sig))
            .map(b => b.toString(16).padStart(2,'0'))
            .join('');
    }

    // sign + fetch
    const signature = await sign(secretHex, payload);
    const res = await fetch(path, {
        method: 'GET',
        headers: {
            'x-session-id': sessionId,
            'x-device-id':  deviceId,
            'x-timestamp':  ts,
            'x-signature':  signature
        }
    });

    if (!res.ok) {
        console.error('Status fetch failed', res.status);
        return window.location.replace('/login');
    }

    const data = await res.json();
    if (!data.loggedIn) {
        return window.location.replace('/login');
    }

    // render
    statusEl.innerHTML         = `<p>Logged in as <b>${data.username}</b></p>`;
    deviceEl.textContent         = deviceId;
    sessionsEl.innerHTML         = data.sessions
        .map(sid => `<li>${sid}</li>`)
        .join('');
})();

