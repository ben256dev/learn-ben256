// login.js
import { reset_animation } from './animation.js';

(async () => {
    const form       = document.getElementById('loginForm');
    const otp_input  = document.getElementById('otp');
    const error_message  = document.getElementById('error-message');

    // generate ECDH keys
    const key_pair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveBits']
    );
    const raw_pub = await crypto.subtle.exportKey('raw', key_pair.publicKey);
    const client_pub = Array.from(new Uint8Array(raw_pub))
        .map(b => b.toString(16).padStart(2,'0'))
        .join('');

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const username = form.username.value;
        const password = form.password.value;

        const body = { username, password, client_pub };
        // include otp if shown
        if (otp_input.style.display === 'block')
            body.otp = otp_input.value;

        const resp = await fetch('/a/login', {
            method: 'POST',
            headers: { 'Content-Type':'application/json' },
            body: JSON.stringify(body)
        });

        const data = await resp.json();
        if (!data.success) {
            if (data.message === 'MFA code required for new device') {
                otp_input.style.display = 'block';
                return alert('Please enter your 6-digit code');
            }

            error_message.style.display = "block";
            error_message.textContent = data.message;

            reset_animation(error_message);

            return
        }

        error_message.style.display = "none";

        // on success, derive shared secret & redirect:
        const server_pub_buf = hex_to_array_buffer(data.server_pub);
        const server_key     = await crypto.subtle.importKey(
            'raw',
            server_pub_buf,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );
        const shared_bits = await crypto.subtle.deriveBits(
            { name:'ECDH', public: server_key },
            key_pair.privateKey,
            256
        );
        const shared_hex = Array.from(new Uint8Array(shared_bits))
            .map(b => b.toString(16).padStart(2,'0'))
            .join('');

        localStorage.setItem('session_id', data.session_id);
        localStorage.setItem('device_id', data.device_id);
        localStorage.setItem('shared_secret', shared_hex);

        window.location.replace('/');
    });

    function hex_to_array_buffer(hex) {
        const buf = new Uint8Array(hex.length/2);
        for (let i = 0; i < hex.length; i += 2) {
            buf[i/2] = parseInt(hex.substr(i,2),16);
        }
        return buf.buffer;
    }
})();
