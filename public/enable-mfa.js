// enable-mfa.js
document.getElementById('enableMfaForm').addEventListener('submit', async e => {
    e.preventDefault();
    try {
        const res = await fetch('/a/enable-mfa', {
            method: 'POST',
            credentials: 'include'
        });
        const data = await res.json();
        if (!data.qr) {
            alert(data.message || 'Failed to generate QR');
            return;
        }

        const qrContainer = document.getElementById('qrContainer');
        const qrImage = document.getElementById('qrImage');

        qrImage.src = data.qr;
        qrContainer.style.display = 'block';
    } catch (err) {
        console.error(err);
        alert('An error occurred while enabling MFA');
    }
});
