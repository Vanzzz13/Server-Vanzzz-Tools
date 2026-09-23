# Vanzzz Tools Server v3.0.0

Server gabungan WA Gateway + Auth + Saldo.

## Deploy ke Railway
1. Upload folder ini ke GitHub
2. Connect repo ke Railway
3. Railway otomatis detect package.json dan jalankan `npm start`

## Endpoint utama
- POST /api/auth/register
- POST /api/auth/login
- POST /api/sender/add (tambah sender pribadi)
- POST /api/sender/add-global (tambah global sender)
- GET  /api/sender/qr/:number (ambil QR code)
- POST /api/spam/message
- POST /api/spam/fake-voice
- POST /api/spam/fake-pdf
- POST /api/spam/fake-image
- POST /api/balance/redeem
- POST /api/balance/buy-feature
