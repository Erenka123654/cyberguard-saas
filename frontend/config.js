// Backend API adresini burada ayarla.
// Yerel geliştirme için FastAPI'yi doğrudan kullanıyorsan:
//   const API_BASE = "http://127.0.0.1:8000";
// Cloudflare Worker gateway üzerinden gidiyorsan (önerilen, prod için):
//   const API_BASE = "https://cyberguard-api.<senin-subdomain>.workers.dev";
// Kendi domain'ini bağladıysan:
//   const API_BASE = "https://api.seninsirketin.com";
const API_BASE = "http://127.0.0.1:8000";
