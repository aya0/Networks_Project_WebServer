# Networks_Project_WebServer

# ENCS3320 – Tiny Webserver (Socket Programming Project)

This project implements a simple yet complete HTTP web server using **raw socket programming** without any web frameworks. The server listens on **port 8099** and supports serving static files, handling redirects, user login/registration, and session management.

---

## 🚀 Features

- Prints all incoming HTTP requests in the terminal  
- Serves static files with correct MIME types:
  - `.html` → `text/html`
  - `.css` → `text/css`
  - `.jpg` → `image/jpeg`
  - `.png` → `image/png`
- Supports English and Arabic homepages:
  - `/` or `/en` → `main_en.html`
  - `/ar` → `main_ar.html`
- Implements **HTTP 307 Temporary Redirect** for:
  - `/chat` → ChatGPT  
  - `/cf` → Cloudflare  
  - `/rt` → Ritaj  
- Custom **404 Not Found** error page with:
  - Client IP + port
  - Group names & IDs
- **User Registration**:
  - Stores username + SHA-256 hashed password in `data.txt`
- **User Login & Sessions**:
  - Validates hashed password
  - Generates unique session ID
  - Sends session in cookies
  - Grants access to `protected.html`
  - Logout removes session from memory

---

## 🧠 How It Works

1. Browser sends an HTTP request to `http://localhost:8099/`
2. The server parses HTTP/1.1 headers manually.
3. Based on the path, the server:
   - Serves HTML/CSS/images  
   - Redirects using status code `307`  
   - Returns a custom 404 page  
4. Login system:
   - Hashes passwords using SHA-256
   - Stores them in `data.txt`
5. Sessions:
   - Server generates a session ID
   - Stores it in memory
   - Sends it as a cookie
   - Cookie is validated for protected pages

---

## 📂 Project Structure (Example)

