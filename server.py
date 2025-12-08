import socket
import threading
import os
import urllib.parse
import hashlib
import uuid
import time

HOST = '0.0.0.0'
PORT = 8099
WWW_DIR = 'www'
DATA_FILE = 'data.txt'  
sessions = {}        

CONTENT_TYPES = {
    '.html': 'text/html',
    '.htm':  'text/html',
    '.css':  'text/css',
    '.js':   'application/javascript',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.txt':  'text/plain'
}

def log_request(client_addr, method, path, headers):
    print(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] {client_addr} {method} {path}")
    for k,v in headers.items():
        print(f"  {k}: {v}")

def read_file_safe(path, mode='rb'):
    try:
        with open(path, mode) as f:
            return f.read()
    except Exception as e:
        return None

def build_response(status_line, headers=None, body=b''):
    if headers is None:
        headers = {}
    header_lines = ''
    for k, v in headers.items():
        header_lines += f"{k}: {v}\r\n"
    return (f"{status_line}\r\n" + header_lines + "\r\n").encode('utf-8') + (body if isinstance(body, bytes) else body.encode('utf-8'))

def serve_404(client_sock, client_addr, names_and_ids_html):
    status = "HTTP/1.1 404 Not Found"
    body = f"""<!doctype html>
<html>
<head><title>Error 404</title></head>
<body>
  <h1 style="color:red">The file is not found</h1>
  <p><b>{names_and_ids_html}</b></p>
  <p>Client IP: {client_addr[0]} Port: {client_addr[1]}</p>
</body>
</html>
"""
    resp = build_response(status, {'Content-Type':'text/html; charset=utf-8','Content-Length':str(len(body.encode('utf-8')))}, body)
    client_sock.sendall(resp)

def parse_headers(header_lines):
    headers = {}
    for line in header_lines:
        if ':' in line:
            k, v = line.split(':',1)
            headers[k.strip()] = v.strip()
    return headers

def url_unquote_plus(s):
    return urllib.parse.unquote_plus(s)

def handle_client(client_sock, client_addr):
    try:
        data = client_sock.recv(65536)  # one request is fine for this assignment
        if not data:
            client_sock.close()
            return
        try:
            text = data.decode('utf-8', errors='replace')
        except:
            text = data.decode('latin1', errors='replace')

        lines = text.split('\r\n')
        request_line = lines[0]
        header_lines = []
        i = 1
        while i < len(lines) and lines[i] != '':
            header_lines.append(lines[i])
            i += 1
        headers = parse_headers(header_lines)
        # log request
        parts = request_line.split()
        if len(parts) < 2:
            client_sock.close()
            return
        method, full_path = parts[0], parts[1]
        path, _, query = full_path.partition('?')
        log_request(client_addr, method, full_path, headers)

        # read body if POST
        body = ''
        if method.upper() == 'POST':
            content_length = int(headers.get('Content-Length','0'))
            # maybe part of body already in data read; extract after header blank line
            raw = text.split('\r\n\r\n',1)
            if len(raw) > 1:
                existing_body = raw[1]
            else:
                existing_body = ''
            # if we don't yet have the full body, read remainder
            missing = content_length - len(existing_body.encode('utf-8'))
            body = existing_body
            while missing > 0:
                more = client_sock.recv(65536)
                if not more:
                    break
                body += more.decode('utf-8', errors='replace')
                missing = content_length - len(body.encode('utf-8'))
        # helper: read cookie session id
        cookies = {}
        if 'Cookie' in headers:
            cookie_parts = headers['Cookie'].split(';')
            for c in cookie_parts:
                if '=' in c:
                    k,v = c.strip().split('=',1)
                    cookies[k] = v

        # -- routing rules --
        # 7) redirects with 307
        if path == '/chat':
            resp = build_response("HTTP/1.1 307 Temporary Redirect", {'Location':'https://chat.openai.com','Content-Length':'0'}, b'')
            client_sock.sendall(resp); client_sock.close(); return
        if path == '/cf':
            resp = build_response("HTTP/1.1 307 Temporary Redirect", {'Location':'https://www.cloudflare.com/','Content-Length':'0'}, b'')
            client_sock.sendall(resp); client_sock.close(); return
        if path == '/rt':
            # replace below URL with actual Ritaj website if you have one
            resp = build_response("HTTP/1.1 307 Temporary Redirect", {'Location':'https://ritaj.example.com/','Content-Length':'0'}, b'')
            client_sock.sendall(resp); client_sock.close(); return

        # 1) default main_en.html mapping for '/', '/index.html', '/main_en.html', '/en'
        if path in ['/', '/index.html', '/main_en.html', '/en']:
            target = os.path.join(WWW_DIR, 'main_en.html')
            data_bytes = read_file_safe(target, 'rb')
            if data_bytes is None:
                serve_404(client_sock, client_addr, "YourName - YourID (replace with actual names/IDs)")
                client_sock.close(); return
            headers = {'Content-Type':'text/html; charset=utf-8', 'Content-Length':str(len(data_bytes))}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, data_bytes))
            client_sock.close(); return

        # 2) /ar -> main_ar.html
        if path == '/ar':
            target = os.path.join(WWW_DIR, 'main_ar.html')
            data_bytes = read_file_safe(target, 'rb')
            if data_bytes is None:
                serve_404(client_sock, client_addr, "YourName - YourID (replace with actual names/IDs)")
                client_sock.close(); return
            headers = {'Content-Type':'text/html; charset=utf-8', 'Content-Length':str(len(data_bytes))}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, data_bytes))
            client_sock.close(); return

        # 9) Register: handle POST to /register.html
        if path == '/register.html' and method.upper() == 'POST':
            # body is form-encoded, e.g. username=...&password=...
            form = urllib.parse.parse_qs(body)
            username = form.get('username',[''])[0]
            password = form.get('password',[''])[0]
            if not username or not password:
                resp_body = "<html><body>Missing username or password</body></html>"
                client_sock.sendall(build_response("HTTP/1.1 400 Bad Request", {'Content-Type':'text/html','Content-Length':str(len(resp_body))}, resp_body))
                client_sock.close(); return
            pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            # append to data file
            with open(DATA_FILE, 'a') as f:
                f.write(f"{username}:{pw_hash}\n")
            resp_body = "<html><body>Registered. <a href='/login.html'>Login</a></body></html>"
            client_sock.sendall(build_response("HTTP/1.1 200 OK", {'Content-Type':'text/html','Content-Length':str(len(resp_body))}, resp_body))
            client_sock.close(); return

        # 10) Login: POST to /login.html
        if path == '/login.html' and method.upper() == 'POST':
            form = urllib.parse.parse_qs(body)
            username = form.get('username',[''])[0]
            password = form.get('password',[''])[0]
            if not username or not password:
                resp_body = "<html><body>Missing username or password</body></html>"
                client_sock.sendall(build_response("HTTP/1.1 400 Bad Request", {'Content-Type':'text/html','Content-Length':str(len(resp_body))}, resp_body))
                client_sock.close(); return
            pw_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            valid = False
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE,'r') as f:
                    for line in f:
                        line=line.strip()
                        if not line: continue
                        user, stored = line.split(':',1)
                        if user==username and stored==pw_hash:
                            valid = True; break
            if not valid:
                resp_body = "<html><body>Invalid credentials. <a href='/login.html'>Try again</a></body></html>"
                client_sock.sendall(build_response("HTTP/1.1 401 Unauthorized", {'Content-Type':'text/html','Content-Length':str(len(resp_body))}, resp_body))
                client_sock.close(); return
            # generate session id, store in sessions
            session_id = uuid.uuid4().hex
            sessions[session_id] = {'username': username, 'created':time.time()}
            # send protected.html and set cookie
            protected_path = os.path.join(WWW_DIR,'protected.html')
            body_bytes = read_file_safe(protected_path,'rb') or b"<html><body>Protected page (create protected.html)</body></html>"
            headers = {'Content-Type':'text/html; charset=utf-8', 'Content-Length':str(len(body_bytes)),
                       'Set-Cookie': f"session={session_id}; HttpOnly; Path=/"}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, body_bytes))
            client_sock.close(); return

        # Logout endpoint: /logout -> remove cookie session on server
        if path == '/logout':
            sid = cookies.get('session')
            if sid and sid in sessions:
                del sessions[sid]
            resp_body = "<html><body>Logged out. <a href='/'>Home</a></body></html>"
            headers = {'Content-Type':'text/html','Content-Length':str(len(resp_body)),'Set-Cookie':"session=; Max-Age=0; Path=/"}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, resp_body))
            client_sock.close(); return

        # Protected page access: check cookie for protected.html or any file under /protected.html
        if path == '/protected.html':
            sid = cookies.get('session')
            if not sid or sid not in sessions:
                # redirect to login
                resp = build_response("HTTP/1.1 307 Temporary Redirect", {'Location':'/login.html','Content-Length':'0'}, b'')
                client_sock.sendall(resp); client_sock.close(); return
            # else serve protected.html
            target = os.path.join(WWW_DIR, 'protected.html')
            data_bytes = read_file_safe(target,'rb')
            if data_bytes is None:
                serve_404(client_sock, client_addr, "YourName - YourID (replace with actual names/IDs)")
                client_sock.close(); return
            headers = {'Content-Type':'text/html; charset=utf-8', 'Content-Length':str(len(data_bytes))}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, data_bytes))
            client_sock.close(); return

        # 3-6) Serve requested files by extension
        # sanitize path
        safe_path = path.lstrip('/')
        safe_path = urllib.parse.unquote(safe_path)
        target = os.path.join(WWW_DIR, safe_path)
        if os.path.isdir(target):
            # if directory, optionally serve index.html
            target = os.path.join(target, 'index.html')
        if os.path.exists(target) and os.path.isfile(target):
            ext = os.path.splitext(target)[1].lower()
            ctype = CONTENT_TYPES.get(ext, 'application/octet-stream')
            mode = 'rb' if ext in ['.png','.jpg','.jpeg','.gif'] else 'rb'
            data_bytes = read_file_safe(target, mode)
            if data_bytes is None:
                serve_404(client_sock, client_addr, "YourName - YourID (replace with actual names/IDs)")
                client_sock.close(); return
            headers = {'Content-Type': f"{ctype}", 'Content-Length': str(len(data_bytes))}
            client_sock.sendall(build_response("HTTP/1.1 200 OK", headers, data_bytes))
            client_sock.close(); return

        # file not found -> 404
        serve_404(client_sock, client_addr, "YourName - YourID (replace with actual names/IDs)")
        client_sock.close()
    except Exception as e:
        print("Error handling client:", e)
        try:
            client_sock.close()
        except:
            pass

def start_server():
    if not os.path.exists(WWW_DIR):
        os.makedirs(WWW_DIR)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(50)
    print(f"Listening on {HOST}:{PORT} ...")
    try:
        while True:
            client_sock, client_addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        sock.close()

if __name__ == '__main__':
    start_server()
