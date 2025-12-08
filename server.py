#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import hashlib
import uuid
import os
import urllib.parse
from typing import Dict, Optional

PORT = 8099

# خريطة الجلسات: sessionId -> username
sessions: Dict[str, str] = {}


class ClientHandler:
    def __init__(self, client_socket: socket.socket, client_address):
        self.socket = client_socket
        self.address = client_address

    def run(self):
        cookie_header = None

        try:
            # Read request headers (first 4096 bytes should be enough for headers)
            request_data = self.socket.recv(4096).decode('utf-8')
            if not request_data:
                self.socket.close()
                return

            lines = request_data.split('\r\n')
            if not lines:
                self.socket.close()
                return

            request_line = lines[0]
            print("----- HTTP Request Start -----")
            print(request_line)

            content_length = 0
            body_start_idx = 0

            # Parse headers
            for i, header_line in enumerate(lines[1:], 1):
                if not header_line:
                    body_start_idx = i + 1
                    break
                print(header_line)
                header_lower = header_line.lower()
                if header_lower.startswith("content-length:"):
                    try:
                        content_length = int(header_line.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif header_lower.startswith("cookie:"):
                    cookie_header = header_line[7:].strip()

            print("----- HTTP Request End -----")

            # Parse request line
            parts = request_line.split()
            if len(parts) < 2:
                self.send_bad_request()
                self.socket.close()
                return

            method = parts[0]
            path = parts[1]

            # Read body if POST - handle cases where body might be split
            body = ""
            if method == "POST" and content_length > 0:
                # Get body from initial request data
                body_lines = '\r\n'.join(lines[body_start_idx:])
                body_received = len(body_lines.encode('utf-8'))
                
                # If we haven't received the full body, read more
                if body_received < content_length:
                    remaining = content_length - body_received
                    additional_data = self.socket.recv(remaining).decode('utf-8')
                    body_lines += additional_data
                
                body = body_lines[:content_length]

            # Handle request
            if method == "GET":
                self.handle_get(path, cookie_header)
            elif method == "POST":
                self.handle_post(path, body)
            else:
                self.send_method_not_allowed()

        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            try:
                self.socket.close()
            except:
                pass

    # ============ GET ============
    def handle_get(self, path: str, cookie_header: Optional[str]):
        # Remove query string
        if '?' in path:
            path = path.split('?')[0]

        # الصفحة الرئيسية
        if path in ["/", "/index.html", "/main_en.html", "/en"]:
            self.send_file_response("main_en.html", "text/html; charset=utf-8")
            return

        # نسخة عربية لو عملتيها
        if path == "/ar":
            self.send_file_response("main_ar.html", "text/html; charset=utf-8")
            return

        # Redirects
        if path == "/chat":
            self.send_redirect("https://chatgpt.com/")
            return
        if path == "/cf":
            self.send_redirect("https://www.cloudflare.com/")
            return
        if path == "/rt":
            self.send_redirect("https://ritaj.birzeit.edu/")
            return

        # الصفحة المحمية
        if path == "/protected.html":
            username = self.get_user_from_cookies(cookie_header)
            if username is None:
                # ما في session → رجّعه على login.html
                self.send_redirect("/login.html")
            else:
                # Logged in → افتح الصفحة
                self.send_file_response("protected.html", "text/html; charset=utf-8")
            return

        # باقي ملفات HTML
        if path.endswith(".html"):
            filename = path[1:]
            self.send_file_response(filename, "text/html; charset=utf-8")
            return

        # CSS
        if path.endswith(".css"):
            filename = path[1:]
            self.send_file_response(filename, "text/css; charset=utf-8")
            return

        # PNG
        if path.endswith(".png"):
            filename = path[1:]
            self.send_file_response(filename, "image/png")
            return

        # JPG/JPEG
        if path.endswith(".jpg") or path.endswith(".jpeg"):
            filename = path[1:]
            self.send_file_response(filename, "image/jpeg")
            return

        self.send_not_found()

    # نستخرج اليوزر من الكوكيز (لو موجود sessionId)
    def get_user_from_cookies(self, cookie_header: Optional[str]) -> Optional[str]:
        if cookie_header is None:
            return None

        cookies = cookie_header.split(";")
        for c in cookies:
            c = c.strip()
            if c.startswith("sessionId="):
                session_id = c[10:].strip()
                if not session_id:
                    return None
                return sessions.get(session_id)
        return None

    # ============ POST ============
    def handle_post(self, path: str, body: str):
        print(f"POST body = {body}")

        decoded = urllib.parse.unquote(body)
        username = None
        password = None

        pairs = decoded.split("&")
        for p in pairs:
            kv = p.split("=", 1)
            if len(kv) == 2:
                if kv[0] == "username":
                    username = kv[1]
                if kv[0] == "password":
                    password = kv[1]

        if path == "/register":
            self.handle_register(username, password)
        elif path == "/login":
            self.handle_login(username, password)
        else:
            self.send_bad_request()

    def handle_register(self, username: Optional[str], password: Optional[str]):
        if not username or not password or username == "" or password == "":
            self.send_simple_html("400 Bad Request",
                                 "<h1>400 Bad Request</h1><p>Username or password is missing.</p>")
            return

        password_hash = self.hash_password(password)

        try:
            with open("data.txt", "a", encoding="utf-8") as f:
                f.write(f"{username}:{password_hash}\n")
        except Exception as e:
            print(f"Error writing to data.txt: {e}")
            return

        body = (
            "<h1>Registration Successful</h1>" +
            f"<p>Welcome, {self.escape_html(username)}!</p>" +
            '<p><a href="login.html">Go to login page</a></p>'
        )

        self.send_simple_html("200 OK", body)

    def handle_login(self, username: Optional[str], password: Optional[str]):
        if not username or not password or username == "" or password == "":
            self.send_simple_html("400 Bad Request",
                                 "<h1>400 Bad Request</h1><p>Username or password is missing.</p>")
            return

        password_hash = self.hash_password(password)

        if not os.path.exists("data.txt"):
            self.send_simple_html("401 Unauthorized",
                                 "<h1>Login Failed</h1><p>No registered users found.</p>" +
                                 '<p><a href="register.html">Register first</a></p>')
            return

        ok = False

        try:
            with open("data.txt", "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        continue

                    stored_user = parts[0]
                    stored_hash = parts[1]

                    if stored_user == username and stored_hash == password_hash:
                        ok = True
                        break
        except Exception as e:
            print(f"Error reading data.txt: {e}")
            return

        if ok:
            # إنشاء session ID وتخزينه في الخريطة
            session_id = str(uuid.uuid4())
            sessions[session_id] = username

            body = (
                "<h1>Login Successful</h1>" +
                f"<p>Welcome back, {self.escape_html(username)}!</p>" +
                '<p><a href="protected.html">Go to protected page</a></p>'
            )

            full_body = f"<html><head><title>200 OK</title></head><body>{body}</body></html>"
            body_bytes = full_body.encode('utf-8')

            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Set-Cookie: sessionId={session_id}; Path=/\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            self.socket.sendall(headers.encode('utf-8'))
            self.socket.sendall(body_bytes)
        else:
            inner = (
                "<h1>Login Failed</h1>" +
                "<p>Invalid username or password.</p>" +
                '<p><a href="login.html">Try again</a></p>'
            )
            self.send_simple_html("401 Unauthorized", inner)

    # ===== Helpers =====
    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

    def escape_html(self, s: str) -> str:
        return (s.replace("&", "&amp;")
                 .replace("<", "&lt;")
                 .replace(">", "&gt;"))

    def send_file_response(self, filename: str, content_type: str):
        if not os.path.exists(filename) or not os.path.isfile(filename):
            self.send_simple_not_found()
            return

        try:
            with open(filename, "rb") as f:
                data = f.read()

            headers = (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Type: {content_type}\r\n"
                f"Content-Length: {len(data)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            )

            self.socket.sendall(headers.encode('utf-8'))
            self.socket.sendall(data)
        except Exception as e:
            print(f"Error sending file {filename}: {e}")
            self.send_simple_not_found()

    def send_redirect(self, location: str):
        body = (
            "<html><head><title>307 Temporary Redirect</title></head>"
            "<body><h1>307 Temporary Redirect</h1>"
            f'<p>The document has moved <a href="{location}">here</a>.</p>'
            "</body></html>"
        )
        body_bytes = body.encode('utf-8')

        headers = (
            "HTTP/1.1 307 Temporary Redirect\r\n"
            f"Location: {location}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)

    def send_bad_request(self):
        body = "<html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1></body></html>"
        body_bytes = body.encode('utf-8')

        headers = (
            "HTTP/1.1 400 Bad Request\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)

    def send_method_not_allowed(self):
        body = "<html><head><title>405 Method Not Allowed</title></head><body><h1>405 Method Not Allowed</h1></body></html>"
        body_bytes = body.encode('utf-8')

        headers = (
            "HTTP/1.1 405 Method Not Allowed\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)

    def send_simple_not_found(self):
        body = "<html><head><title>Error 404</title></head><body><h1 style='color:red;'>The file is not found</h1></body></html>"
        body_bytes = body.encode('utf-8')

        headers = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)

    def send_not_found(self):
        client_info = f"{self.address[0]}:{self.address[1]}"

        body = (
            "<html><head><title>Error 404</title></head>"
            "<body>"
            "<h1 style='color:red;'>The file is not found</h1>"
            "<p><b>Aya Abd-alkarim - 1220020</b><br>"
            "<b>Malak Abu Jaradeh - 1221890</b><br>"
            "<b>Bisan Barghothi - 1211234</b></p>"
            f"<p>Client: {client_info}</p>"
            "</body></html>"
        )
        body_bytes = body.encode('utf-8')

        headers = (
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)

    def send_simple_html(self, status: str, inner_html: str):
        body = f"<html><head><title>{status}</title></head><body>{inner_html}</body></html>"
        body_bytes = body.encode('utf-8')

        headers = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body_bytes)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        self.socket.sendall(headers.encode('utf-8'))
        self.socket.sendall(body_bytes)


def main():
    print(f"Tiny Web Server is starting on port {PORT}...")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("", PORT))
        server_socket.listen(5)

        while True:
            client_socket, client_address = server_socket.accept()
            print(f"New connection from {client_address[0]}:{client_address[1]}")

            handler = ClientHandler(client_socket, client_address)
            thread = threading.Thread(target=handler.run)
            thread.daemon = True
            thread.start()

    except KeyboardInterrupt:
        print("\nServer shutting down...")
    except Exception as e:
        print(f"Error starting server: {e}")
    finally:
        try:
            server_socket.close()
        except:
            pass


if __name__ == "__main__":
    main()

