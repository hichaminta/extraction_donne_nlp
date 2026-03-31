import http.server
import socketserver
import webbrowser
import os
import sys

# Configuration
PORT = 8000
DIRECTORY = "." # Root of the project

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def start_server():
    try:
        with socketserver.TCPServer(("", PORT), MyHttpRequestHandler) as httpd:
            print(f"--- CTI DASHBOARD SERVER ---")
            print(f"Serving at: http://localhost:{PORT}/dashboard/")
            print(f"Loading data from: {os.path.abspath('output_regex')}")
            print(f"Press CTRL+C to stop the server.")
            
            # Open browser automatically
            url = f"http://localhost:{PORT}/dashboard"
            webbrowser.open(url)
            
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    start_server()
