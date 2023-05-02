import http.server
import ssl

server_address = ("localhost", 8888)
httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)


httpd.socket = ssl.wrap_socket(
    httpd.socket,
    # keyfile="/home/glaum/engine/tests/server.key",
    # certfile="/home/glaum/engine/tests/server.pem",
    # ca_certs="/home/glaum/engine/keys/ca/ca.crt",
    cert_reqs=1,
    keyfile="/home/glaum/engine/server.key",
    certfile="/home/glaum/engine/server.pem",
    server_side=True,
)

httpd.serve_forever()
