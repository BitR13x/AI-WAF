#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import argparse, sys, requests
from socketserver import ThreadingMixIn
from custom_waf import SignatureBased, AIBased
from utils import relative_path
import logging
import time
import json

def merge_two_dicts(x: dict, y: dict) -> dict:
    # if y has duplicate, duplicate will replace x
    return {**x, **y}

def set_header() -> dict:
    headers = { 'Host': hostname }
    return headers

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.do_GET(body=False)
        return

    def do_GET(self, body=True):
        try:
            url = protocol+f'{hostname}{self.path}'
            req_header = self.headers
            logging.info(f"Proxying request 'GET' {url}")

            error_details = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": self.client_address[0],
                "request_uri": self.path,
                #"rule_id": "",
                #"rule_description": "Possible SQL Injection Attempt",
                #"server_id": "MyWebServer",
                "waf_version": "CyberH/1.0.0",
                "request_headers": str(self.headers),
            }

            # check AI/SIG based WAF (payloads)
            if not sig_waf.verify_agent(req_header):
                error_details["rule_id"] = "AGENT"
                self.log_incident(error_details)
                return


            if self.path != "/":
                if not sig_waf.verify_url(self.path):
                    error_details["rule_id"] = "URL"
                    self.log_incident(error_details)
                    return

                # check AI based WAF
                if not ai_waf.verify_url(self.path):
                    error_details["rule_id"] = "AI-URL"
                    self.log_incident(error_details)
                    return

            try:
                resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
            except requests.exceptions.ConnectionError:
                logging.warning(f"Server not running: {url}")
                self.send_error(404, "Server not running")
                return

            msg = resp.text
            if sig_waf.verify_response(resp.text):
                # headers (be careful with end_headers())
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)

                if body:
                    self.wfile.write(msg.encode(encoding='UTF-8',errors='strict'))
                return
            else:
                error_details["rule_id"] = "ERROR"
                self.log_incident(error_details)

        except BrokenPipeError:
            return


    def do_POST(self, body=True):
        try:
            url = protocol+f'{hostname}{self.path}'
            # could be a security problem when server intercepting it differently
            content_len = 0
            for header in self.headers:
                if header.lower() == "content-length":
                    content_len = int(self.headers[header])

            post_body = self.rfile.read(content_len)
            req_header = self.headers
            logging.info(f"Proxying request 'POST' {url}")

            error_details = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "client_ip": self.client_address[0],
                "request_uri": self.path,
                #"rule_id": "",
                #"rule_description": "Possible SQL Injection Attempt",
                #"server_id": "MyWebServer",
                "waf_version": "CyberH/1.0.0",
                "request_headers": str(self.headers),
            }

            post_body = post_body.decode()
            try:
                error_details["query_params"] = json.dumps(post_body)
            except TypeError:
                error_details["query_params"] = post_body.decode()


            # check AI/SIG based WAF (payloads)
            if self.path != "/":
                if not sig_waf.verify_url(self.path):
                    error_details["rule_id"] = "URL"
                    self.log_incident(error_details)
                    return

                # check AI based WAF
                if not ai_waf.verify_url(self.path):
                    error_details["rule_id"] = "AI-URL"
                    self.log_incident(error_details)
                    return

            if not sig_waf.verify_data(post_body):
                error_details["rule_id"] = "DATA"
                self.log_incident(error_details)
                return

            if not sig_waf.verify_agent(req_header):
                error_details["rule_id"] = "AGENT"
                self.log_incident(error_details)
                return

            if not ai_waf.verify_data(post_body):
                error_details["rule_id"] = "AI-DATA"
                self.log_incident(error_details)
                return

            try:
                resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
            except requests.exceptions.ConnectionError:
                logging.warning(f"Server not running: {url}")
                self.send_error(404, "Server not running")
                return

            if sig_waf.verify_response(resp.text):
                self.send_response(resp.status_code)
                self.send_resp_headers(resp)

                if body:
                    self.wfile.write(resp.content)
                return
            else:
                error_details["rule_id"] = "ERROR"
                self.log_incident(error_details)

        except BrokenPipeError:
            return

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        #print('Response Header')
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                #print(key, respheaders[key])
                self.send_header(key, respheaders[key])
        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

    def log_incident(self, error_details: dict):
        self.send_waf_error(error_details)
        logging.warning(f"Potential security threat detected: {json.dumps(error_details)}")
        return

    def send_waf_error(self, error_details: dict):
        """Sends the WAF error page with dynamic content."""

        # load the template
        with open(relative_path("page/error.html"), "r") as f:
            ERROR_PAGE_HTML = f.read()

        # replace placeholders with actual values
        ERROR_PAGE_HTML = ERROR_PAGE_HTML.replace(
            "REPLACE_ME",
            f"<script>window.errorDetails = {json.dumps(error_details)};</script>"
        )

        try:
            self.send_response(403)
            self.send_header("content-type", "text/html")
            self.send_header('content-length', len(ERROR_PAGE_HTML))
            self.end_headers()

            self.wfile.write(ERROR_PAGE_HTML.encode(encoding='UTF-8',errors='strict'))
        except BrokenPipeError:
            return


def parse_args(argv=sys.argv[1:]):
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')

    parser.add_argument('--protocol', dest='protocol', type=str, default="http://",
                        help='web HTTP or HTTPS (default: "http://")')

    parser.add_argument('--port', dest='port', type=int, default=9999,
                        help='serve HTTP requests on specified port (default: 9999)')
    parser.add_argument('--proxy_hostname', dest='proxy_hostname', type=str, default='0.0.0.0',
                        help='where proxy will be hosted (default: 0.0.0.0)')

    parser.add_argument('--hostname', dest='hostname', type=str, default='127.0.0.1',
                        help='hostname to be processed (default: 127.0.0.1)')

    return parser.parse_args(argv)

def run(USE_HTTPS=False):
    args = parse_args()

    global hostname, protocol, sig_waf, ai_waf


    # AI - def __init__(self, MODEL_NAME, trained_model_paths: list, LABELS: list, probability_catch: float = 0.9):
    
    MODEL_NAME = 'distilbert-base-uncased'
    
    # url-ai, data-ai
    trained_model_paths = [
        relative_path("results/model-fwaf-dataset.pth"),
        relative_path("results/model-attack-dataset.pth")
    ]

    from os import listdir
    targets = [
        ["goodqueries", "badqueries"],
        listdir(relative_path("data/attack-datasets"))
    ]

    # create dict [url, data]
    LABELS = [{ k:v for (k,v) in zip(range(len(target)), target)} for target in targets]


    # Sig - def __init__(self, signatures_paths: dict):
    # ["url", "agents", "errors", "body"]
    signature_paths = { 
        "url": relative_path("rules/request/url"),
        "agents": relative_path("rules/request/agents"),
        "errors": relative_path("rules/response/errors"),
        "body": relative_path("rules/request/body")
    }

    sig_waf, ai_waf = SignatureBased(signature_paths), AIBased(MODEL_NAME, trained_model_paths, LABELS)

    hostname = args.hostname
    protocol = args.protocol
    server_address = (args.proxy_hostname, args.port)

    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    print(f'Proxy running at server is starting on http://{args.proxy_hostname}:{args.port}/')
    print('HTTP server is running as reverse proxy')

    if USE_HTTPS:
        import ssl
        # openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
        httpd.socket = ssl.wrap_socket(httpd.socket, keyfile='./key.pem', certfile='./cert.pem', server_side=True)
    httpd.serve_forever()

if __name__ == '__main__':
    run()