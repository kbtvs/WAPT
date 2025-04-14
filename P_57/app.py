from flask import Flask, render_template, request
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
import os

app = Flask(__name__)

COMMON_PATHS = [
    "admin/", "backup/", "backups/", ".git/", ".env", "config/", "phpinfo.php",
    "test/", "debug/", "uploads/", "logs/", "server-status", "database.sql", "db.sql"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (DirectoryScanner)"
}

# Check for security-related HTTP header misconfigurations
def check_headers(base_url):
    issues = []
    try:
        res = requests.get(base_url, headers=HEADERS, timeout=5)
        headers = res.headers

        # Common headers to check
        if 'X-Frame-Options' not in headers:
            issues.append("Missing X-Frame-Options header")
        if 'X-Content-Type-Options' not in headers:
            issues.append("Missing X-Content-Type-Options header")
        if 'Content-Security-Policy' not in headers:
            issues.append("Missing Content-Security-Policy header")
        if 'Strict-Transport-Security' not in headers and base_url.startswith("https"):
            issues.append("Missing Strict-Transport-Security header")

        if 'Access-Control-Allow-Origin' in headers and headers['Access-Control-Allow-Origin'] == '*':
            issues.append("CORS misconfiguration: Access-Control-Allow-Origin is set to *")
        if 'Set-Cookie' in headers:
            cookies = headers.get('Set-Cookie')
            if 'HttpOnly' not in cookies:
                issues.append("Set-Cookie missing HttpOnly flag")
            if 'Secure' not in cookies and base_url.startswith("https"):
                issues.append("Set-Cookie missing Secure flag")
            if 'SameSite' not in cookies:
                issues.append("Set-Cookie missing SameSite flag")
        if 'Server' in headers:
            issues.append(f"Server header exposed: {headers['Server']}")
        if 'X-Powered-By' in headers:
            issues.append(f"X-Powered-By header exposed: {headers['X-Powered-By']}")


    except requests.RequestException:
        issues.append("Could not fetch headers")
    return issues


def check_url(base_url, path):
    full_url = urljoin(base_url, path)
    try:
        response = requests.get(full_url, headers=HEADERS, timeout=5, allow_redirects=False)
        code = response.status_code
        if code in [200, 301, 302]:
            return (full_url, code)
    except requests.RequestException:
        pass
    return None


def scan_website(base_url):
    found_paths = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(check_url, base_url, path) for path in COMMON_PATHS]
        for future in futures:
            result = future.result()
            if result:
                found_paths.append(result)
    return found_paths


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url')
        if not url.startswith("http"):
            url = "http://" + url

        results = scan_website(url)
        open_dirs = [r[0] for r in results]
        misconfigs = [r[0] for r in results if any(keyword in r[0] for keyword in ['.git', '.env', 'phpinfo', 'logs', 'backup', 'db.sql'])]

        header_issues = check_headers(url)

        return render_template('result.html', url=url, open_dirs=open_dirs, misconfigs=misconfigs, header_issues=header_issues)

    return render_template('index.html')


if __name__ == '__main__':
    app.run(debug=True)


# from flask import Flask, render_template, request
# import requests
# from urllib.parse import urljoin
# from concurrent.futures import ThreadPoolExecutor
# import os

# app = Flask(__name__)

# COMMON_PATHS = [
#     "admin/", "backup/", "backups/", ".git/", ".env", "config/", "phpinfo.php",
#     "test/", "debug/", "uploads/", "logs/", "server-status", "database.sql", "db.sql"
# ]

# HEADERS = {
#     "User-Agent": "Mozilla/5.0 (DirectoryScanner)"
# }


# def check_url(base_url, path):
#     full_url = urljoin(base_url, path)
#     try:
#         response = requests.get(full_url, headers=HEADERS, timeout=5, allow_redirects=False)
#         code = response.status_code
#         if code in [200, 301, 302]:
#             return (full_url, code)
#     except requests.RequestException:
#         pass
#     return None


# def scan_website(base_url):
#     found_paths = []
#     with ThreadPoolExecutor(max_workers=10) as executor:
#         futures = [executor.submit(check_url, base_url, path) for path in COMMON_PATHS]
#         for future in futures:
#             result = future.result()
#             if result:
#                 found_paths.append(result)
#     return found_paths


# @app.route('/', methods=['GET', 'POST'])
# def index():
#     if request.method == 'POST':
#         url = request.form.get('url')
#         if not url.startswith("http"):
#             url = "http://" + url
#         results = scan_website(url)

#         open_dirs = [r[0] for r in results]
#         misconfigs = [r[0] for r in results if any(keyword in r[0] for keyword in ['.git', '.env', 'phpinfo', 'logs', 'backup', 'db.sql'])]

#         return render_template('result.html', url=url, open_dirs=open_dirs, misconfigs=misconfigs)

#     return render_template('index.html')


# if __name__ == '__main__':
#     app.run(debug=True)
