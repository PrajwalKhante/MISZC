from flask import Flask, request, jsonify, render_template
import requests
import socket

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'Invalid URL'}), 400

    # Automatically add http or https if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Default to http if no scheme is provided

    try:
        # Automatically resolve domain to IP address
        domain = url.split('//')[-1].split('/')[0]
        ip_address = socket.gethostbyname(domain)

        # Make a request and check for redirection
        response = requests.get(url, allow_redirects=True)
        
        # Check if the response was redirected
        redirected = response.history
        redirected_url = response.url if redirected else None  # Get final URL after redirection

        # Get server name from response headers
        server_name = response.headers.get('Server', 'N/A')

        # TLS version: Need to use requests to access it
        tls_version = response.raw.version  # May require additional logic to get the exact version

        # Security headers checking
        headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', None),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', None),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', None),
            'X-Frame-Options': response.headers.get('X-Frame-Options', None),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', None),
            'Referrer-Policy': response.headers.get('Referrer-Policy', None),
            'Permissions-Policy': response.headers.get('Permissions-Policy', None),
            'Feature-Policy': response.headers.get('Feature-Policy', None),
        }

        # Calculate score
        score = sum(1 for value in headers.values() if value)  # Example scoring logic
        alphabet_score = ["F", "D", "C", "B", "A"][min(score, 4)]

        # Additional information
        additional_info = {
            "description": url,
            "tips": [
                "Ensure all security headers are properly configured.",
                "Use HTTPS for secure communication.",
                "Regularly review your security policies."
            ]
        }

        return jsonify({
            'ip': ip_address,
            'server': server_name,
            'tls': tls_version,
            'redirected': len(redirected) > 0,
            'redirected_url': redirected_url,
            'headers': {k: ('ENABLED' if v else 'DISABLED') for k, v in headers.items()},
            'score': alphabet_score,
            'additionalInfo': additional_info
        })

    except Exception as e:
        # Log the error for debugging
        print(f"Error occurred: {str(e)}")
        return jsonify({'error': 'Failed to process request', 'details': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
