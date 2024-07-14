from flask import Flask, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

def detect_anomalous_url(url):
    parsed_url = urlparse(url)
    
    # Check for non-standard scheme
    if parsed_url.scheme not in ['http', 'https']:
        return True, "Non-standard scheme"
    
    # Check for IP address in netloc (domain part)
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc):
        return True, "IP address in URL"
    
    # Check for suspicious characters in path or query
    suspicious_chars = ['<', '>', '(', ')', "'", '"', '\\', '{', '}', '|', '`', '^']
    if any(char in parsed_url.path or char in parsed_url.query for char in suspicious_chars):
        return True, "Suspicious characters in path or query"
    
    # Check for non-standard port
    if parsed_url.port and parsed_url.port not in [80, 443]:
        return True, "Non-standard port"
    
    # If no anomalies detected
    return False, "No anomalies detected"

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')  # Using get() to safely retrieve 'url' from JSON
    if not url:
        return jsonify({'error': 'URL not provided'}), 400
    
    is_anomalous, reason = detect_anomalous_url(url)
    return jsonify({'is_anomalous': is_anomalous, 'reason': reason})

if __name__ == '__main__':
    app.run(debug=True)
