import json
import requests
import argparse
import urllib3
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JSONPScanner:
    def __init__(self, collection_path: str, jwt_token: Optional[str] = None):
        """Initialize the scanner with a Postman collection file path and optional JWT token."""
        self.collection_path = collection_path
        self.callback_params = ['callback', 'jsonp', 'jsonpcallback', 'json_callback']
        self.test_callback = 'testCallback'
        self.base_url = None
        self.headers = {}
        if jwt_token:
            self.headers['Authorization'] = f'Bearer {jwt_token}'
        
    def load_collection(self) -> Dict:
        """Load and parse the Postman collection file."""
        try:
            with open(self.collection_path, 'r') as f:
                collection = json.load(f)
                
            # Extract base URL
            if 'variable' in collection:
                for var in collection['variable']:
                    if var.get('key') == 'baseUrl':
                        self.base_url = var.get('value')
                        break
            
            return collection
        except Exception as e:
            raise Exception(f"Failed to load Postman collection: {str(e)}")

    def resolve_url(self, url_data) -> str:
        """Resolve URL from Postman request format to actual URL."""
        if isinstance(url_data, str):
            url = url_data
        elif isinstance(url_data, dict):
            url = url_data.get('raw', '')
        else:
            return ''
        
        # Replace baseUrl variable
        if self.base_url and '{{baseUrl}}' in url:
            url = url.replace('{{baseUrl}}', self.base_url)
        
        # Handle path parameters (replace {param} with test values)
        param_replacements = {
            '{id}': 'test-id',
            '{userId}': 'test-user',
            '{videoId}': 'test-video',
            '{roomId}': 'test-room',
            '{sidekickId}': 'test-sidekick'
        }
        
        for param, value in param_replacements.items():
            url = url.replace(param, value)
        
        return url

    def extract_endpoints(self, collection: Dict) -> List[Dict]:
        """Extract all GET endpoints from the Postman collection."""
        endpoints = []
        total_endpoints = 0
        get_endpoints = 0
        
        def process_item(item):
            nonlocal total_endpoints, get_endpoints
            if 'request' in item:
                total_endpoints += 1
                method = item['request'].get('method', '').upper()
                if method == 'GET':
                    get_endpoints += 1
                    url = self.resolve_url(item['request'].get('url', ''))
                    if url:
                        endpoints.append({
                            'name': item.get('name', 'Unnamed Request'),
                            'method': 'GET',
                            'url': url
                        })
            if 'item' in item:
                for subitem in item['item']:
                    process_item(subitem)
        
        for item in collection['item']:
            process_item(item)
        
        print(f"\nFound {get_endpoints} GET endpoints out of {total_endpoints} total endpoints")
        return endpoints

    def add_callback_parameter(self, url: str, callback_param: str) -> str:
        """Add a callback parameter to the URL."""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        query_dict[callback_param] = [self.test_callback]
        new_query = urlencode(query_dict, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    def check_jsonp(self, endpoint: Dict) -> Dict:
        """Test an endpoint for JSONP vulnerability."""
        results = {
            'name': endpoint['name'],
            'url': endpoint['url'],
            'method': endpoint['method'],
            'jsonp_enabled': False,
            'vulnerable_params': [],
            'error': None
        }

        for callback_param in self.callback_params:
            try:
                test_url = self.add_callback_parameter(endpoint['url'], callback_param)
                response = requests.get(
                    test_url,
                    timeout=10,
                    verify=False,
                    headers=self.headers
                )
                
                # Check if response contains the callback wrapper
                if self.test_callback in response.text:
                    if not results['jsonp_enabled']:
                        results['jsonp_enabled'] = True
                    results['vulnerable_params'].append(callback_param)
                    
            except requests.exceptions.RequestException as e:
                results['error'] = f"Error testing {callback_param}: {str(e)}"
                continue

        return results

    def scan(self) -> List[Dict]:
        """Scan all endpoints in the collection."""
        collection = self.load_collection()
        endpoints = self.extract_endpoints(collection)
        results = []

        if not endpoints:
            print("No GET endpoints found to test.")
            return results

        print(f"\nTesting {len(endpoints)} GET endpoints for JSONP vulnerabilities...")
        
        for i, endpoint in enumerate(endpoints, 1):
            print(f"\nTesting endpoint {i}/{len(endpoints)}: {endpoint['name']}")
            print(f"URL: {endpoint['url']}")
            
            result = self.check_jsonp(endpoint)
            results.append(result)
            
            if result['jsonp_enabled']:
                print("⚠️  JSONP vulnerability found!")
                print(f"Vulnerable parameters: {', '.join(result['vulnerable_params'])}")
            elif result['error']:
                print(f"❌ Error: {result['error']}")
            else:
                print("✓ No JSONP vulnerability detected")

        return results

def main():
    parser = argparse.ArgumentParser(description='Scan Postman Collection for JSONP endpoints')
    parser.add_argument('collection_path', help='Path to Postman Collection JSON file')
    parser.add_argument('-o', '--output', help='Output file path for results', default='jsonp_scan_results.json')
    parser.add_argument('--jwt', help='JWT token for authentication', default=None)
    args = parser.parse_args()

    try:
        scanner = JSONPScanner(args.collection_path, args.jwt)
        results = scanner.scan()
        
        # Output results to file
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        
        if not results:
            print("\nNo results to report - no GET endpoints were found.")
            return

        # Print summary
        print("\nScan Results Summary:")
        print("--------------------")
        vulnerable_count = sum(1 for r in results if r['jsonp_enabled'])
        error_count = sum(1 for r in results if r['error'])
        print(f"Total GET endpoints scanned: {len(results)}")
        print(f"Endpoints with JSONP enabled: {vulnerable_count}")
        print(f"Endpoints with errors: {error_count}")
        print(f"Detailed results written to: {args.output}")
        
        # Print vulnerable endpoints
        if vulnerable_count > 0:
            print("\nVulnerable Endpoints:")
            for result in results:
                if result['jsonp_enabled']:
                    print(f"\nName: {result['name']}")
                    print(f"URL: {result['url']}")
                    print(f"Vulnerable parameters: {', '.join(result['vulnerable_params'])}")

    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()
