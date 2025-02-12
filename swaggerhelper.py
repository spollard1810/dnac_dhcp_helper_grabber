### Script to create API methods from swagger ###

import requests
import json
import os
import argparse
from typing import Dict, Any
import re
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import urllib3

# Disable SSL warnings
urllib3.disable_warnings()

def readSwagger():
    with open('swagger.json', 'r') as file:
        return json.load(file)

def sanitize_name(name: str) -> str:
    """Sanitize a name to be a valid Python identifier.
    
    Args:
        name (str): Name to sanitize
        
    Returns:
        str: Valid Python identifier
    """
    # Replace hyphens and other special characters with underscores
    clean_name = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    # Remove leading digits or underscores
    clean_name = re.sub(r'^[0-9_]+', '', clean_name)
    # Convert to snake_case
    clean_name = ''.join(['_' + c.lower() if c.isupper() else c for c in clean_name]).lstrip('_')
    return clean_name or "param"  # Fallback if name becomes empty

def create_method_name(path: str, method: str) -> str:
    # Convert path to method name, e.g. /addressSpaces/{ref} -> get_address_space
    parts = path.strip('/').split('/')
    name_parts = []
    for part in parts:
        # Remove any path parameters
        clean_part = part.replace('{', '').replace('}', '')
        # Convert to snake case
        clean_part = sanitize_name(clean_part)
        name_parts.append(clean_part)
    
    return f"{method.lower()}_{'_'.join(name_parts)}"

def get_parameters(operation: Dict[str, Any]) -> list:
    params = []
    if 'parameters' in operation:
        for param in operation['parameters']:
            # Handle both inline parameters and references
            if '$ref' in param:
                # Would need to resolve reference in full implementation
                continue
            param_name = sanitize_name(param['name'])  # Sanitize parameter name
            param_type = param.get('type', 'Any')
            # Convert Swagger types to Python types
            if param_type == 'string':
                param_type = 'str'
            elif param_type == 'boolean':
                param_type = 'bool'
            elif param_type == 'integer':
                param_type = 'int'
            param_required = param.get('required', False)
            param_in = param.get('in', 'query')
            params.append((param_name, param_type, param_required, param_in))
    return params

def generate_api_methods(swagger: Dict[str, Any]) -> str:
    lines = [
        "from typing import Dict, List, Optional, Any",
        "import requests",
        "from requests.auth import HTTPBasicAuth",
        "import os",
        "from dotenv import load_dotenv",
        "import urllib3",
        "",
        "# Disable SSL warnings",
        "urllib3.disable_warnings()",
        "",
        "class APIClient:",
        "    _instance = None",
        "",
        "    def __new__(cls):",
        "        if cls._instance is None:",
        "            cls._instance = super(APIClient, cls).__new__(cls)",
        "            cls._instance._initialized = False",
        "        return cls._instance",
        "",
        "    def __init__(self):",
        "        if self._initialized:",
        "            return",
        "",
        "        # Load environment variables",
        "        load_dotenv()",
        "",
        "        # Get credentials from environment",
        "        self.host = os.getenv('DNAC_HOST')",
        "        if not self.host:",
        "            raise ValueError('DNAC_HOST must be provided in .env file')",
        "",
        "        self.username = os.getenv('DNAC_USERNAME')",
        "        if not self.username:",
        "            raise ValueError('DNAC_USERNAME must be provided in .env file')",
        "",
        "        self.password = os.getenv('DNAC_PASSWORD')",
        "        if not self.password:",
        "            raise ValueError('DNAC_PASSWORD must be provided in .env file')",
        "",
        "        # Strip any trailing slashes and protocol from host",
        "        self.host = self.host.rstrip('/').replace('https://', '').replace('http://', '')",
        "        self.base_url = f'https://{self.host}'  # Always use HTTPS",
        "        self.token = None",
        "        self.session = requests.Session()",
        "        self.session.verify = False  # Disable SSL verification",
        "",
        "        # Get initial auth token",
        "        self.authenticate()",
        "        self._initialized = True",
        "",
        "    def authenticate(self) -> None:",
        "        \"\"\"Authenticate with DNA Center and get token\"\"\"",
        "        url = f\"https://{self.host}/dna/system/api/v1/auth/token\"",
        "",
        "        try:",
        "            response = requests.post(",
        "                url,",
        "                auth=HTTPBasicAuth(self.username, self.password),",
        "                verify=False",
        "            )",
        "            response.raise_for_status()",
        "            self.token = response.json()['Token']",
        "            ",
        "            # Update session headers with new token",
        "            self.session.headers.update({",
        "                'X-Auth-Token': self.token,",
        "                'Content-Type': 'application/json'",
        "            })",
        "        except requests.exceptions.RequestException as e:",
        "            raise Exception(f'Error getting auth token: {e}')",
        "",
        "    def _handle_request(self, method: str, url: str, **kwargs) -> Dict:",
        "        \"\"\"Handle API request with token refresh if needed\"\"\"",
        "        try:",
        "            response = self.session.request(method, url, **kwargs)",
        "            ",
        "            # If we get a 401, try to refresh the token and retry once",
        "            if response.status_code == 401:",
        "                self.authenticate()",
        "                response = self.session.request(method, url, **kwargs)",
        "",
        "            response.raise_for_status()",
        "            return response.json()",
        "        except requests.exceptions.RequestException as e:",
        "            raise Exception(f'API request failed: {e}')",
        "",
        "# Create a singleton instance",
        "client = APIClient()",
        ""
    ]

    # Process each endpoint
    for path, path_info in swagger['paths'].items():
        for method, operation in path_info.items():
            if method not in ['get', 'post', 'put', 'delete', 'patch']:
                continue

            method_name = create_method_name(path, method)
            params = get_parameters(operation)
            
            # Sort parameters
            required_params = [(n, t, r, i) for n, t, r, i in params if r]
            optional_params = [(n, t, r, i) for n, t, r, i in params if not r]
            sorted_params = required_params + optional_params
            
            # Method signature
            param_list = []
            for param_name, param_type, required, _ in sorted_params:
                if required:
                    param_list.append(f"{param_name}: {param_type}")
                else:
                    param_list.append(f"{param_name}: Optional[{param_type}] = None")
            
            # Add method to the client instance instead of the class
            method_sig = f"def {method_name}(self"
            if param_list:
                method_sig += ", " + ", ".join(param_list)
            method_sig += ") -> Dict[str, Any]:"
            lines.append(method_sig)
            
            # Start docstring
            docstring_lines = []
            docstring_lines.append('        """' + operation.get('summary', 'No description'))
            
            if operation.get('description'):
                docstring_lines.append("")
                docstring_lines.append("        " + operation.get('description'))
            
            if sorted_params:
                docstring_lines.append("")
                docstring_lines.append("        Args:")
                for param_name, param_type, required, _ in sorted_params:
                    param_desc = next((p.get('description', 'No description') 
                                    for p in operation['parameters'] 
                                    if sanitize_name(p['name']) == param_name),
                                   'No description')
                    docstring_lines.append(f"            {param_name} ({param_type}): {param_desc}")
            
            docstring_lines.extend([
                "",
                "        Returns:",
                "            Dict[str, Any]: API response",
                "",
                "        Raises:",
                "            requests.exceptions.RequestException: If the API request fails",
                '        """'
            ])
            
            # Add docstring to code
            lines.extend(docstring_lines)
            
            # Process parameters
            path_params = []
            query_params = []
            body_params = []
            header_params = []
            
            url_path = path
            for param_name, _, _, param_in in sorted_params:
                orig_name = next(p['name'] for p in operation['parameters'] 
                               if sanitize_name(p['name']) == param_name)
                if param_in == 'path':
                    path_params.append((param_name, orig_name))
                    url_path = url_path.replace('{' + orig_name + '}', '{' + param_name + '}')
                elif param_in == 'body':
                    body_params.append(param_name)
                elif param_in == 'header':
                    header_params.append((param_name, orig_name))
                else:
                    query_params.append((param_name, orig_name))
            
            # Request headers
            lines.append("")  # Add blank line after docstring
            lines.append("        request_headers = self.session.headers.copy()")
            for name, orig in header_params:
                lines.append(f"        if {name} is not None:")
                lines.append(f"            request_headers['{orig}'] = str({name})")
            
            # URL with path parameters
            lines.append(f"        url = self.base_url + '{url_path}'")
            if path_params:
                param_dict = ", ".join(f"{name}={name}" for name, _ in path_params)
                lines.append(f"        url = url.format({param_dict})")
            
            # Query parameters
            if query_params:
                lines.append("        params = {")
                for name, orig in query_params:
                    lines.append(f"            '{orig}': {name},")
                lines.append("        }")
                lines.append("        params = {k: v for k, v in params.items() if v is not None}")
            else:
                lines.append("        params = {}")
            
            # Make request
            if body_params:
                lines.append(f"        json_data = {body_params[0]}")
                lines.append(f"        return self._handle_request('{method}', url, params=params, headers=request_headers, json=json_data)")
            else:
                lines.append(f"        return self._handle_request('{method}', url, params=params, headers=request_headers)")
    
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Generate API client from Swagger specification")
    parser.add_argument("swagger_file", help="Path to the Swagger/OpenAPI JSON file")
    parser.add_argument("-o", "--output_dir", help="Output directory for generated code", default="api")
    parser.add_argument("-f", "--filename", help="Output filename", default="api_methods.py")
    
    args = parser.parse_args()
    
    try:
        with open(args.swagger_file, 'r') as file:
            swagger = json.load(file)
    except FileNotFoundError:
        print(f"Error: Swagger file not found: {args.swagger_file}")
        return 1
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in swagger file: {args.swagger_file}")
        return 1
    
    api_code = generate_api_methods(swagger)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    output_path = os.path.join(args.output_dir, args.filename)
    try:
        with open(output_path, 'w') as f:
            f.write(api_code)
        print(f"Successfully generated API client at: {output_path}")
    except Exception as e:
        print(f"Error writing output file: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())