import requests
import json
import sys
import os
from datetime import datetime

def check_url_with_safe_browsing(api_key, url):
    """
    Check a URL using Google Safe Browsing API and return detailed results
    
    Args:
        api_key (str): Google Safe Browsing API key
        url (str): URL to check
        
    Returns:
        dict: Results of the check
    """
    # API endpoint
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    
    # Request parameters
    params = {"key": api_key}
    
    # Request body
    request_body = {
        "client": {
            "clientId": "safe-browsing-test-script",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING", 
                "UNWANTED_SOFTWARE", 
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Checking URL: {url}")
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending request to Google Safe Browsing API...")
    
    try:
        # Send the request
        response = requests.post(api_url, params=params, json=request_body)
        
        # Print basic response info
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Response Status Code: {response.status_code}")
        
        # If the request was successful
        if response.status_code == 200:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Request successful!")
            
            # Parse the response
            result = response.json()
            
            # Check if there are any matches (threats)
            if "matches" in result and len(result["matches"]) > 0:
                print("\n🚨 ALERT: URL IS UNSAFE 🚨")
                print(f"The URL '{url}' has been identified as potentially dangerous.\n")
                
                print("Threat Details:")
                print("---------------")
                for i, match in enumerate(result["matches"], 1):
                    threat_type = match.get("threatType", "Unknown")
                    platform = match.get("platformType", "Unknown")
                    threat_entry = match.get("threatEntryType", "Unknown")
                    
                    print(f"Threat #{i}:")
                    print(f"  - Threat Type: {threat_type}")
                    print(f"  - Platform: {platform}")
                    print(f"  - Entry Type: {threat_entry}")
                    if "cacheDuration" in match:
                        print(f"  - Cache Duration: {match['cacheDuration']}")
                    print()
                
                return {
                    "safe": False,
                    "url": url,
                    "threats": result["matches"],
                    "raw_response": result
                }
            else:
                print("\n✅ URL IS SAFE ✅")
                print(f"The URL '{url}' appears to be safe according to Google Safe Browsing API.")
                return {
                    "safe": True,
                    "url": url,
                    "raw_response": result
                }
        else:
            print("\n⚠️ API REQUEST FAILED ⚠️")
            print(f"Status code: {response.status_code}")
            
            # Try to parse the error message
            try:
                error_info = response.json()
                print("\nError Details:")
                print("-------------")
                print(json.dumps(error_info, indent=2))
                
                # Specific guidance for common errors
                if response.status_code == 400:
                    print("\nTROUBLESHOOTING HELP:")
                    print("1. Check if your API key is correct")
                    print("2. Verify the URL format is valid")
                    print("3. Ensure your request body follows the API specification")
                    
                elif response.status_code == 403:
                    print("\nTROUBLESHOOTING HELP:")
                    print("1. Ensure the Safe Browsing API is enabled in your Google Cloud Console")
                    print("2. Check if your API key has the correct permissions")
                    print("3. Verify your Google Cloud billing is set up correctly")
                    
            except json.JSONDecodeError:
                print("\nRaw Error Response:")
                print(response.text)
            
            return {
                "error": True,
                "status_code": response.status_code,
                "response": response.text
            }
            
    except requests.exceptions.RequestException as e:
        print(f"\n⚠️ CONNECTION ERROR ⚠️")
        print(f"Error: {str(e)}")
        return {
            "error": True,
            "message": str(e)
        }


def main():
    """Main function to run the script"""
    
    # ASCII art header
    print("""
    =========================================================
    🛡️  GOOGLE SAFE BROWSING API TEST TOOL 🛡️
    =========================================================
    """)
    
    # Get API key (either from environment variable or user input)
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
    
    if not api_key:
        api_key = input("Enter your Google Safe Browsing API key: ").strip()
        if not api_key:
            print("❌ Error: API key is required")
            return
    
    # Get URL from command line argument or prompt user
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("Enter the URL to check: ").strip()
        if not url:
            print("❌ Error: URL is required")
            return
    
    # Add protocol if missing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
        print(f"Added protocol: {url}")
    
    # Check the URL
    result = check_url_with_safe_browsing(api_key, url)
    
    # Save the raw response to a file for debugging
    with open("safe_browsing_response.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\nFull response saved to 'safe_browsing_response.json'")
    
    print("\nTest completed!")


if __name__ == "__main__":
    main()