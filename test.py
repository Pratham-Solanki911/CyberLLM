import requests
import os
import re
from dotenv import load_dotenv
from groq import Groq
from OSINT.search_ap import scrape_text_sandboxed
from OSINT.Osint import osint_wrapper

# Load environment variables
load_dotenv()

# Initialize Groq client with API key
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# API Keys from environment variables
whois_api_key = os.getenv("WHOIS_API_KEY")
shodan_api_key = os.getenv("SHODAN_API_KEY")
groq_api_key = os.getenv("GROQ_API_KEY")
google_safe_browsing_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
virustotal_key = os.getenv("VIRUSTOTAL_KEY")
abuse_ipdb_key = os.getenv("ABUSE_IPDB_KEY")

# Function to check URL with Google Safe Browsing
def check_google_safe_browsing(url):
    if not url:
        return "No URL provided for Google Safe Browsing check."
    
    payload = {
        "client": {"clientId": "groq-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_safe_browsing_key}",
        json=payload
    )
    return response.json()

# Function to check URL with VirusTotal
import requests
import time

# Function to check URL with VirusTotal
def check_virustotal(url):
    if not url:
        return "No URL provided for VirusTotal check."
    
    headers = {"x-apikey": virustotal_key}
    # Submit the URL for analysis
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data={"url": url})
    analysis_id = response.json().get("data", {}).get("id", "")
    
    if analysis_id:
        # Loop to check the status until it's no longer in the queue
        while True:
            report = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers).json()
            status = report.get("data", {}).get("attributes", {}).get("status", "")
            
            if status == "completed":
                stats = report.get("data", {}).get("attributes", {}).get("stats", {})
                flagged_by = [
                    engine for engine, result in report.get("data", {}).get("attributes", {}).get("results", {}).items()
                    if result.get("category") == "malicious"
                ]
                return {"stats": stats, "flagged_by": flagged_by}
            elif status == "queued":
                time.sleep(5)  # Wait for 5 seconds before checking again
            else:
                return "Unexpected status returned by VirusTotal."
    else:
        return "No analysis ID returned by VirusTotal."


# Function to check IP with AbuseIPDB
def check_abuse_ipdb(ip):
    if not ip:
        return "No IP provided for AbuseIPDB check."
    
    headers = {"Key": abuse_ipdb_key, "Accept": "application/json"}
    response = requests.get(
        f"https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={"ipAddress": ip}
    )
    return response.json()

# Function to aggregate report
def aggregate_report(url=None, ip=None):
    # Initialize results
    google_safe_browsing_result = None
    virustotal_result = None
    abuse_ipdb_result = None
    osint_results = None

    # Fetch results based on input type
    if url and not ip:
        google_safe_browsing_result = check_google_safe_browsing(url)
        virustotal_result = check_virustotal(url)
        osint_results = osint_wrapper(url)
    elif ip and not url:
        abuse_ipdb_result = check_abuse_ipdb(ip)

    # Aggregate the results
    report = {
        "Google Safe Browsing Result": google_safe_browsing_result,
        "VirusTotal Result": virustotal_result,
        "AbuseIPDB Result": abuse_ipdb_result,
        "OSINT Results": osint_results
    }

    # Print the aggregated report before sending to LLM
    print("-----------------------------------Aggregated Report start -----------------------------------------:")
    print(report)
    print("-----------------------------------Aggregated Report End-----------------------------------------:")
    
    return report

# Function to generate a detailed report using LLM
def generate_detailed_report(report):
    # Use Groq to generate a detailed report text
    completion = client.chat.completions.create(
        model="llama3-groq-70b-8192-tool-use-preview",
        messages=[
            {
                "role": "user",
                "content": (
                    "Generate a detailed report for the following security check results. explaining each result "
                    "Only provide the report and the threat flag separated by a line. "
                    "Even if one of the detection says malicious then flag url as malicious"
                    "The flag should be in the format: 'Flag: Safe/Undetected/Malicious'. "
                    f"{report}."
                    "after giving flag dont give anything it should be your last line then nothing else"
                )
            }
        ],
        temperature=0.5,
        max_tokens=2048,
        top_p=0.9,
        stream=True,
        stop=None,
    )

    # Capture the report and determine the flag
    report_content = ""

    for chunk in completion:
        report_content += chunk.choices[0].delta.content or ""

    # Remove the threat flag from the report content using regex
    report_content_cleaned = re.sub(r"Flag:\s*(Safe|Undetected|Malicious).*", "", report_content, flags=re.IGNORECASE).strip()

    # Extract the threat flag using regex
    threat_flag = "undetected"  # Default flag
    flag_match = re.search(r"Flag:\s*(Safe|Undetected|Malicious)", report_content, re.IGNORECASE)
    if flag_match:
        threat_flag = flag_match.group(1).lower()

    # Construct final JSON result
    final_report = {
        "Report": report_content_cleaned,
        "Threat Flag": threat_flag
    }

    return final_report

# Function to extract threat flag and report
def extract_flag_and_report(report_json):
    threat_flag = report_json.get("Threat Flag", "undetected")
    report_text = report_json.get("Report", "No report available.")
    return threat_flag, report_text

# Function to get flag and report for a given URL or IP
def get_flag_and_report(url=None, ip=None):
    aggregated_report = aggregate_report(url, ip)
    report_json = generate_detailed_report(aggregated_report)
    threat_flag, report_text = extract_flag_and_report(report_json)
    return threat_flag, report_text

# Example Usage
# if __name__ == "__main__":
    # url = "http://youtube.com"  # Replace with a URL to check, or set to None
    # ip = None              # Replace with a public IP to check, or set to None
    # threat_flag, report_text = get_flag_and_report(url, ip)

    # # Print extracted information
    # print(f"\nThreat Flag: {threat_flag}")
    # print(f"\nDetailed Report:\n{report_text}")
