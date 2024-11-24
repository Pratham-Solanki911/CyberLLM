import requests
import time
import os
from dotenv import load_dotenv
load_dotenv()

virustotal_key = os.getenv("VIRUSTOTAL_KEY")
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

if __name__ == "__main__":
    test_url="https://www.youtube.com/watch?v=r_A8oVoJXVM"
    result = check_virustotal(test_url)
    print("Test Result:", result)