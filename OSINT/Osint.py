import requests
import os
from dotenv import load_dotenv
from OSINT.search_ap import scrape_text_sandboxed

# Load environment variables
load_dotenv()

# API Keys from environment variables
whois_api_key = os.getenv("WHOIS_API_KEY")
shodan_api_key = os.getenv("SHODAN_API_KEY")

class OSINT:
    def __init__(self, domain):
        self.domain = domain
        self.whois_api_key = whois_api_key
        self.shodan_api_key = shodan_api_key
        self.results = {}

    def whois_lookup(self):
        """Perform Whois lookup using WhoisXML API"""
        try:
            response = requests.get(
                f"https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "apiKey": self.whois_api_key,
                    "domainName": self.domain,
                    "outputFormat": "JSON"
                }
            )
            response.raise_for_status()
            self.results["Whois"] = response.json()
        except requests.exceptions.RequestException as e:
            self.results["Whois"] = {"error": f"Whois API request failed: {e}"}

    def shodan_lookup(self):
        """Perform Shodan lookup using Shodan API"""
        try:
            response = requests.get(
                f"https://api.shodan.io/dns/domain/{self.domain}",
                params={"key": self.shodan_api_key}
            )
            response.raise_for_status()
            self.results["Shodan"] = response.json()
        except requests.exceptions.RequestException as e:
            self.results["Shodan"] = {"error": f"Shodan API request failed: {e}"}

    def scrape_site(self):
        """Scrape website content using sandboxed environment"""
        try:
            text_content = scrape_text_sandboxed(f"https://{self.domain}")
            if text_content:
                self.results["Sandboxed Scrape"] = text_content[:1000]  # Limit preview to 1000 characters
            else:
                self.results["Sandboxed Scrape"] = {"error": "Failed to retrieve text content."}
        except Exception as e:
            self.results["Sandboxed Scrape"] = {"error": f"Sandboxed scraping failed: {e}"}

    def map_incidents(self):
        """Map incidents based on the gathered data"""
        mapped_data = {
            "Domain": self.domain,
            "Incidents": []
        }
        for source, result in self.results.items():
            if isinstance(result, dict) and "error" not in result:
                mapped_data["Incidents"].append({source: result})
        self.results["Mapped Incidents"] = mapped_data

    def perform_osint(self):
        """Perform the complete OSINT process"""
        # self.whois_lookup()
        # self.shodan_lookup()
        self.scrape_site()
        self.map_incidents()
        return self.results


def osint_wrapper(url):
    """Wrapper function to perform OSINT on a given URL and return raw report data."""
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    osint = OSINT(domain)
    raw_report_data = osint.perform_osint()
    return raw_report_data
