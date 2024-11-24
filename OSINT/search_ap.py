import requests
from dotenv import load_dotenv
import os

# Load API key from .env file
load_dotenv()
RAPIDAPI_KEY = os.getenv("RAPIDAPI_KEY")

if not RAPIDAPI_KEY:
    raise ValueError("RAPIDAPI_KEY is not set in the .env file.")

# ScrapeNinja API URL
SCRAPENINJA_API_URL = "https://scrapeninja.p.rapidapi.com/scrape"

def scrape_text_sandboxed(url):
    """
    Scrape the given URL in a sandboxed environment using ScrapeNinja.
    
    Args:
        url (str): The URL to scrape.
    
    Returns:
        str: Extracted text content from the URL (up to 5000 characters), or None if an error occurs.
    """
    payload = {
        "url": url,
        "method": "GET",
        "retryNum": 1,
        "geo": "us",
        "extractor": """
        function extract(input, cheerio) {
            let $ = cheerio.load(input);
            let text = $('body').text();
            return { text: text.slice(0, 5000) }; // Limit the response to 5000 characters
        }
        """
    }
    headers = {
        "Content-Type": "application/json",
        "x-rapidapi-host": "scrapeninja.p.rapidapi.com",
        "x-rapidapi-key": RAPIDAPI_KEY,
    }

    try:
        response = requests.post(SCRAPENINJA_API_URL, json=payload, headers=headers)
        response.raise_for_status()
        response_json = response.json()
        return response_json.get("extractor", {}).get("result", {}).get("text", "No text found")
    except requests.RequestException as e:
        print(f"Failed to scrape {url} in sandbox: {e}")
        return None
