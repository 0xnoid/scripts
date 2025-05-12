import requests
import json
import argparse

API_KEY = 'YOUR_API_KEY'

def lookup_phone_abstract(phone_number):
    """Fetches phone number details from Abstract API."""
    url = f"https://phonevalidation.abstractapi.com/v1/?api_key={API_KEY}&phone={phone_number}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to lookup {phone_number}")
        return None

def bulk_lookup(input_file, output_file):
    """Processes a list of phone numbers from an input file and writes formatted results to an output file."""
    results = []

    # Read from input file
    with open(input_file, 'r') as file:
        phone_numbers = [line.strip() for line in file if line.strip()]

    # Lookup
    for phone_number in phone_numbers:
        result = lookup_phone_abstract(phone_number)
        if result:
            results.append(format_phone_info(result))

    # Format and output
    with open(output_file, 'w') as outfile:
        outfile.write("\n\n".join(results))
    print(f"Lookup results saved to {output_file}")

def format_phone_info(info):
    """Formats phone number information for output."""
    formatted_info = (
        f"Phone Number: {info.get('phone')}\n"
        f"Valid: {info.get('valid')}\n"
        f"Country: {info.get('country', {}).get('name')}\n"
        f"Location: {info.get('location')}\n"
        f"Carrier: {info.get('carrier')}\n"
        f"Line Type: {info.get('type')}"
    )
    return formatted_info

def main():
    parser = argparse.ArgumentParser(description="Phone number lookup using Abstract API")
    parser.add_argument("-i", "--input", required=True, help="Input file containing phone numbers")
    parser.add_argument("-o", "--output", required=True, help="Output file to save results")
    args = parser.parse_args()

    bulk_lookup(args.input, args.output)

if __name__ == "__main__":
    main()
