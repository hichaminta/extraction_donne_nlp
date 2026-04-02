import json
import random
import os
import sys

def extract_random_bulletins(input_file, output_file, count=1000):
    """
    Extracts a random sample of bulletins from a JSON file.
    """
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        return

    print(f"Loading data from {input_file}...")
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading JSON: {e}")
        return

    if not isinstance(data, list):
        print("Error: JSON data is not a list.")
        return

    total_bulletins = len(data)
    print(f"Total bulletins found: {total_bulletins}")

    if total_bulletins <= count:
        print(f"Warning: Total bulletins ({total_bulletins}) is less than or equal to requested count ({count}). Returning all.")
        sample = data
    else:
        print(f"Selecting {count} random bulletins...")
        sample = random.sample(data, count)

    print(f"Saving {len(sample)} bulletins to {output_file}...")
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(sample, f, indent=2, ensure_ascii=False)
        print("Done!")
    except Exception as e:
        print(f"Error saving JSON: {e}")

if __name__ == "__main__":
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(base_dir, 'output', 'dgssi_stage1.json')
    output_path = os.path.join(base_dir, 'output', 'dgssi_stage1_random_1000.json')

    # Allow custom count via command line
    count = 1000
    if len(sys.argv) > 1:
        try:
            count = int(sys.argv[1])
        except ValueError:
            pass

    extract_random_bulletins(input_path, output_path, count)
