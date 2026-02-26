import sys
import os

def process_wordlist(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: {input_path} not found.")
        return

    print(f"Processing {input_path}...")
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        # Filter: Only keep words >= 5 characters, strip whitespace/newlines
        words = [line.strip() for line in f if len(line.strip()) >= 5]
    
    # Sort by length (shorter words first)
    words.sort(key=len)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        for word in words:
            f.write(word + '\n')
            
    print(f"Done! Saved {len(words)} words to {output_path}")

if __name__ == "__main__":
    # Usage: python3 clean_list.py raw_words.txt
    infile = sys.argv[1] if len(sys.argv) > 1 else 'raw_wordlist.txt'
    # Defaults output to 'wordlist.txt' in the current folder
    outfile = "wordlist.txt"
    process_wordlist(infile, outfile)