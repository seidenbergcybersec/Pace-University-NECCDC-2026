import nmap
import datetime
import os

# Function to read baseline file
def read_baseline(file_path):
    with open(file_path, 'r') as f:
        baseline_lines = f.readlines()
    return baseline_lines

# Function to get currently running services
def scan_and_save():
    # Get the current script's directory to save the output file in the same location
    script_dir = os.path.dirname(os.path.realpath(__file__))
    output_file = os.path.join(script_dir, 'current_scan.txt')

    nm = nmap.PortScanner()
    nm.scan('localhost', arguments='-sV')  # Scan localhost with version detection

    with open(output_file, 'w') as f:
        f.write(f"Scan Date: {datetime.datetime.now().isoformat()}\n\n")
        for host in nm.all_hosts():
            f.write(f"Host: {host}\n")
            for proto in nm[host].all_protocols():
                f.write(f"Protocol: {proto}\n")
                lport = nm[host][proto].keys()
                for port in sorted(lport):
                    service = nm[host][proto][port]['product']
                    version = nm[host][proto][port]['version']
                    f.write(f"Port: {port}\tService: {service}\tVersion: {version}\n")
            f.write("\n")

    print(f"Scan results saved to {output_file}")
    return output_file

# Function to generate a baseline file of the current scan
def generate_baseline(file_name):
    # Get the current directory where the script is located
    script_dir = os.path.dirname(os.path.realpath(__file__))
    baseline_file = os.path.join(script_dir, file_name)

    # Perform the scan and save the results as the baseline
    current_file = scan_and_save()

    # Now, copy the content of the current scan into the baseline file
    with open(baseline_file, 'w') as f:
        with open(current_file, 'r') as current_f:
            f.write(current_f.read())

    print(f"Baseline file '{baseline_file}' has been generated.")

# Function to compare current scan results with the baseline
def compare_scans(baseline_file, current_file):
    baseline_lines = read_baseline(baseline_file)
    with open(current_file, 'r') as f2:
        current_lines = f2.readlines()

    # Assuming the files have similar structure, compare line by line
    differences = []
    for line1, line2 in zip(baseline_lines, current_lines):
        if line1 != line2:
            differences.append(f"Difference found:\nBaseline: {line1}\nCurrent: {line2}")

    if differences:
        for diff in differences:
            print(diff)
    else:
        print("No differences found between scans.")

def main():
    action = input("Type 'generate' to generate a baseline or 'compare' to compare current scan with baseline: ").strip().lower()

    baseline_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'baseline_scan.txt')

    if action == 'generate':
        generate_baseline('baseline_scan.txt')
    elif action == 'compare':
        current_file = scan_and_save()  # Perform the current scan
        compare_scans(baseline_file, current_file)
    else:
        print("Invalid action. Please type 'generate' or 'compare'.")

if __name__ == '__main__':
    main()
