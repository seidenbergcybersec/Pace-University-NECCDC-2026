import psutil
import os

# Read baseline services from a file
def read_baseline(file_path):
    with open(file_path, 'r') as f:
        baseline_services = f.read().splitlines()
    return baseline_services

# Get currently running services
def get_running_services():
    running_services = []
    for proc in psutil.process_iter(['pid', 'name']):
        running_services.append(proc.info['name'])
    return set(running_services)

# Generate a baseline file of currently running services
def generate_baseline(file_name):
    # Get the current directory where the script is located
    current_directory = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_directory, file_name)
    
    running_services = get_running_services()
    with open(file_path, 'w') as f:
        for service in running_services:
            f.write(service + '\n')
    
    print(f"Baseline file '{file_path}' has been generated with {len(running_services)} services.")

# Compare current running services with the baseline
def compare_services(baseline_file):
    # Current directory where the script is located
    current_directory = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_directory, baseline_file)

    baseline_services = read_baseline(file_path)
    current_services = get_running_services()
    
    new_services = current_services - set(baseline_services)

    if new_services:
        print("Services running that weren't in the baseline:")
        for service in new_services:
            print(service)
    else:
        print("No new services found that weren't in the baseline.")

def main():
    action = input("Type 'generate' to generate a baseline or 'compare' to compare current services: ").strip().lower()
    
    baseline_file = 'baseline_services.txt'

    if action == 'generate':
        generate_baseline(baseline_file)
    elif action == 'compare':
        compare_services(baseline_file)
    else:
        print("Invalid action. Please type 'generate' or 'compare'.")

if __name__ == "__main__":
    main()
