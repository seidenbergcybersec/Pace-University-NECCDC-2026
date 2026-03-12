import os
import subprocess
import sys

def make_sh_files_executable(start_dir="."):
    # Check if we are in a git repository
    try:
        subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: This directory is not a git repository or git is not installed.")
        return

    print(f"Traversing: {os.path.abspath(start_dir)}")
    count = 0

    for root, dirs, files in os.walk(start_dir):
        # Skip the .git directory itself
        if '.git' in dirs:
            dirs.remove('.git')

        for file in files:
            if file.endswith(".sh"):
                filepath = os.path.join(root, file)
                
                # Normalize path for Windows/Git compatibility
                normalized_path = filepath.replace(os.sep, '/')

                try:
                    # git update-index --chmod=+x <file>
                    subprocess.run(
                        ["git", "update-index", "--chmod=+x", normalized_path],
                        check=True
                    )
                    print(f"Fixed: {normalized_path}")
                    count += 1
                except subprocess.CalledProcessError:
                    print(f"Failed to update index for: {normalized_path}")

    print(f"\nFinished. Updated {count} .sh files.")

if __name__ == "__main__":
    # You can pass a directory as an argument, or it defaults to current directory
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    make_sh_files_executable(target_dir)