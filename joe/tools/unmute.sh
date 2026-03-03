#!/bin/sh

# Default to current directory if no argument is provided
TARGET_DIR="${1:-.}"

# Check if the target exists
if [ ! -e "$TARGET_DIR" ]; then
    echo "Error: '$TARGET_DIR' does not exist." >&2
    exit 1
fi

# Verify required tools exist (standard on Alpine/Debian/RHEL)
if ! command -v lsattr >/dev/null 2>&1 || ! command -v chattr >/dev/null 2>&1; then
    echo "Error: lsattr or chattr not found. Please install e2fsprogs." >&2
    exit 1
fi

echo "Scanning for immutable files and directories in: $TARGET_DIR"

# We remove '-type f' so find includes directories
# We use 'lsattr -d' to check the attribute of the item itself
find "$TARGET_DIR" -exec sh -c '
    for item do
        # Get the attribute string (e.g., "----i---------e-------")
        # cut -f1 ensures we only look at the first column (attributes)
        attrs=$(lsattr -d "$item" 2>/dev/null | cut -d" " -f1)

        case "$attrs" in
            *i*)
                if chattr -i "$item" 2>/dev/null; then
                    echo "LIFTED: $item"
                else
                    echo "FAILED: $item (Are you root?)" >&2
                fi
                ;;
        esac
    done
' sh {} +

echo "Done."