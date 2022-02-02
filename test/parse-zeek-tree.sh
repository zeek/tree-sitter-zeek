#! /usr/bin/env bash
#
# A parsing test that takes the path to a Zeek script tree as input and runs
# "tree-sitter parse" on each .zeek file in that tree. The names of erroneous
# files are reported to stdout, with a final summary of total files processed
# and number of errors occurred.
#
# For every erroneous file the script archives the input file and the
# corresponding tree-sitter error in two local files. It derives these names
# from the input file names, with slashes and other problematic characters
# substituted to "_". The error file ends in ".err".
#
# When no input directory is given, the script attempts to find a Zeek
# installation via "zeek-config --script_dir".

scriptsdir="$1"

if ! command -v tree-sitter >/dev/null 2>&1; then
    echo "This requires the tree-sitter command."
    exit 1
fi

if [ -z "$scriptsdir" ] && command -v zeek-config >/dev/null 2>&1; then
    scriptsdir=$(zeek-config --script_dir)
fi

if [ ! -d "$scriptsdir" ]; then
    echo "Please provide a Zeek scripts directory as only argument."
    exit 1
fi

total=0
errors=0

for script in $(cd "$scriptsdir" && find . -type f -name "*.zeek"); do
    # Strip leading "./" from script name
    script="${script:2}"

    # A local file name based on the input file, for storing errors.
    localfile=$(echo "$script" | sed 's/[^.a-zA-Z0-9-]/_/g')
    inputfile="$scriptsdir/$script"

    rm -f $localfile $localfile.err

    total=$((total + 1))

    tree-sitter parse "$inputfile" >output

    if [ $? -eq 0 ]; then
        rm -f output
        continue
    fi

    errors=$((errors + 1))
    echo "ERROR: $script"

    # Preserve script and error details
    cp "$inputfile" "$localfile"
    mv output "${localfile}.err"
done

echo "SUMMARY: $total files parsed below $scriptsdir, $errors errors."
[ $errors -ne 0 ] && exit 1

exit 0
