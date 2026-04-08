#!/bin/bash

# Get the directory this script is located in
PROJECT_FOLDER=$( dirname "$(realpath "$0")" )
cd $PROJECT_FOLDER || exit 1

printf "\n\nPROJECT_FOLDER = ${PROJECT_FOLDER}\n\n"

# Show errors
printf "\nPrint all clang-format errors:\n\n"
find . -not -path "./cmake-build-*/*"  -type f \( -name "*.cpp" -o -name "*.hpp"  -o -name "*.h" \) -print0 | xargs -0 -I{} clang-format -i {} --dry-run --Werror -style=file:.clang-format

# Fix errors
printf "\nApplying fixes...\n"
find . -not -path "./cmake-build-*/*" -type f \( -name "*.cpp" -o -name "*.hpp"  -o -name "*.h" \) -print0 | xargs -0 -I{} clang-format -i {} --Werror -style=file:.clang-format
printf "\nDone\n"