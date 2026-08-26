
set -ueo pipefail

#Examples relevant to openshell concepts
# Example 1 - Identity report - Script that prints a who am i report 

# identity_report() {

#     echo "Current Username: $(whoami)"
#     echo "Current user id: $(id -u)"
#     if [[ $(id -u) -eq 0 ]]; then
#         echo "Privileged"
#     else
#         echo "Unprivileged"
#     fi

# }

# identity_report

#Example 2 - Environment leak checker

# leak_checker() {

#     if env | grep -i -q "API_KEY"; then
#         echo "leaked: API_:KEY is set"
#     else
#         echo "clean: API_KEY not found"
#     fi
# }
# leak_checker

#Example 3 - file permission auditor


# file_permission_auditor() {
#     echo "Running file availability check"

#     if [[ -e "$1" ]]; then
#         echo "File exists"
#     else 
#         echo "File doesnot exist"
#     fi

#     echo
#     echo "Running file readable check"

#     if [[ -r "$1" ]]; then
#         echo "Readable by current user"
#     else 
#         echo "Not readable by current user"
#     fi

#    echo
#    echo "Running file writable check"
#     if [[ -w "$1" ]]; then
#         echo "Writable by current user"
#     else 
#         echo "Not writable by current user"
#     fi

#    echo
#    echo "Running world writable file check"

#    local perms=$(stat -c '%a' "$1")
#    if [[ $perms -eq 777 || $perms -eq 666 ]]; then
#     echo "World writable file"
#    else
#     echo "Not world writable file"
#    fi

# }

# file_permission_auditor dummy.txt

##Example 4 - Safe subprocess runner 
run_isolated(){

    if [[ "$#" -eq 0 ]]; then
        echo "Pass atleast 1 argument"
        return 1
    else
        env -i PATH="$PATH" "$1"
        echo "Exit status : $?"
       
    fi

}

run_isolated ls






