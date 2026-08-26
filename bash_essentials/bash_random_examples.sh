#!/usr/bin/bash
set -euo pipefail

ls -la both.txt 1>> correct.txt 2>>bad.txt

ls both.txt > test1.txt 2>&1

ls ~ | grep "a"

ls -la abc.txt >> both.txt 2>&1

ls abc.txt 2>> err.txt ##Its interetsing that if you give a space ot breaks the flow of data

status=pending
echo "before update - $status"
update_status() {
    status=done
}
update_status
echo "After update_status - $status"


square_number() {
echo $(( $1*$1 ))
}

result=$( square_number 10 )
echo $result

odd_or_even() {
    if [[ $(($1 % 2)) -eq 0 ]]; then
        echo "Even"
    else
        echo "Odd"
    fi

}

odd_or_even 31

show_date() {
    date
}

show_date

counter=0

increment() {
    local counter=99
    echo "Inside func counter $counter"
}

increment
echo "Outside counter $counter"


add() {
func_result=$(( $1+$2 ))
echo $(( $1+$2 ))
}

result=$( add 3 100 )
echo "$result"
echo "$func_result"


greet_people() {
  echo "$3, $2, $1"
}

greet_people Donkey Monkey Honkey




say_hello() {
  echo "Hello"
}

say_hello


while read -r line || [[ -n "$line" ]]; do
  echo "$line"
done < simple.txt

count=1
for item in $@; do
  echo "Item number - $count and item - $item"
  count=$(( count+1 ))
done


for i in {1..10}; do
  echo "$i"
done


count=1
while [[ "$count" -le 10 ]]; do
  echo "$count"
  count=$(( count+1 ))
done


for item in apple banana cherry; do
  echo "$item"
done

read -p "Enter your username: " uname

if [[ $1 -eq 0 ]]; then
    echo "Zero"
elif [[ $1 -lt 0 ]]; then
    echo "Negative"
else
    echo "Positive"
fi




type while

if [[ -f "./simple.txt" ]]; then
    echo "File exists"
else
    echo "not found"
fi



#Conditionals
if [[ -f ~/Desktop/openshell/simpl.txt ]]; then
    echo "File exists"
elif [[ -d ~/Desktop/openshel ]]; then
    echo "Directory exists"
else
    echo "Neither file nor directory exists"
fi


CURRENT_PID=$$ ##Get the PID of the bash shell in use
echo "Current PID - $CURRENT_PID"
echo "$BASHPID"

if ps -p $CURRENT_PID > /dev/null;then
    echo "I am still alive"
fi

echo $?

( x=999; echo "inside subshell, x=$x"; )
echo "After subshell, x=$x"

{ x=999; echo "inside group x=$x"; }
echo "After group, x=$x"





echo "Hello. How are you?"

#Create a simple variable and print it
NAME="Alice"
echo "$NAME"

#Create a number and update it
NUM=1000
echo "$NUM"
echo "After updating - $((NUM * 8))"

#Create a readonly variable and update it
readonly SIMPLE_VARIABLE=200
echo "$((SIMPLE_VARIABLE + 20))" ##this works as you are not modifing the variable in memory
#SIMPLE_VARIABLE+=50   #This will throw error
#echo "$SIMPLE_VARIABLE"