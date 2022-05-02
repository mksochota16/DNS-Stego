#!/usr/bin/env zsh

#shuffle
cat urls | shuf -o urls

encode() {
    curl https://$movie >> /dev/null
}

FIFO=$(mktemp -t fifo-XXX)
LOCK=$(mktemp -t lock-XXX)

rm $FIFO
mkfifo $FIFO

cleanup() {
  rm $FIFO
  rm $LOCK
}
trap cleanup EXIT

do_work(){
    ID=$1
    exec 3<$FIFO
    exec 4<$LOCK

    while true
    do
        flock 4
        read -st -u 3 movie
        status_code=$?
        flock -u 4
        #on new item
        if [ $status_code -eq 0 ]
        then
            echo "Worker" $ID "is encoding file " $movie
            encode $movie
            echo "Worker" $ID "has finished encoding file " $movie
        # on timeout
        elif [ $status_code -gt 128 ]
        then
            continue
        # on EOF
        else
            break
        fi
    done

    exec 3<&-
    exec 4<&-
    echo "Worker" $ID "has finished"
}

CORES=`nproc --all`
echo $CORES "cores detected - starting" $CORES "workers."

# start workers

for i in {1..$CORES}
do
    echo "Starting worker" $i
    do_work $i &
done

# open fifo

exec 3>$FIFO

# assign jobs
input="urls"
while read -r line
do
  echo "$line" 1>&3
done < "$input"

# close fifo

exec 3<&-

wait
