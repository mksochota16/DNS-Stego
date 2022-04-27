#shuffle
cat urls | shuf -o urls

#download whole pages
cat urls | while read line ; do curl https://$line >> /dev/null ; done

#only dns requests
#cat urls | while read line ; do host $line >> /dev/null ; done
