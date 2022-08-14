#!/usr/bin/bash

# When the script hangs, the correct port has been found.
start=9000
end=13999
middle=$(( $start+ ( ( $end - $start ) / 2 ) ))

loop=1
while [ $loop -eq 1 ]; do
  resp=$(ssh -oHostKeyAlgorithms=+ssh-rsa -o "StrictHostKeyChecking=no" -p $middle 10.10.88.109 2>/dev/null)

  if [[ "$resp" == "Lower"* ]]; then
    echo "$middle: Port is lower";
    start=$middle;
  elif [[ "$resp" == "Higher"* ]]; then
    echo "$middle: Port is higher";
    end=$middle;
  else
    echo "Unexpected response for port $middle: $resp";
    loop=0;
  fi
  middle=$(( $start+ ( ( $end - $start ) / 2 ) ));
  echo "New middle is $middle";
done

