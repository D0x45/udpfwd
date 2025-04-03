
# udpfwd
for times when you're not sure if it's `socat` (or `netcat`) acting out or your
network stack is failing.

for windows users that need tcp port forwarding i suggest `netsh interface portproxy`

# arguments
+ `--destination` (`-d`) the destination address in `addr:port` format. note that
  ipv6 addresses must be wrapped in square brackets (e.g. `[::1]`).
  this option also supports domain names.
+ `--listen-port` (`-p`) the port to listen on
+ `--no-ipv4` (`-6`) listen on the ipv6 stack only.
+ `--no-ipv6` (`-4`) listen on the ipv4 stack only.
+ `--loopback` (`-l`) listen on loopback only. (e.g. `127.0.0.1` and `[::1]`)

the current dummy implementation under `src/worker.c` is quite cpu-intensive as it
does not use `select` or `poll` since i didn't feel like going through the
trouble. better implementations are most certainly welcome.

NOTE: this is a hobby project and it was meant for finding out what's wrong in
      my network stack as `netcat` and `socat` failed for ipv6 forwarding!
      this work is dedicated to the public domain.

