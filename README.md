
# udpfwd
couldn't get socat working on windows. forwards udp packets to and from one
address to another.

for windows users that need tcp port forwarding i suggest `netsh interface portproxy`

# arguments
+ `--destination` (`-d`) the destination address in `addr:port` format. note that
  ipv6 addresses must be wrapped in square brackets (e.g. `[::1]`).
  this option also supports domain names.
+ `--listen-port` (`-p`) the port to listen on
+ `--no-ipv4` (`-6`) listen on the ipv6 stack only.
+ `--no-ipv6` (`-4`) listen on the ipv4 stack only.
+ `--loopback` (`-l`) listen on loopback only. (e.g. `127.0.0.1` and `[::1]`)

# build
clone submodules
use cmake
:p
