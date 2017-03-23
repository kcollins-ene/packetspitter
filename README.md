# Packet Spitter

This was developed for a very specific testing purpose, but is a simple python routine that listens for a connection and then begins sending packets to a connected client at a given rate.  

## Usage

Execute with `1000ms` frequency, listening on port `8888`, verbose output:

`./PacketSpitter.py -r 1000 -p 8888 -v`

## Packet Contents

The payload of the packet is a ASCII 19-digit zero-padded timestamp of UTC milliseconds since Unix Epoch followed by a CR (0x0D), for example:

```
0000001490303038014\r
```

