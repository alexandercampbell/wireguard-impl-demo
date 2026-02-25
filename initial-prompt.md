
Hello Claude!

This is a challenge to see if you and I working together can implement a
wireguard server for the 9front operating system.

The challenge was issued by a friend, who claims we can't do it. He has
implemented something similar by hand, himself.

According to him, these are the key features:

>1. implemented blake2 hashing from scratch, with test vectors
>2. full client implementation of the vpn protocol, inlcuding sessions and keep alives

>there's a lot of edge cases around keeping sessions alive from a clients
perspective, so the test is that if you get a wireguard server setup on a
linux machine, the client should be able to connect and deal with intermittent
connection loss and having to replay traffic

The wireguard whitepaper is here in the pwd with the filename `wireguard-whitepaper.pdf`.

We'll need to test this on the 9front iso, probably using Qemu. But I imagine
much of the code can be written in C89 by us and tested here on this Debian
instance.

