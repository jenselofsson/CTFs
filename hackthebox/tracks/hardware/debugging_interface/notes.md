# Debugging Interface
Description:
```
We accessed the embedded device's asynchronous serial debugging interface while it was operational and captured some messages that were being transmitted over it. Can you decode them?
```
Files found in "Debugging Interface.zip".
Unpacking it yeilds a debugging_interfaces.sal-file.

We can use Salaes Logic2 software to do this.

Opening up debugging_interface.sal reveals a signal capture on channel zero.
We can add a Aynch serial analyzer (since the signal was captured on the 
asynchronous serial debugging interface).

We now need to know the correct settings to use, otherwise we wont be able to
decode the data.

There are a few params we need to determine. For now, lets focus on baud rate
(labelled "Bit Rate (Bits/s)" in Logic2) and leave the other params as default.

# How to determine the baud rate
(shamelessly stolen from [salae](https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-async-serial#determining-the-proper-bit-rate-baud-rate))

Baud rate means "number of symbols per second". A symbol represents a number of
bits. How many bits a symbol represents is a [whole topic](https://en.wikipedia.org/wiki/Modulation#Digital_modulation_methods)
in and of itself. For now we can assume that 1 symbol equals 1 bit, from here
on "symbol" and "bit" will be used interchangeably.

In order to transmit one bit, the transmitter transmit either a high signal
or a low signal, depending on if the bit is 1 or 0. Notice that the signal doesn't
shift instantly from low to high, but it stays in that state for some amount of
time in order to give the reciever time to read ("sample") the incoming signal.

The question we are asking is: What is the amount of time the transmitter gives
the receiver to sample one bit?

By looking at the signal in Logic2, we see that the shortest amount of time
between a high and low state is 32 microseconds.

In other words, 1 bit is transmitted every 32 microseconds. The number of bits
per seconds equals (1 second)/ (second per bit). Which in this case means
1/(32e-6) = 31250 bits per seconds.

Thus, if we use 31250 as the value for the "Bit Rate (Bits/s)"-field in the
"Async Serial"-analyzer, and changing the format to "ascii", we should get
something useful.

If we look at the "Data" field in the right hand menu we first see a bunch
of (seemingly) random hex. If we scroll down towards the end, we get something
that looks human readable:
```
[MSG] Activity from: ec1c7e7449341b58478c93c27ea6e08a53cc834279e1643dbba994a0e7f3ea43
[MSG] Activity from: 003b9434a45f0eecd2d35bcc78129aa3edc363f802ae5abdd161c4f421ca49a7
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: 223e634cea203ba2c7d4e7931a2dafdf0d452309c1a1eb1a28fc2fae057df400
[MSG] Activity from: 431d591c6eed3b6e793b316d7bf6ce2e3be51aa707680b6f14511fbc9dae9e32
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: ebb2b5d1dfbbb8174f5fb1fd15230540aea77772d3a65482def3d978f6caf152
[MSG] Activity from: f7fab4b591754a190be32cb607f257f436fa3f325d71edf41b6179c5330cd75a
[MSG] Activity from: 476bdcaf166385371f49c54ba74d275cfdfa5c70c255ea45363e3795cbc11ae5
[MSG] Activity from: 63681fa3c03451c49f9fc2ab9be43bea7f069069c1c472f6a41e3ef3a761de50
[MSG] Activity from: 36257a19934b71cea753da3df9be8ae8ca49ee843b72b1c5468f8f5dab8a7ad0
[MSG] Activity from: 36257a19934b71cea753da3df9be8ae8ca49ee843b72b1c5468f8f5dab8a7ad0
[MSG] Activity from: HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}
```

On the last line we find the flag.
