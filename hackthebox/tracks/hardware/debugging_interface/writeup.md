# Writeup: Debugging Interface

This is a write up of the [Debugging Interface](https://app.hackthebox.com/challenges/207)-challenge
in the [Intro to Hardware Hacking](https://app.hackthebox.com/tracks/Intro-to-Hardware-Hacking)
track.

## Description
> We accessed the embedded device's asynchronous serial debugging interface while it was operational and captured some messages that were being transmitted over it. Can you decode them?

## Solution
There is no machine to connect to in this challenge, just a file (Debugging Interface.zip)
to analyze.

### Making sense of the zip-file
Unpacking it, we find that it contains debugging_interface_signal.sal.

Now we hit the first problem. What is a .sal-file? By googl:ing "sal file", we
find that it's the file extensions used by the [Salae Logic Analyzer](https://www.saleae.com/).

Very simplified, a logic analyzer is used to capture signals sent over data lines,
such as a "asynchronous serial debugging interface" as stated in the description.

Now we just need to figure out how we can open the file and see the captured signal.

This is where I probably spent the bulk of the time in this challenge. After a
few minutes I figured out that we should use Salaes [Logic2]https://www.saleae.com/downloads/()-software.

When we open the debugging_interface_signal.sal in Logic2 we can see that the
capture was done over one channel ("Channel 0") and it looks just like a large
block in the middle.
[The signal capture zoomed out](signal_zoomed_out.png "The captured signal")

If we zoom in in the white block we can see that it is actually something useful
[The signal capture zoomed in](signal_zoomed_in.png "A zoomed in portion of the captured signal").

### Making sense of the signal
#### What are we actually looking at?
Baud rate means "number of symbols per second". A symbol represents a number of
bits. How many bits a symbol represents is a [whole topic](https://en.wikipedia.org/wiki/Modulation#Digital_modulation_methods)
in and of itself. By looking at the zoomed in signal we can see that the signal
have two states, high or low, meaning that it can only represent one bit ("1"
or "0").

There are [other techniques](https://en.wikipedia.org/wiki/Modulation#Digital_modulation_methods)
that can be used to make one symbol represent multiple bits.

In order to transmit one bit, the transmitter transmit either a high
or a low signal, depending on if the bit is 1 or 0. The reciever takes a snapshot
("samples") the input signal X amount of times per second. If a sample is high
the receiver assumes that it is a 1, if it is low the reciever assumes
that it is a 0. It could also be the other way around, high means 0 and low
means 1, so this is something that need's to be agreed upon beforehand.

#### How do we calculate the correct bit rate?
"Bit rate" means "how many bits per second". Looking back at the previous
paragraph, in other words "how many time per second do the reciever take a
snapshot of the signal?"

We can think about how a bitstream usually looks. You will very rarely see a
transmitter transmitting just a series of 1:s, or just a series of 0:s.
Instead it will look random "100110100101", meaning quite often there will be a
1 surrounded by 0:s on either side (or vice versa).

So by finding the smallest duration where the signal is in one state (high or
low) we can find out the duration of one bit. And we can use that number to
calculate the number of bits that can fit into one second.

In this case we can find this to be 32 microseconds

1/duration = bit-rate => 1 / 32e-6 = (1/32)e6 = 31250 bits per second.

If we then input that as the bit rate in the Asynch analyzer, we should be able
to make some sense of the signal.
[The settings for the asynch analyzer](analyzer_setting.png)

One of the ways to interpret the data is a ASCII.

Look in the "data" window in the analyzer, and we find some human readable text
containing the flag:
[The output from the analyzer interpreted as ASCII](decoded_data.png)

And in the last line we find the flag!

## Reflections
I found this to be a quite good beginner challenge to lay the groundwork for
how to work with a signal that you don't know very much about.
In a more advanced scenario you would perhaps have to deal with multiple
channels, such as synchronization, receive, and transmit over seperate channels
etc.

The principles we went over here wrt decoding the signal isn't just useful when
using a logic analyzer to make sense of a debug interface. The same basic
principle applies when transmitting over the air in WiFi, Bluetooth, Zigbee,
4G/5G etc.

The field of "how to transmit data from point A to point B over the air" is a
really interesting subject and I'm hoping to be able to dive more into it in
the future.
