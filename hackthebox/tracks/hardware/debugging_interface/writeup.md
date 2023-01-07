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

.sal is the file extension used by the [Salae Logic Analyzer](https://www.saleae.com/)
to store signal captures.

Very simplified (to the point where it may be incorrect in some cases), a
logic analyzer is used to capture signals sent over data lines. This could be
pins connecting a chip to the circuit board, GPIO-pins etc.

Now we need to figure out how we can open the file and see the captured
signal.

Having never worked with a Salae logic analyzer before, this is probably where
I spent the bulk of the time in this challenge, trying to figure out what to do
with the file. After a few minutes I figured out that we can use Salaes
[Logic2]https://www.saleae.com/downloads/()-software to read the signal capture.

When we open the debugging_interface_signal.sal in Logic2 we can see that the
capture was done over one channel ("Channel 0") and it looks just like a large
block in the middle.
[The signal capture zoomed out](signal_zoomed_out.png "The captured signal")

If we zoom in in the white block we can see that it is actually a signal going
from high to low in a seemingly random pattern. The x-axis denotes time, and
the y-axis denotes the signal strength.
[The signal capture zoomed in](signal_zoomed_in.png "A zoomed in portion of the captured signal").

### Making sense of the signal
#### What are we actually looking at?
To answer this we need to answer the question:
"How are the bits transmitted from point A to B?" The answer is: via an
electrical signals sent either through a metal wire or through the air.
The transmitter (for example a computer with a serial debugging interface)
translates the bit stream (data) it wants to send into an electrocal signal. That
electrical signal is sent through a wire, and the receiver on the other end
reads (or samples) that voltage level and translates it back into bits.

The translation bits -> signal can be done in quite a few ways, and is referred
to as a [modulation schema](https://en.wikipedia.org/wiki/Modulation#Digital_modulation_methods).

These schemes can get quite complicated, but we are working with [asynchronous
serial communication](https://en.wikipedia.org/wiki/Asynchronous_serial_communication).
It uses the scheme: high voltage means 1, low voltage means 0 (or vice versa).

And as we can see in the last image in the previous section, there is quite a
clear distinction between a high and a low signal.

#### How do we decode the signal?
So now when we know roughly what we are looking at, how do we decode it?

We could use the information from [the wikipedia article](https://en.wikipedia.org/wiki/Asynchronous_serial_communication)
and decode this using pen-and-paper, but luckily there are protocol analyzers
available in the Logic2 software that can do the job for us. All we need to do
is to figure out the correct settings.

Looking in the right hand menu we find an analyzer labelled "[Async Serial](https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-async-serial)".

Adding this analyzer opens up a settings menu. If you ever worked with serial
interfaces before (for example on Arduino boards) you will recognize most of
these settings. They are also mention in the [the wikipedia article on asynchronous serial communication](https://en.wikipedia.org/wiki/Asynchronous_serial_communication)
as well as [his article from sparkfun](https://learn.sparkfun.com/tutorials/serial-communication/all).

For now, we can leave most of them on the default setting and focus on the bit
rate.

##### Figuring out the bit rate (number of bits per second)?
There are a few more or less commonly used bit rates, such as [9600](9600.png)
or [115200](115200.png), but when trying those we can see they don't really
yeild any readable result even when setting the analyzer to [interpret the signal as ASCII](analyzer_ascii.png).

So instead of trying to brute force our way to the correct bit rate, we need to
figure out how to calculate it from the captured signal.

To do that we can think about how a bitstream usually looks. You will very
rarely see a transmitter transmitting just a series of 1:s, or just a series of
0:s. Instead it will look sort of random, for example "1010110100101".

This means that quite often there will be a 1 surrounded by 0:s on either side
(or vice versa). In other words, the signal will be high for the duration of
***one bit*** before becoming low again quite often.

So by finding the smallest duration where the signal is in one state (high or
low) we can find out the duration of one bit. And we can use that number to
calculate the number of bits that can fit into one second.

By hovering over the signal in Logic2 we see that the shortest duration found
is 32 microseconds. In order to find how many 32 microseconds fit into one
second we simply take 1 second and divide it by 32 microseconds:

> (1 seconds) / (32e-6 seconds per bit) = 31250 bits per second

If we then input that as the bit rate in the Asynch analyzer, we should be able
to make some sense of the signal.
[The settings for the asynch analyzer](analyzer_setting.png)

Look in the "data" window in the analyzer, and we find some human readable text
containing the flag:
[The output from the analyzer interpreted as ASCII](decoded_data.png)

And in the last line we find the flag!

## Reflections
This is a quite good beginner challenge to lay the groundwork for how to work
with a signal that you don't know very much about. In a more advanced scenario
you would perhaps have to deal with multiple channels, such as synchronization
signals, receive, and transmit over seperate channels etc.

The principles we (incredibly briefly) went over here when decoding the signal
isn't just useful when using a logic analyzer to make sense of a debug
interface. The same basic principle applies when transmitting over the air in
WiFi, Bluetooth, Zigbee, 4G/5G etc.
