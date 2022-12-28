# Thoughtstream
The archive contains a .sal-file. What is it and what can I do with it?

Googling "sal file" reveals the following:
https://discuss.saleae.com/t/utilities-for-sal-files/725

which is a file from the Salae hw debugger.
I could get some hints on what to do with this from thm:s advent of cyber,
they had a HW section.

Lets try unpacking it just for the heck of it, since ***file***
reports it to be a zip-archive:
```
ls -l
total 128
-rw-r--r--@ 1 jens  staff   9697 Apr  8  2021 debugging_interface_signal.sal
-rw-r--r--@ 1 jens  staff  22090 Mar 23  2021 digital-0.bin
-rw-r--r--@ 1 jens  staff  27810 Mar 23  2021 meta.json
```

What the hell do I do with these files?

This site links to a github page:
https://support.saleae.com/saleae-api-and-sdk/protocol-analyzer-sdk

Here's a link to the guide for async serial:
https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-async-serial
https://github.com/saleae/serial-analyzer

Install the software from here:
https://www.saleae.com/downloads/

Open the application, click on the three lines in the lower right corner,
and press "Open Capture" (Cmd+O for short).
Adding a async serial analyzer as described here:
https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-async-serial

makes it so we can interpret the data as something at least.

Gotta figure out how to determine the baud rate. There is a guide for that:
https://support.saleae.com/protocol-analyzers/analyzer-user-guides/using-async-serial#determining-the-proper-bit-rate-baud-rate
