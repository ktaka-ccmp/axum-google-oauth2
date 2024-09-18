# Protection Against Session Fixation in OAuth Flow

## What is Session Fixation?

Session fixation is an attack where an attacker sets a known session identifier in a user's browser, waits for the user to login, and then hijacks the session using the known identifier. This attack exploits systems that reuse session identifiers before and after authentication.

## How Your Code Protects Against It

Your implementation protects against session fixation by creating a new session with a new identifier upon successful authentication. This ensures that any pre-authentication session (which could potentially be planted by an attacker) is not carried over to the authenticated state.

Key aspects of this protection in your code:

1. **New Session Creation**: 
   In the `login_authorized` function, after successful authentication, a new session is created:

   ```rust
   let session_id = create_and_store_session(user_data, &store, expires_at).await?;
   ```

2. **Old Session Deletion**:
   Before creating a new session, the old CSRF session is deleted:

   ```rust
   delete_session_from_store(cookies, CSRF_COOKIE_NAME.to_string(), &store).await?;
   ```

3. **New Cookie Setting**:
   A new cookie with the new session ID is set:

   ```rust
   header_set_cookie(
       &mut headers,
       COOKIE_NAME.to_string(),
       session_id,
       expires_at,
       max_age,
   )?;
   ```

4. **CSRF Cookie Invalidation**:
   The CSRF cookie used during the authentication process is invalidated:

   ```rust
   header_set_cookie(
       &mut headers,
       CSRF_COOKIE_NAME.to_string(),
       "value".to_string(),
       Utc::now() - Duration::seconds(86400),
       -86400,
   )?;
   ```

## Why This is Important

1. **Breaks the Attack Chain**: By creating a new session upon successful authentication, any session identifier known to an attacker becomes invalid.

2. **Clean Slate**: Each authenticated session starts fresh, without any potential contamination from the pre-authentication state.

3. **Principle of Least Privilege**: It ensures that the elevated privileges of an authenticated session are not accidentally granted to a pre-authentication session.

4. **Complements CSRF Protection**: While CSRF tokens protect against cross-site request forgery, session fixation protection safeguards the session itself.

By implementing these measures, your code ensures that even if an attacker manages to fix a session identifier, it becomes useless once the user authenticates, as a completely new session is established.
