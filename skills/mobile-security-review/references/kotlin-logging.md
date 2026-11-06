# Review Kotlin logging

Run the checker on the Kotlin files relevant to the review. Choose files for the app modules and variants in scope.

```sh
python3 <skill-dir>/scripts/check_kotlin_logs.py path/to/Session.kt path/to/Login.kt
```

Rule `MSR007` looks for direct calls to [Android Log](https://developer.android.com/reference/android/util/Log) methods `v`, `d`, `i`, `w`, `e`, and `wtf`. It recognizes the fully qualified receiver and the short receiver with an explicit `import android.util.Log`.

The second argument must be a bare identifier or a string with a simple template reference, such as `Log.d(TAG, "session: $accessToken")`. Names are matched against a fixed list including access and refresh tokens, passwords, API keys, and client secrets. Case and underscores are ignored. Comments, plain literal text, and unrelated names such as `accessTokenCount` do not trigger the rule.

The JSON report contains file paths, one-based call lines, and rule IDs. It omits source excerpts and values. Exit 0 means no candidates in the supplied files. Exit 1 means candidates were found. Exit 2 means some input was incomplete or invalid, even if other files produced candidates.

Review the value, the actual logger binding, the release variant, and the destinations where logs are retained. A name match is a review candidate. Trace where the value comes from and confirm the affected build before assigning impact. A synthetic canary test can corroborate runtime exposure.

This lexical check covers only the selected forms. It has no Kotlin symbol resolution or data flow and does not analyze complex expressions, aliases, concatenation, wrappers, throwable contents, Java, or runtime logging configuration. Verify any redaction function separately.
