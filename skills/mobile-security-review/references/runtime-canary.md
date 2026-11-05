# Synthetic canary checks

Run this check against local captures from an authorized Android test flow. A canary is a unique fake value that you deliberately pass through one sensitive input. Its presence in a capture shows where that value appeared.

1. Generate a new marker for each flow and run. Put it in a file and use the same value in the test account, mock response, or other controlled input. Use synthetic data throughout.
2. Record the app variant, device/API, test steps, collection window, and expected destinations. Capture app-relevant Logcat output and selected storage files from the authorized test build. Keep captures outside version control. Verify that each collection command succeeded before scanning its output. Include database sidecar files separately when relevant.
3. Run the checker with the canary file and captures.

```sh
python3 -c 'import secrets; print("MSR_CANARY_" + secrets.token_hex(16))' > canary.txt

# After exercising the flow and saving the captures:
python3 <skill-dir>/scripts/check_canary.py \
  --canary-file canary.txt \
  --logcat captured-logcat.txt \
  --storage captured-preferences.xml
```

Repeat either capture flag for additional files. For device collection, see the Android documentation for [ADB](https://developer.android.com/tools/adb) and [Logcat](https://developer.android.com/tools/logcat). Log buffers, process selection, and capture timing affect what reaches the scanner.

The checker emits JSON with the result per file and the zero-based byte offset of the first match. It omits content excerpts and redacts the marker in reported paths. File paths can still contain sensitive names. Exit 0 means no exact match in the supplied files. Exit 1 means at least one match. Exit 2 takes precedence when any capture is incomplete or arguments are invalid. An empty Logcat file is treated as incomplete. An empty storage file is valid.

For a match, verify that the capture belongs to the current flow and that test instrumentation did not write the marker itself. Assess storage matches against expected behavior. For example, a token present during a session and a token left behind after logout are different observations. Test separate before and after captures when checking cleanup.

Matching is case-sensitive and byte-for-byte. Encoded, transformed, compressed, or encrypted values require separate checks. The tool reads only the supplied files. Report missing surfaces and any capture window or process gaps alongside the result.
