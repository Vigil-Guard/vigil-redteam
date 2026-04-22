# Security and Data Handling

## Test Results — Never Commit

This is a **public repository**. Test results contain sensitive operational data and must never be committed:

### Sensitive Data in Results

- **API responses** — full detection scores, threat assessments, metadata
- **Timestamps** — request/response timing that reveals system state
- **Request metadata** — session IDs, prompt IDs, agent context (if provided)
- **Metrics** — per-scenario verdicts that reflect system behavior

### Directories to Keep Local

```bash
results/          # Full JSON results with per-scenario API responses
reports/          # Markdown reports with metrics and failure analysis
```

Both are in `.gitignore` — verify they never appear in `git status`.

### Safe Practices

1. **Run benchmarks locally** or in private CI/CD systems
2. **Archive results** in private storage (e.g., encrypted S3, internal systems)
3. **Share only metrics** (recall %, FPR %, latency) in public discussions — never full result files
4. **Review `.gitignore`** before each commit: confirm `results/` and `reports/` are excluded
5. **Use `git check-ignore`** if unsure:
   ```bash
   git check-ignore results/run_*.json
   git check-ignore reports/report_*.md
   ```

### Configuration Files

- `.env` and `redteam.toml` are gitignored (contain API keys, credentials)
- Never commit credentials or API keys
- Use environment variables for sensitive config

## API Key Management

- Generate test keys via VGE's functional key endpoint
- Export as `VGE_API_KEY` environment variable (do not hardcode)
- Rotate keys regularly in production systems
- Never log or display full API keys (use truncated format `vg_test_...`)

## For Contributors

Before committing:
```bash
git status                              # Verify no result files
git diff --cached                       # Review staged changes
git check-ignore results/ reports/      # Confirm .gitignore applies
```

Avoid:
- Committing `.json` or `.md` files from `results/` or `reports/`
- Logging API responses to stdout (captures sensitive data)
- Including example results in documentation
