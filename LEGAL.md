# Legal & Ethics

AMWE is a defensive tool. It exists so you can see your own exposure before an
attacker does. These rules are not decoration — they define what AMWE is.

## The ten rules

1. **Self-scan only.** AMWE runs against an address you can prove you control,
   or against someone who has explicitly asked you to scan them.
2. **Ownership is enforced in code.** The verification step gates every
   collector. A build that removes it is not AMWE.
3. **Public sources only.** AMWE reads what a logged-out browser can read.
   It never bypasses logins, CAPTCHAs, rate limits, or any access control.
4. **No credential capture, ever.** The simulated login page rejects all input
   by design. Nothing typed into it is stored or sent anywhere.
5. **Local by default.** Findings stay on your machine. Profiling runs locally.
   No data is sent to any third party.
6. **No third-party personal data.** AMWE does not aggregate or store data about
   people other than the verified target.
7. **No weaponization.** The phishing output is a teaching artifact shown to the
   target themselves. It is not a tool for sending attacks to others.
8. **No "legally safe" promises.** AMWE documents a process; it is not legal
   advice and makes no guarantees.
9. **Honest findings.** AMWE reports what it actually found and marks what it
   could not determine as unknown.
10. **Consent before every assisted scan of another person**, recorded by the
    operator. The responsibility for target choice is the user's.

## For contributors

Any pull request that weakens the ownership check, adds credential capture,
targets third parties, or bypasses access controls will be declined on sight.
See [SECURITY.md](SECURITY.md) to report misuse.
