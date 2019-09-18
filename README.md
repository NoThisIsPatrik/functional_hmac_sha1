# functional_hmac_sha1
Python scratch implementation of TOTP (time based one-time-password) in some unusual forms

Two factor authentication is steadily gaining populatiy, which is good since passwords aren't really safe anymore.
To avoid an extra comm channel (such as sending an sms), a popular way to keep a separate secret to pass wihtout showing it is the time-base OTP,
as popularized by Google Authenticator (and used by tons of similar apps). They generally make sure there's not easy way to extract
your secret, or duplicate your authenticaiton mechanism. That's good, but sometimes one might be setting up test account, throwaway accounts.
In those instances, it's all flips on it's head - you *want* to store them with your notes, easily duplicatable, runnable anywhere without a phone.

I keep a tiny little pyton2.7 script for those occasions. But 2.7 is heading into EOL, and I needed to find a 3+ version. So.. to get a 
grip on what this protocol is, I wrote it myself. Then, because I didn't get some of it, I reimplemented the primitives and sha1.

That means this is unaudited, homebrew, just-some-guy-here crypto. Don't consider it particularly safe, on top of, well, that I intentionally
wrote it to enable poor key management.

Then I rewrote that to be funcitonal instead of iterative, to see what an immutable function chain from secret + time to output would look llike.
Then I reimplemented xor, and, addition, and so on, so that it could work on ascii strings of '0' and '1'. And that's what's here.

I'm using it to experiment with tagging bits, letting some be symbolic, etc without gettinga SAT solver and a crytpo studio going, because
really, that hasn't worked that last few brief tries, and I don't have time to go real deap on this. I'm sure there may be other uses, so
if you have one, feel free to reuse.
