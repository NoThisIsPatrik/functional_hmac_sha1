#!/usr/bin/python3
import time

__author__ = "Patrik Lundin" 
__copyright__ = "Copyright 2018, nothisispatrik.com" 
__license__ = "LGPL v3. Algos are whatever SHA1/HMAC/TOTP are, code is 100% from scratch"
__email__ = "patrik@nothisispatrik.com"
__status__ = "Prototype"
__doc__ = """A reimplementation of TOTP, like the thing Google Authenticator et al uses. Do not rely on this for security. Reimplementing primitives like this isn't safe, or at least not nearly as safe as using proper audited ones.
Started as a small reassemble from the crypto primitives, as the TOTP client lib I sometime use isn't in python 3. Then I wondered about perhaps implementing a bare-bones version without so many depenednecies. Once that worked, some parts do not feel like they could fully be safe (beyond that sha1 is dated), so I rearranged it into a functionally expressed version to have a unbroken chain of immutable stateless function calls from key+time -> number. Because it's hard to see the bits, I moved the math/bit primitives into calls working on ascii strings of "0" and "1". That's what this file is.
"""

    # Do logic on string of '0' and '1'
def bitxor(a,b): return {"00":"0", "01":"1", "10":"1", "11":"0"}[a+b]
def bitor(a,b):  return {"00":"0", "01":"1", "10":"1", "11":"1"}[a+b]
def bitand(a,b): return {"00":"0", "01":"0", "10":"0", "11":"1"}[a+b]

    # Do a one bit op on a two longer strings
def wdo(wa,wb,f):  return ''.join( f(a,b) for (a,b) in zip(wa,wb))

    # Higher order func:s like some academic..
def wor(wa,wb): return wdo(wa,wb,bitor)
def wxor(wa,wb): return wdo(wa,wb,bitxor)
def wand(wa,wb): return wdo(wa,wb,bitand)

def wK(k): # make a b form int32
    return bin(k)[2:].zfill(32)

    # rotate left, string version
def wrol(wa, n): return wa[n:]+wa[:n]

    # shift left
def wshl(a): return (a[1:]+ "0")

    # implement + (add) using and/or/xor
def wadd(a,b):
        # Carry, prelim Result
    c, r =  wand(a,b), wxor(a,b)  
        # could be terminated when c==0, but stuff beyond
        # c==0 will cancel out anyway, being zero and all..
    for _ in range(32):
        sc, c, r = wshl(c), wand(r, wshl(c)), wxor(r, wshl(c))
    return r

def bH(bm):
        # map "message" to "correctly padded messgae"
    mf = lambda i:(
        bm[i] if i<len(bm) else 
        "10000000000000000000000000000000" if i==len(bm) else 
        bin(len(bm)*32)[2:].zfill(32) if i==31 else
        "00000000000000000000000000000000" )

        # Key expansion. As pure no-state function, this ends up being
        # huge - w(73) depends on w(70), which in turn on w(67),64,61...
        # w/ four branches ea. 

    #w = lambda k,i: (k(i) if i<16 else wrol(
    #    wxor(wxor(wxor(w(k,i-3),w(k,i-8)),w(k,i-14)),w(k,i-16)),1))

        # There's now a bypassable option to cache those. It makes it`
        # no longer stateless, but speeds it up from 1-2min to ~.3-.5 sec.
        # So if nothing else, it's handy for debugging.
    cache_w = 1
      
        # Little stateful cache wrapper
    ww = [-1]*80
    def sww(v,i):
        if not cache_w:
            return v()
        if ww[i]==-1:
            ww[i] = v()
        return ww[i]
        
        # map padded message to fully expanded message, given a function that produces the
        # padded message and the postition (first 16 words copied, 16-80 a chain of xors of
        # earlier ones). The parameterless lambda passed into sww will calculate it by recursing
        # w() if called directly. sww will call it once for each i and cache it (or always if
        # cache_w is 0)
        
    w = lambda k,i:k(i) if i<16 else sww(lambda:wrol(
        wxor(wxor(wxor(w(k,i-3),w(k,i-8)),w(k,i-14)),w(k,i-16)),1),i)


        # inside main loop. S is a five-word(int32) state, whose next
        # iteration is returned in parts ( lambda S:(a,b,c,d,e) ).
        # Combined wtih moving | ^ & + from infix to functions, it
        # became rather opaque, but it will return a new state form
        # the prior state 'S', a function to access current round data 'k',
        # and which sub-round this is 'i'.
       
    C = lambda S,k,i:(wadd(wadd(wadd(wadd(wrol(S[0],5) , (
        wxor(S[3],wand(S[1],wxor(S[2],S[3]))),
        wxor(wxor(S[1],S[2]),S[3]),
        wor(wor(wand(S[1],S[2]),wand(S[1],S[3])),wand(S[2],S[3])),
        wxor(S[1],wxor(S[2],S[3]))
        )[i//20]), S[4]), (
        '01011010100000100111100110011001',
        '01101110110110011110101110100001',
        '10001111000110111011110011011100',
        '11001010011000101100000111010110')[i//20]), 
        w(k,i)), S[0], wrol(S[1],30), S[2], S[3])

        # runs 'i' loops of C, recursively chainign them ( (C(C(C,k,0),k,1)....),k,79) ),
        # like the normal loop would but as immutable chain instead of updated state
    ra = lambda L,k,i:(C(ra(L,k,i-1), k, i) if i else C(L, k, i))

        # Multiple loops (each doing a block) actually add the 80-round-grinded-out state
        # to the prior state. So here's an accumilator func to do that, calls ra(), adds
        # the prior state, and returns is, ready to chain to more blocks.

        # The number of blocks is actually hardcoded to two here. Just from the HMAC spec,
        # it be just one - it'd get hashed and padded so that it'd be two by here. I haven't
        # seen anything saying it can't be three blocks, but most secrets are 16-20 bytes. 
        # The average authenticator QR code encodes digits/periods too (which, granted, I ignore)
        # looking something like:
        # otpauth://totp/combined?secret=vvfmehlfxhmorcs2x2g67wgl6i65bxzl&algorithm=SHA1&digits=6&period=30
        # (a 97 char payload). That would have to go up to 280ish to get a three blocker, which
        # certainly doesn't violate the QR or url limits or anything, but it is a busy code/long url
        # and I haven't seen one so far.
        
    ladd = lambda L,k: ((lambda P,Q: tuple( wadd(x,y) for (x,y) in zip(P,Q) ))(L,ra(L,k,79)))

        # The 5x32 words here is the sha1 init vector, constant per spec. 'mf()' is where to get the
        # data. I temp stoe in iR here rather than (more purely funcitonal) pass it to the next block
        # because if we *are* cheating with the cache thing, it needs reset each block. Dropping it
        # into the next ladd(.. works fine.

    iR = ladd( 
        ('01100111010001010010001100000001', 
         '11101111110011011010101110001001',
         '10011000101110101101110011111110',
         '00010000001100100101010001110110',
         '11000011110100101110000111110000'), mf)

    ww = [-1]*80 # flush cache, if there

        # Second round. The finalizing-padding-digesting thing was just done with the inital pad/prep,
        # easier that way we know up front there won't be more data suddenly showing up. To offset
        # what to read in the input data, I just make a fresh function "lambda i:f(i+16)" to hit block
        # two. If there were more blocks, we could keep iterating them by applyting this to itself
        # for future blocks to keep shoving it 16x32=512 bits forward until it ran out.
    return list(ladd(iR, lambda i:mf(i+16))) 

def ntotp(s, t):
        # Base32 decoder. Not completely flow-through here, since it's just massaging the data
    B = ''.join(f"{'abcdefghijklmnopqrstuvwxyz234567'.index(c):05b}" for c in s.lower() if c!='=')
    if len(B)%8:
        B = B[:-(len(B)%8)]

        # Pad
    B = B + "0"*(512-len(B))
        # Break into 32 bit words, ready for hashign
    bK = [B[i:i+32] for i in range(0,len(B),32)]

        # Same format for the time, or actually number of intervals (default 30s) since the epoch,
        # 64 bit bit width. I presume we're pre-2106 like a punk badass and just zero pad - sha1
        # surely must be irrelevant by then..
        
    bM = ["0"*32, bin(int(t//30))[2:].zfill(32)]

        # HMAC will want an inner and outer key for it's thing, so I make them.
    biK = [wxor(a,"00110110"*4) for a in bK] # 0011(3) 0110(6)
    boK = [wxor(a,"01011100"*4) for a in bK] # 0101(5) 1100(c)

        # hash the inner key concat the time, then the outer concat the result.
    bm = bH( boK + bH( biK + bM ) )
        # Cleared HMAC and SHA1, time for TOTP again. Take the 4 LSBits from the result, offset
        # into the whole result from the MSB by that many byte, get 32 bits from there. Then 
        # clear the MSB on those 32 bits ([1::32] skips getting it) to ensure signed/unsigned 
        # won't be a hassle. Convert to decimal, get the 6 LS..Ds? Yeah, least siginificant digits..

    bq = ''.join(bm)
    bq = bq[(((bq[-4]=='1')<<3)|
                ((bq[-3]=='1')<<2)|
                ((bq[-2]=='1')<<1)|
                (bq[-1]=='1'))<<3:][1:32]
    rvbq2 = int(bq,2)%(10**6) 

    return rvbq2 # Send them!
        # This looks like I do a lot of tmp vars rather than piling the funcs together, and indeed
        # I did. They do drop into each other just fine, but some of these do things that venture
        # out of the ascii '01's box. Some of that is ok, but next step (to me) here is to start
        # marking/differentiating/symbol-evaluating some of the bits, which will make some of it
        # less fine again, and having them a little more spread out will be helpful. It doesn't *really*
        # change anything since they're fairly explicitly not interacting between states.

    # Very arbitrary test values
def testsome(): 
    t = 0  
    loud = 0 # Shout results during?

        # Correct premade results. Three kind of arbitrary b32 keys,
        # Their result at three even more arbitrary times.
    prec = [
        ['orcs2x2g67wgl6i65bxzl===', [u'713332', u'511624', u'768573'], 1],
        ['vvfmehlfxhmorcs2x2g67wgl6i65bxzl', [u'416665', u'993192', u'137491'], 2], 
        ['xhmorcs2x2g67wgl6i65bxzl', [u'294243', u'134723', u'167641'], 3]
        ]

    for sc,rr,tn in prec:
        fail = 0
        for t in range(0,9000,3123): # Three times per key 
            a = int(rr.pop(0)) # pre-provied result

            b = ntotp(sc, t) 
            print(repr(a),repr(b))
            if a!=b: # b ok?
                print(f"a={a}!=b={b} (c={c})")
                fail |= 1
            elif loud: # Show them?
                print(f"a={a}==b={b}==c={c}")

        if fail: # Summarize.
            print(f"t{tn}: FAIL {bin(fail)}")
        else:
            print(f"t{tn}: PASS")

def main():
    #testsome()
    #quit()
            # if test/quit is commented out, run a TOTP round and present..
    s = 'vvfmehlfxhmorcs2x2g67wgl6i65bxzl'
    t = time.time()
    print(f"One time code: {ntotp(s,t)}")
    print(f"Changes in {30-t%30} seconds")

if __name__=="__main__":
    main()
