#!/usr/bin/python3
import time

def H(m):
        # need rotate left (primitives only has shifts)
    rol = lambda n,b:((n<<b)|(n>>(32-b)))&0xffffffff

        # msg -> padded msg function map
    mf = lambda i:(
        m[i] if i<len(m) else           # Message
        0x80000000 if i==len(m) else    # a single '1' bit..
        (len(m)*32) if i==31 else       # Message lenth in bits as int32 last
        0)                              # Rest is zeros

        # expanded key pos -> key.
    w = lambda k,i: k(i) if i<16 else rol(w(k,i-3)^w(k,i-8)^w(k,i-14)^w(k,i-16),1)
        # sha1 80 round loop, tail recurse
    ra = lambda L,k,i:(C(ra(L,k,i-1), k, i) if i else C(L, k, i))

        # inner loop. 
    C = (lambda S,k,i:((rol(S[0],5) + (
                        (S[3]^(S[1]&(S[2]^S[3]))),
                        (S[1]^S[2]^S[3]),
                        (((S[1]&S[2])|(S[1]&S[3]))|(S[2]&S[3])),
                        (S[1]^S[2]^S[3])
                        )[i//20] + S[4] + 
                    ( 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6)[i//20] + 
                    w(k,i)&0xffffffff),S[0],rol(S[1],30),S[2],S[3]))

        # Accumilator 
    ladd = lambda L,k: (
        (lambda P,Q:tuple( (x+y)&0xffffffff for (x,y) in zip(P,Q) ))(
            L, ra(L,k,79) ))

    return list(ladd(ladd(
                (0x67452301,0xefcdaB89,0x98Badcfe,0x10325476,0xc3d2e1f0), mf)
                ,lambda i:mf(i+16))) 

def ntotp(s, t):
        # b32 unpacker. Just being cutesy and going for zero deps
    bM = ''.join(f"{'abcdefghijklmnopqrstuvwxyz234567'.index(c.lower()):05b}" for c in s if c!='=')

    if len(bM)%8:  # This is what two other b32 decoders do at least. <shrug>
        bM = bM[:-(len(bM)%8)]

    bM = bM + "0"*(512-len(bM))

    K = [int(bM[i:i+32],2) for i in range(0,len(bM),32)]
    M = [ 0, t//30 ]

    return (lambda t:((t>>(160-32-(t&15)*8))&0x7fffffff)%10**6)(
        (lambda h:sum(h[i]<<((4-i)*32) for i in range(5)))(
            H([a^0x5c5c5c5c for a in K] + H([a^0x36363636 for a in K]+M)) ))

def test_some():
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
                print(f"a={a}!=b={b}")
                fail |= 1
            elif loud: # Show them?
                print(f"a={a}==b={b}")

        if fail: # Summarize.
            print(f"t{tn}: FAIL")
        else:
            print(f"t{tn}: PASS")

def main():
     # OTP_KEY = "gq5edg4zut7kmuec"
     OTP_KEY = "G5JVITRXJFDTCRCP"

     t = time.time()
     print( ntotp(OTP_KEY, int(t)) )
     print(f"Key will change in {30-(t%30):.2f} s")

if __name__=="__main__":
    main()
