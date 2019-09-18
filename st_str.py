#!/usr/bin/python3
import time

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
        # So if nothing else, it's handy for debugging
    cache_w = 0
      
    ww = [-1]*80
    def sww(v,i):
        if not cache_w:
            return v()
        if ww[i]==-1:
            ww[i] = v()
        return ww[i]

        # like above, but with sww wrapper
    w = lambda k,i:k(i) if i<16 else sww(lambda:wrol(
        wxor(wxor(wxor(w(k,i-3),w(k,i-8)),w(k,i-14)),w(k,i-16)),1),i)

        # the 80 round sha1 loop, tail recursive
    ra = lambda L,k,i:(C(ra(L,k,i-1), k, i) if i else C(L, k, i))

        # inside main loop. S is a five-word(int32) state, whose next
        # iteration is returned in parts ( lambda S:(a,b,c,d,e) ).
        # Combined wtih moving | ^ & + from infix to functions, it
        # became rather opaque.
       
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

        # Rounds actually add to a set of five words, so here's a helper 
        # function to deal with the accumilation.
    ladd = lambda L,k: ((lambda P,Q: tuple( wand(wadd(x,y),wK(0xffffffff)) for (x,y) in zip(P,Q) ))(L,ra(L,k,79)))

    iR = ladd( 
        ('01100111010001010010001100000001', 
         '11101111110011011010101110001001',
         '10011000101110101101110011111110',
         '00010000001100100101010001110110',
         '11000011110100101110000111110000'), mf)

    ww = [-1]*80 # flush cache, if there

    return list(ladd(iR, lambda i:mf(i+16))) 

def ntotp(s, t):
    B = ''.join(f"{'abcdefghijklmnopqrstuvwxyz234567'.index(c):05b}" for c in s if c!='=')
    if len(B)%8:
        B = B[:-(len(B)%8)]

    B = B + "0"*(512-len(B))
    bK = [B[i:i+32] for i in range(0,len(B),32)]
    """
    M = [ 0, t//30 ]
    bM = []
    for a in M:
        bM.append("0"*32, bin(int(t//30))[2:].zfill(32))
    """
    bM = ["0"*32, bin(int(t//30))[2:].zfill(32)]

    biK = [wxor(a,"00110110"*4) for a in bK] # 0011(3) 0110(6)
    boK = [wxor(a,"01011100"*4) for a in bK] # 0101(5) 1100(c)

    bm = bH( boK + bH( biK + bM ) )

    bq = ''.join(bm)
    bq = bq[(((bq[-4]=='1')<<3)|
                ((bq[-3]=='1')<<2)|
                ((bq[-2]=='1')<<1)|
                (bq[-1]=='1'))<<3:][1:32]
    rvbq2 = int(bq,2)%(10**6) 

    return rvbq2 # Send them!

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
    testsome()
    quit()
    s = 'vvfmehlfxhmorcs2x2g67wgl6i65bxzl'
    t = time.time()
    print(ntotp(s,t))

if __name__=="__main__":
    main()
