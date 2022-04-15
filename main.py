
from flask import Flask, jsonify, request, session, redirect
from passlib.hash import pbkdf2_sha256
from app import db
import uuid
#array=list(db.user_login_system.users.find({}, {"_id": 0, "password":1}))
#print(array)
array={"kani":"kanikani","mouthika":"mouths","aishwarya":"aishaish","trial":"trial123","vasu":"vasuvasu","harry":"harry","kala":"kala"}
import random
import time

DEBUG = True

def rand():
    return random.randint(0, 2147483647)

calcul = [0 for i in range(100)]  # int calcul[100];

# Fonction puissance
def puissance(a, b):
    if b == 0:
        return 1
    if b == 1:
        return a
    tmp = puissance(a, b//2)
    if b % 2 == 0:
        return tmp*tmp
    else:
        return tmp*tmp*a


# Generation of a prime number between 5 and 199
 # with the Miller-Rabin algorithm
def premier(q):
    while True:
        m = rand() % 200
        if (m < 5) or (m == q):
            continue
        # m : m=2^s*t
        s = 0
        m2 = m - 1
        while m2 % 2 == 0:
            m2 /= 2
            s += 1

        t = (m-1) // puissance(2, s)
        # test primality
        cpt = 0
        while cpt < 20:
            a = rand() % (m-1) + 1
            u = (puissance(a,t)) % m
            if u == 1:
                b = True
            else:
                i = 0
                b = False
                while (i < s) and (b == 0):
                    if (u == m-1) or (u == -1):
                        b = True
                    else:
                        b = False
                    u = (u*u) % m
                    i += 1
            if not b:
                cpt = 21
            else:
                cpt += 1
        if cpt <= 20:
            break
    return m


# test validity of e
def check(phi, e):
    if e % 2 == 0:
        return False
        # test 2: primalite avec phi
    i = 3
    while i <= e:
        if e % i == 0 and phi % i == 0:
            return False
        i += 2
    return True

def encrypte(M, e, n,):
    C = 1
    #i = 0
    for i in range(e):
    #while i < e:
        C = C * M % n
    #    i += 1
    C = C % n

    # Make M printable.
    if M < 32:
        M = 32
    print("\tCharcter %c  : %d" % (chr(M), C))
    return C

def decrypte(C, d_lg, n, clef):
    s = []
    R = []
    data_list = []
    s.append(1)
    for i in range(d_lg):
        start = time.perf_counter()
        repeat_count = 1000
        alea = rand()
        for j in range(repeat_count):
            if clef[d_lg-1-i] == 1:
                if alea < 2147483647/2:
                    Ri = s[i]
                else:
                    for k in range(11):
                        pass
                Ri = s[i] * C % n
            else:
                if alea < 2147483647/2:
                    Ri = s[i] * C % n
                else:
                    for k in range(11):
                        pass
                Ri = s[i]
        end = time.perf_counter()
        R.append(Ri)
        tm = (end - start) * 1000000000 // repeat_count  # nanoseconds
        print("iteration time %d: %d nsec" % (i, tm))

        s.append((Ri * Ri) % n)
        data_list.append( (tm, i) )

    data_list.sort(key = lambda x: x[0])

    ecart = 0
    ecart_bis = 0
    j = 0
    for d in data_list:
        if (j >= (d_lg/3)-1 and j <= d_lg-(d_lg/3) and
           j+1 < len(data_list) and (data_list[j+1][0] - d[0]) > ecart):
            ecart = data_list[j+1][0] - d[0]
            ind_ecart = j
        elif j+1 < len(data_list) and (data_list[j+1][0] - d[0]) > ecart:
            ecart_bis = data_list[j+1][0] - d[0]
            ind_ecart_bis = j
        j += 1
    if ecart == 0:
        ecart = ecart_bis
        ind_ecart = ind_ecart_bis
    clef_estimee = [0 for i in range(100)]
    for j in range(ind_ecart+1):
        d = data_list[j]
        clef_estimee[d[1]] = 0
        if d[1] == 0:
            clef_estimee[d[1]] = 1
            calcul[d[1]] += 1
    for i in range(ind_ecart+1, len(data_list)):
        d = data_list[i]
        clef_estimee[d[1]] = 1
        calcul[d[1]] += 1

    print("estimated key:\t ", end="")
    for j in range(1, d_lg):
        print(clef_estimee[j], end=" ")

    M = R[d_lg - 1]
   # print("\tDecrypted characters:% c" % M)

def convert(d):
    clef = []
    q = 1
    i = 0
    while q != 0:
        q = d // 2
        r = d % 2
        d = q
        clef.append(r)
        i += 1
        j = i
    print("\tkey in binary\t: ", end="")
    i = j-1
    while i >= 0:
        #printf("%d ", clef[i]);
        print(clef[i], end=" ")
        i -= 1
    print()
    return (j, clef)

def main():
    # Generation des nombres premiers pour la clef
    if DEBUG:
        p = 193
        q = 13
    else:
        p = premier(0)
        q = premier(p)
    print("\nPrime numbers:\np=%d\tq=%d" % (p, q))
    n = p*q
    phi = (p-1)*(q-1)
    print("Phi(n)= %d\n" % phi)
    while True:
        e = int(input("Enter e: "))
        if check(phi, e):
            break
    d = 1
    while ((d*e) % phi) != 1:
        d += 1
    print("\tPublic key\t: {%d,%d}" % (e, n))
    print("\tPrivate key\t: {%d,%d}" % (d, n))

    clef = []  #[100];

    # conversion de la clef en binaire
    d_lg, clef = convert(d)
    # recuperation du message a chiffrer
    user=input("\nchoose the user:")
    # message a crypter
    pt = array[user]  # input() strips a trailing newline.

    code = [ encrypte(ord(m), e, n) for m in pt ]

    print()

    for c in code:
        decrypte(c, d_lg, n, clef)

    # affichage de la clef estimee
    print("\tEstimated final key:\t", end="")
    for i in range(d_lg):
        if calcul[i] > (len(pt)/2):
            print("1", end="")
        else:
            print("0", end="")

    print()
    return 0


if __name__ == "__main__":
    main()
