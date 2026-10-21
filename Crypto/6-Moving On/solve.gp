\\ GP solution  —  mirrors solve.sage exactly (Sage's E.gens()[0] = PARI ellgroup(flag=1) generator)
p = 0x00e675aaef519c7bdfa7e9b6d5;
a = 0x00c5a83d2b9ce92d9c75a37a08;
b = 0x0020cd6dc3b4b34e4332463ccd;
E = ellinit([Mod(a,p), Mod(b,p)]);

\\ [card, cyc, pts] = ellgroup(E, p, 1)  -> same as Sage: card, ords, pts = E.__pari__().ellgroup(flag=1)
group = ellgroup(E, p, 1);
card = group[1];
cyc  = group[2];
pts  = group[3];
G = pts[1];
n_G = cyc[1];

print("card(E) = ", card);
print("cyc     = ", cyc);
print("G       = ", G);
print("order(G)= ", n_G);
print("supersingular: #E = p+1 ?  ", card == p + 1);

Q1 = [25868279382606376233089622039, 35226758373642087968613953852];
Q2 = [31211278741961598848732755066, 68653856268530027481128223450];

print("Q1 on curve? ", ellisoncurve(E, Q1));
print("Q2 on curve? ", ellisoncurve(E, Q2));

\p 9
s1 = elllog(E, Q1, G, n_G);
print("s1 = ", s1);
s2 = elllog(E, Q2, G, n_G);
print("s2 = ", s2);

\\ verify
print("s1*G == Q1 ? ", ellmul(E, G, s1) == Q1);
print("s2*G == Q2 ? ", ellmul(E, G, s2) == Q2);
\q