\\ gp : MOV attack, mirrors the sage pipeline (see solve_movingon.sage)
p = 0x00e675aaef519c7bdfa7e9b6d5;
a = 0x00c5a83d2b9ce92d9c75a37a08;
b = 0x0020cd6dc3b4b34e4332463ccd;
E = ellinit([Mod(a,p), Mod(b,p)]);
grp = ellgroup(E, p, 1);
n   = grp[1];
G   = grp[3][1];
Q1 = [25868279382606376233089622039, 35226758373642087968613953852];
Q2 = [31211278741961598848732755066, 68653856268530027481128223450];
Qs = [Q1, Q2];
q = 24171428442137419;
cofactor = n \ q;
u = ffgen(p^2, 'u);
E2 = ellinit([u^0*a, u^0*b]);
G2 = [u^0 * lift(G[1]), u^0 * lift(G[2])];
P = ellmul(E2, G2, cofactor);
R = [0];
w = 1;
for (i = 1, 1000000, x = random(p) + u*random(p); ys = ellordinate(E2, x); if (#ys == 0, next); Rtmp = ellmul(E2, [x, ys[1]], cofactor); if (Rtmp == [0], next); wtry = ellweilpairing(E2, P, Rtmp, q); if (wtry != 1, R = Rtmp; w = wtry; break));
if (w == 1, error("failed to find good R"));
print("MOV_READY");
secrets = vector(0);
for (i = 1, 2, Q2i = [u^0 * Qs[i][1], u^0 * Qs[i][2]]; Qq = ellmul(E2, Q2i, cofactor); target = ellweilpairing(E2, Qq, R, q); s = fflog(target, w, q); s = lift(s) % q; small_mods = [2, 5, 757, 1627, 239579]; residues = vector(5); for (j = 1, 5, m = small_mods[j]; Gm = ellmul(E, G, n \ m); Qm = ellmul(E, Qs[i], n \ m); r = elllog(E, Qm, Gm, m); residues[j] = r); sfull = Mod(s, q); for (j = 1, 5, sfull = chinese(sfull, Mod(residues[j], small_mods[j]))); print("SECRET_", i, " = ", lift(sfull)));
\q
