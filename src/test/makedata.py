f = open("in.dat", "w")

for i in xrange(5001):
    print >>f, str(i) + ".",

f.close()