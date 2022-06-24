
DST=xt_geoip_build_maxmind
$(DST): $(DST).c
	gcc -g -O2 -Wall -o $@ $< -lmaxminddb
