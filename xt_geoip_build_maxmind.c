#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>
#include <maxminddb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

char *progname = NULL; 
char *filename = NULL; 
MMDB_s mmdb;
#define AZNUM 26
FILE *CFD4[AZNUM*AZNUM] = { 0, };
FILE *CFD6[AZNUM*AZNUM] = { 0, };
FILE *CSV_IPv4_fd = NULL;
FILE *CSV_IPv6_fd = NULL;
FILE *CSV_EN_fd = NULL;
int32_t  CCN4[AZNUM*AZNUM] = { 0, };
int32_t  CCN6[AZNUM*AZNUM] = { 0, };

int CSV_EN[300] = { 0, };
int CSV_EN_last = 0;

int opt_v = 0;
int opt_4 = 1;
int opt_6 = 1;
int opt_csv = 0;

int opt_asn = 0;
char *opt_asn_val = NULL;

int *asn_list = NULL;
int asn_list_last = 0;
int asn_list_max = 0;

int opt_xtgeo = 0;
char output_dir[256];
char *CSV_IP_hdr = "network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider\n";
char *CSV_EN_hdr = "geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union\n";

void parse_asn_list(const char *arg) {
    char *buf,*v,*n,*e;
    if(!strcmp(arg,"all")) {
        opt_asn = -1;
        return;
    }
    buf = strdup(arg);
    if(!buf) abort();
    v = buf;
    while((n = strtok(v,",")) != NULL) {
        v = NULL;
        int asn2,asn = strtol(n,&e,10);
        asn2 = asn;
        if(*e) {
            if(*e != '-') {
                printf("Invalid ASN number %s\n",n);
                exit(1);
            }
            asn2 = strtol(e+1,&e,10);
            if(*e) {
                printf("Invalid ASN number %s\n",n);
                exit(1);
            }
            if(asn2 < asn) {
                printf("Wrong ASN range %s\n",n);
                exit(1);
            }
        }
        if(asn < 0 || asn2 < 0) {
            printf("Invalid ASN number %s\n",n);
            exit(1);
        }
        if(asn_list_last >= asn_list_max) {
            asn_list_max += 256;
            asn_list = realloc(asn_list,sizeof(int)*asn_list_max);
            if(!asn_list) abort();
        }
        asn_list[asn_list_last++] = asn;
        asn_list[asn_list_last++] = asn2;
        opt_asn = asn_list_last == 1 ? asn:-2;
    }
    free(buf);
}

void parse_asn_val(const char *arg) {
    if(!strcmp(arg,"ASNUM")) 
        opt_asn_val = (char *)1;
      else
        opt_asn_val = strdup(arg);
}

int match_asn(int asn) {
    int i;
    if(opt_asn > 0) return asn == opt_asn;
    if(opt_asn == -1) return 1;
    for(i=0; i < asn_list_last; i+=2) if(asn >= asn_list[i] && asn <= asn_list[i+1]) return 1;
    return 0;
}

int country2idx(char *cn) {
    if(cn[0] >= 'A' && cn[0] <= 'Z' &&
       cn[1] >= 'A' && cn[1] <= 'Z' && cn[2] == '\0') {
        return (cn[0]-'A')*AZNUM + (cn[1]-'A');
    }
    if(opt_v) printf("Bad CN %s\n",cn);
    return -1;
}

static char _ccname[4];
char *idx2country(int fd) {
    _ccname[0] = (fd / AZNUM) + 'A';
    _ccname[1] = (fd % AZNUM) + 'A';
    _ccname[2] = 0;
    return &_ccname[0];
}
void mmdb_str_utf8(const MMDB_entry_data_s *d,char *buf,size_t buf_len) {
        if(!d->has_data) abort();
        if(d->type != MMDB_DATA_TYPE_UTF8_STRING) abort();
        if(d->data_size >= buf_len) abort();
        memcpy(buf,d->utf8_string,d->data_size);
        buf[d->data_size] = 0;
}

static int last_asn = -1;
static char last_isp_name[128];

void country_dump(MMDB_entry_s *e,int ipv6,
        const char *ip_buf, int masklen,
        char *cn_buf,size_t cn_buf_len) {
    int r,idx;
    int geoname_id,r_geoname_id,asn;

    MMDB_entry_data_s d;

    if(opt_asn) {
        char isp_name[128];
        r = MMDB_get_value(e,&d,"autonomous_system_number",NULL);
        if(r != MMDB_SUCCESS) {
            fprintf(stderr,"Missing autonomous_system_number\n");
            exit(1);
        }
        if(d.type != MMDB_DATA_TYPE_UINT32) abort();
        asn  = d.uint32;
        if(!match_asn(asn)) return;
        r = MMDB_get_value(e,&d,"autonomous_system_organization",NULL);
        if(r == MMDB_SUCCESS)
            mmdb_str_utf8(&d,isp_name,sizeof(isp_name));
          else
            strcpy(isp_name,"Unknown");

        if(last_asn == asn && !strcmp(isp_name,last_isp_name)) {
            if(opt_asn_val) {
                if(opt_asn_val == (char *)1)
                    fprintf(stdout,"%s/%d %6d;\n",ip_buf,masklen,asn);
                  else
                    fprintf(stdout,"%s/%d %s;\n",ip_buf,masklen,opt_asn_val);
            } else {
                fprintf(stdout,"%s/%d %6d \"%s\"\n",ip_buf,masklen,asn,isp_name);
            }
            return;
        }
        last_asn = asn;
        strncpy(last_isp_name,isp_name,sizeof(last_isp_name));
        if(opt_asn_val) {
            if(opt_asn_val == (char *)1)
                fprintf(stdout,"%s/%d %6d; # A%-6d \"%s\"\n",ip_buf,masklen,asn,asn,isp_name);
              else
                fprintf(stdout,"%s/%d %s; # A%-6d \"%s\"\n",ip_buf,masklen,opt_asn_val,asn,isp_name);
        } else {
            fprintf(stdout,"%s/%d %6d \"%s\"\n",ip_buf,masklen,asn,isp_name);
        }
        return;
    }

    do {
        r = MMDB_get_value(e,&d,"country","iso_code",NULL);
        if(r == MMDB_SUCCESS) {
            mmdb_str_utf8(&d,cn_buf,cn_buf_len);
            break;
        }
        r = MMDB_get_value(e,&d,"registered_country","iso_code",NULL);
        if(r == MMDB_SUCCESS) {
            mmdb_str_utf8(&d,cn_buf,cn_buf_len);
            break;
        }
        r = MMDB_get_value(e,&d,"continent","code",NULL);
        if(r == MMDB_SUCCESS) {
            mmdb_str_utf8(&d,cn_buf,cn_buf_len);
            break;
        }
        strcpy(cn_buf,"??");
        return;
    } while(0);
    idx = country2idx(cn_buf);
    if(idx < 0) return;
// csv_ip
    r = MMDB_get_value(e,&d,"country","geoname_id",NULL);
    if(r != MMDB_SUCCESS) return;
    if(d.type != MMDB_DATA_TYPE_UINT32) abort();
    geoname_id  = d.uint32;
    if(CSV_IPv4_fd ||  CSV_IPv6_fd) {
        r = MMDB_get_value(e,&d,"registered_country","geoname_id",NULL);
        if(r != MMDB_SUCCESS) return;
        if(d.type != MMDB_DATA_TYPE_UINT32) abort();
        r_geoname_id  = d.uint32;
        if(!ipv6 && CSV_IPv4_fd)
            fprintf(CSV_IPv4_fd,"%s/%d,%d,%d,,0,0\n",ip_buf,masklen,geoname_id,r_geoname_id);
        if(ipv6 && CSV_IPv6_fd)
            fprintf(CSV_IPv6_fd,"%s/%d,%d,%d,,0,0\n",ip_buf,masklen,geoname_id,r_geoname_id);
    }

// csv_en
    if(!CSV_EN_fd) return;

    for(int i = 0; i < CSV_EN_last; i++) {
        if(CSV_EN[i] == geoname_id) return;
    }
    if(CSV_EN_last >= sizeof(CSV_EN)/sizeof(CSV_EN[0])) abort();

    CSV_EN[CSV_EN_last++] = geoname_id;

    char *locale_code = "en";
    char continent_code[8];
    char continent_name[32];
    char country_iso_code[8];
    char country_name[128];
    int is_in_european_union = 0;

    char *bug = "Unknown!";

    do {
        bug = "continent_code";
        r = MMDB_get_value(e,&d,"continent","code",NULL);
        if(r != MMDB_SUCCESS) break;
        mmdb_str_utf8(&d,continent_code,sizeof(continent_code));

        bug = "continent_name";
        r = MMDB_get_value(e,&d,"continent","names",locale_code,NULL);
        if(r != MMDB_SUCCESS) break;
        mmdb_str_utf8(&d,continent_name,sizeof(continent_name));

        bug = "country_iso_code";
        r = MMDB_get_value(e,&d,"country","iso_code",NULL);
        if(r != MMDB_SUCCESS) break;
        mmdb_str_utf8(&d,country_iso_code,sizeof(country_iso_code));

        bug = "country_name";
        r = MMDB_get_value(e,&d,"country","names",locale_code,NULL);
        if(r != MMDB_SUCCESS) break;
        mmdb_str_utf8(&d,country_name,sizeof(country_name));

        fprintf(CSV_EN_fd,"%d,%s,%s,%s,%s,\"%s\",%d\n",
                geoname_id,locale_code,continent_code,continent_name,
                country_iso_code,country_name,is_in_european_union);
        return;
    } while(0);
    fprintf(stderr,"BUG %s %s %s\n",ip_buf,cn_buf,bug);
}

void setnbin(uint8_t *path,int n,int v) {
    int nb = n >> 3;
    int b = n & 7;
    path[nb] &= (0xff00 >> b) & 0xff;
    if(v) path[nb] |= 0x80 >> b;
    while(++nb < 16) path[nb] = 0;
}
void sethostbit(uint8_t *path,int n) {
    int nb = n >> 3;
    int b = n & 7;

    path[nb++] |= 0xff >> b;
    while( nb < 16) {
            path[nb++] = 0xff;
    }
    fflush(stdout);
}

static char all_zero[16] = { 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };
static char ipv6_ipv4_1[16] = { 0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 0,0,0,0 };
static char ipv6_ipv4_2[16] = { 0x20,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0 };

void p_dump(int l, uint8_t *path, MMDB_entry_s *e) {
    char ip_buf1[64],ip_buf2[64],cfd_name[256+13],cn_buf[8];
    uint8_t path2[18];
    int start = l > 95 && (!memcmp(path,all_zero,12) || !memcmp(path,ipv6_ipv4_1,12)) ? 12:0;
    int ml = start ? 32-(128-(l+1)) : l+1;
    int cind = 0;
    FILE **CFD;

    if(start && !opt_4) return;
    if(!start && !opt_6) return;
    if(!start && !memcmp(path,ipv6_ipv4_2,2)) return;

    inet_ntop(start ? AF_INET:AF_INET6,&path[start],ip_buf1,sizeof(ip_buf1)-1);

    country_dump(e, start == 0, ip_buf1, ml, cn_buf, sizeof(cn_buf));
    if(opt_asn) 
        return;

    memcpy(path2,path,16);
    sethostbit(path2,l+1);
    inet_ntop(start ? AF_INET:AF_INET6,&path2[start],ip_buf2,sizeof(ip_buf2)-1);

    cind = country2idx(cn_buf);
    if(cind < 0) return;

    if(opt_v > 1) printf("%s/%d %s %s\n",ip_buf1,ml,ip_buf2,cn_buf);

    if( start ) CCN4[cind]++ ; else CCN6[cind]++;

    if(!opt_xtgeo) return;

    snprintf(cfd_name,sizeof(cfd_name)-1,"%s%s.iv%c",output_dir,cn_buf,start ? '4':'6');
    CFD = start ? &CFD4[0]:&CFD6[0];
    if(!CFD[cind]) CFD[cind] = fopen(cfd_name,"w");
    if(!CFD[cind]) { 
        fprintf(stderr,"create file %s:%s\n",cfd_name,strerror(errno));
        exit(1);
    }
    fwrite(&path[start],16-start,1,CFD[cind]);
    fwrite(&path2[start],16-start,1,CFD[cind]);
}
static int skip_n96 = 0;

void tree_walk(int rn,int l, uint8_t *path) {
    MMDB_search_node_s node;

    if(l > 128) return;
    if(l >= mmdb.depth) return;
    if(rn >= mmdb.metadata.node_count) return;
    if(rn == mmdb.ipv4_start_node.node_value) {
        if(skip_n96) return;
        skip_n96 = 1;
    }
    int result = MMDB_read_node(&mmdb, rn,&node);
    if(result != MMDB_SUCCESS) abort();

    setnbin(path,l,0);
    if(node.left_record_type == MMDB_RECORD_TYPE_SEARCH_NODE && node.left_record) {
        tree_walk(node.left_record,l+1,path);
    }
    if(node.left_record_type == MMDB_RECORD_TYPE_DATA) {
        p_dump(l,path,&node.left_record_entry);
    }
    setnbin(path,l,1);
    if(node.right_record_type == MMDB_RECORD_TYPE_SEARCH_NODE && node.right_record) {
        tree_walk(node.right_record,l+1,path);
    }
    if(node.right_record_type == MMDB_RECORD_TYPE_DATA) {
        p_dump(l,path,&node.right_record_entry);
    }
}

void usage(void) {
    printf("%s [-4] [-6] [-v] [-c] [-N ASNUM|string ][-A all|asnum[,asnum...]] [-o outputdir] file.mmdb\n",progname);
    printf("\t asnum: number | number-number\n");
    exit(1);
}

int main(int argc, char **argv)
{
    int fd,c,l,status;
    struct stat st;
    int c_ipv4 = 0,c_ipv6 = 0;
    uint8_t path[18];
    
    progname = strdup(argv[0]);

    while((c=getopt(argc,argv,"46cvo:A:N:")) != -1) {
      switch(c) {
        case 'c': opt_csv = 1; break;
        case '4': opt_6 = 0; break;
        case '6': opt_4 = 0; break;
        case 'v': opt_v++; break;
        case 'A': parse_asn_list(optarg); break;
        case 'N': parse_asn_val(optarg); break;
        case 'o': strncpy(output_dir,optarg,sizeof(output_dir)-2);
                  opt_xtgeo = 1;
                  break;
        default: usage();
      }
    }
    if(opt_6+opt_4  == 0) {
        fprintf(stderr,"%s: can't use -4 and -6\n",progname);
        exit(1);
    }
    if(optind < argc && !access(argv[optind],R_OK)) {
        filename = strdup(argv[optind]);
    } else usage();

    if(stat(filename,&st)) {
        perror("mmdb file:");
        exit(1);
    }
    if(!opt_xtgeo && !opt_csv && !opt_asn) {
        fprintf(stderr,"%s: -o or -c or -a is required!\n",progname);
        exit(1);
    }
    if(opt_asn && (opt_xtgeo  || opt_csv)) {
        fprintf(stderr,"%s: cant use -A with -o or -c\n",progname);
        exit(1);
    }
    if(opt_xtgeo) {
        l = strlen(output_dir)-1;

        while(l > 1 && output_dir[l] == '/') output_dir[l--] = '\0';

        if(stat(output_dir,&st)) {
            perror("output dir:");
            exit(1);
        }
        if((st.st_mode & S_IFMT) != S_IFDIR) {
            fprintf(stderr,"Output dir is not directory\n");
            exit(1);
        }
        output_dir[l+1] = '/';
        output_dir[l+2] = '\0';
    }

    status = MMDB_open(filename, MMDB_MODE_MMAP, &mmdb);

    if (MMDB_SUCCESS != status) {
        fprintf(stderr, "\n  Can't open %s - %s\n",
           filename, MMDB_strerror(status));

        if (MMDB_IO_ERROR == status) {
            fprintf(stderr, "    IO error: %s\n", strerror(errno));
        }
        exit(1);
    }
    if(opt_csv) {
        if(opt_4) {
            CSV_IPv4_fd = fopen("GeoLite2-Country-Blocks-IPv4.csv","w");
            if(CSV_IPv4_fd)
                fprintf(CSV_IPv4_fd,"%s",CSV_IP_hdr);
        }
        if(opt_6) {
            CSV_IPv6_fd = fopen("GeoLite2-Country-Blocks-IPv6.csv","w");
            if(CSV_IPv6_fd)
                fprintf(CSV_IPv6_fd,"%s",CSV_IP_hdr);
        }
        CSV_EN_fd = fopen("GeoLite2-Country-Locations-en.csv","w");
        if(CSV_EN_fd)
            fprintf(CSV_EN_fd,"%s",CSV_EN_hdr);
    }
    memset(path,0,sizeof(path));
    if(!opt_6) {
        tree_walk(mmdb.ipv4_start_node.node_value,mmdb.ipv4_start_node.netmask,path);
    } else
        tree_walk(0,0,path);
    MMDB_close(&mmdb);
    if(opt_asn) exit(0);
    for(fd = 0; fd < sizeof(CFD4)/sizeof(CFD4[0]); fd++) {
        if(opt_xtgeo) {
            if(CFD4[fd]) fclose(CFD4[fd]);
            if(CFD6[fd]) fclose(CFD6[fd]);
        }
        c_ipv4 += CCN4[fd];
        c_ipv6 += CCN6[fd];
        if(opt_v && ( CCN4[fd] || CCN6[fd])) {

            printf("%s",idx2country(fd));
            if(opt_4) printf(" IPv4:%d",CCN4[fd]);
            if(opt_6) printf(" IPv6:%d",CCN6[fd]);
            printf("\n");
        }
    }
    printf("Total ");
    if(opt_4) printf(" IPv4:%d",c_ipv4);
    if(opt_6) printf(" IPv6:%d",c_ipv6);
    printf("\n");
    if(CSV_IPv4_fd) fclose(CSV_IPv4_fd);
    if(CSV_IPv6_fd) fclose(CSV_IPv6_fd);
    if(CSV_EN_fd) fclose(CSV_EN_fd);

    exit(0);
}

/*
 * vim: set ts=4 sw=4 et :
 */
