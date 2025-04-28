#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "traceroute.h"


struct icmp_ext_header {
#if __BYTE_ORDER == __BIG_ENDIAN
	unsigned int version:4;
	unsigned int reserved:4;
#else
	unsigned int reserved:4;
	unsigned int version:4;
#endif
	uint8_t reserved1;
	uint16_t checksum;
} __attribute__ ((packed));


struct icmp_ext_object {
	uint16_t length;
	uint8_t class;
	uint8_t c_type;
	uint8_t data[0];
};

#define MPLS_CLASS	1
#define MPLS_C_TYPE	1

#define IFACE_INFO_CLASS	2
#define IFACE_INFO_NAME_LEN	64


#define do_snprintf(CURR, END, FMT, ARGS...)	\
	do {					\
	    CURR += snprintf (CURR, END - CURR, (FMT), ## ARGS);\
	    if (CURR > END)  CURR = END;			\
	} while (0)


/*	rfc 5837 stuff    */

static int print_iface_info (struct icmp_ext_object *obj, char *buf, size_t length) {
	uint32_t *ui;
	char tmp[128];	/*  enough: 4 + (4 + 16) + 64 + 4 = 92   */
	size_t data_len;
	char *curr = buf, *end = buf + length;
	char *start;
	const char *roles[] = { "INC", "SUB", "OUT", "NXT" };


	/*  Copy data into temporary array of enough length
	   to avoid boundary checks on each step.
	*/
	data_len = ntohs (obj->length) - sizeof (*obj);
	if (data_len > sizeof (tmp))  return 0;

	memset (tmp, 0, sizeof (tmp));
	memcpy (tmp, obj->data, data_len);

	ui = (uint32_t *) tmp;


	do_snprintf (curr, end, "%s:", roles[(obj->c_type >> 6) & 0x03]);
	start = curr;

	if (obj->c_type & 0x08)    /*  index   */
		do_snprintf (curr, end, "%u", ntohl (*ui++));

	if (obj->c_type & 0x04) {  /*  IP address   */
	    sockaddr_any addr;
	    void *ptr;
	    size_t len;
	    uint16_t afi = ntohl (*ui++) >> 16;

	    memset (&addr, 0, sizeof (addr));

	    if (afi == 1) {    /*  ipv4   */
		addr.sa.sa_family = AF_INET;
		ptr = &addr.sin.sin_addr;
		len = sizeof (addr.sin.sin_addr);
	    }
	    else if (afi == 2) {  /*  ipv6   */
		addr.sa.sa_family = AF_INET6;
		ptr = &addr.sin6.sin6_addr;
		len = sizeof (addr.sin6.sin6_addr);
	    } else
		return 0;

	    memcpy (ptr, ui, len);
	    ui += len / sizeof (*ui);

	    do_snprintf (curr, end, "%s%s", (curr > start) ? "," : "", addr2str (&addr));
	}

	if (obj->c_type & 0x02) {	/*  name   */
	    uint8_t *name = (uint8_t *) ui;
	    uint8_t len = *name;
	    char str[IFACE_INFO_NAME_LEN * 4];	    /*  enough...   */
	    char *p = str;
	    static char hex[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
	    int i;

	    if (!len || (len % sizeof (uint32_t)) || len > IFACE_INFO_NAME_LEN)
		    return 0;

	    for (i = 1; i < len; i++) {	    /*  name[0] is length   */
		int ch = name[i];

		if (!ch)  break;
		else if (!isascii (ch) || !isgraph (ch) || ch == '%' || ch == '"') {
		    *p++ = '%';
		    *p++ = hex[(ch >> 4) & 0x0f];
		    *p++ = hex[ch & 0x0f];
		} else
		    *p++ = ch;
	    }
	    *p++ = '\0';

	    do_snprintf (curr, end, "%s\"%s\"", (curr > start) ? "," : "", str);

	    ui += len / sizeof (*ui);
	}

	if (obj->c_type & 0x01)    /*  mtu   */
		do_snprintf (curr, end, "%smtu=%u", (curr > start) ? "," : "", ntohl (*ui++));


	if (ui > (uint32_t *) (tmp + data_len))
		return 0;

	return  (curr - buf);
}


static int try_extension (probe *pb, char *buf, size_t len) {
	struct icmp_ext_header *iext = (struct icmp_ext_header *) buf;
	char str[1024];
	char *curr = str;
	char *end = str + sizeof (str) / sizeof (*str);
	

	/*  a check for len >= 8 already done for all cases   */

	if (iext->version != 2)  return -1;

	if (iext->checksum &&
	    in_csum (iext, len) != (uint16_t) ~0
	)  return -1;

	buf += sizeof (*iext);
	len -= sizeof (*iext);


	while (len >= sizeof (struct icmp_ext_object)) {
	    struct icmp_ext_object *obj = (struct icmp_ext_object *) buf;
	    size_t objlen = ntohs (obj->length);
	    size_t data_len;
	    uint32_t *ui = (uint32_t *) obj->data;
	    int i, n;

	    if (objlen < sizeof (*obj) ||
		objlen > len
	    )  return -1;

	    data_len = objlen - sizeof (*obj);
	    if (data_len % sizeof (uint32_t))
		    return -1;	/*  must be 32bit rounded...  */

	    n = data_len / sizeof (*ui);


	    if (curr > (char *) str && curr < end)
		    *curr++ = ';';	/*  a separator   */

	    if (obj->class == MPLS_CLASS &&
		obj->c_type == MPLS_C_TYPE &&
		n >= 1
	    ) {    /*  people prefer MPLS (rfc4950) to be parsed...  */

		do_snprintf (curr, end, "MPLS:");

		for (i = 0; i < n; i++, ui++) {
		    uint32_t mpls = ntohl (*ui);

		    do_snprintf (curr, end, "%sL=%u,E=%u,S=%u,T=%u",
					i ? "/" : "",
					mpls >> 12,
					(mpls >> 9) & 0x7,
					(mpls >> 8) & 0x1,
					mpls & 0xff);
		}

	    }
	    else if (obj->class == IFACE_INFO_CLASS &&
		     (i = print_iface_info (obj, curr, end - curr)) > 0
	    ) {
		curr += i;	/*  successfully parsed   */

	    }
	    else {	/*  common case...  */

		do_snprintf (curr, end, "%u/%u:", obj->class, obj->c_type);

		for (i = 0; i < n && curr < end; i++, ui++)
		    do_snprintf (curr, end, "%s%08x", i ? "," : "", ntohl(*ui));
	    }

	    buf += objlen;
	    len -= objlen;
	}

	if (len)  return -1;


	pb->ext = strdup (str);

	return 0;
}


void handle_extensions (probe *pb, char *buf, int len, int step) {

	if (!step)
	    try_extension (pb, buf, len);
	else {
	    for ( ; len >= 8; buf += step, len -= step)
		if (try_extension (pb, buf, len) == 0)
			break;
	}

	return;
}

