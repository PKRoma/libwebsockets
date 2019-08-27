/*
 * Adapted from tadns 1.1, from http://adns.sourceforge.net/
 * Original license -->
 *
 * Copyright (c) 2004-2005 Sergey Lyubka <valenok@gmail.com>
 *
 * "THE BEER-WARE LICENSE" (Revision 42):
 * Sergey Lyubka wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.
 *
 * Integrated into lws, largely rewritten and relicensed (as allowed above)
 *
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010 - 2019 Andy Green <andy@warmcat.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "private-lib-core.h"

#define	DNS_MAX			128	/* Maximum host name		*/
#define	DNS_PACKET_LEN		1400	/* Buffer size for DNS packet	*/
#define	MAX_CACHE_ENTRIES	10	/* Dont cache more than that	*/
#define	DNS_QUERY_TIMEOUT	30	/* Query timeout, seconds	*/

typedef struct {
	uint8_t			addr[96];
	lws_sorted_usec_list_t	sul;
	lws_dll2_t		list;
	lws_dll2_owner_t	wsi_adns;
	struct lws_context	*context;
	size_t			addrlen;
	lws_async_dns_retcode_t	ret;
	uint16_t		tid;
	uint16_t		qtype;
	char			sent;

	/* name overallocated here */
} lws_adns_q_t;

struct header {
	uint16_t		tid;
	uint16_t		flags;
	uint16_t		nqueries;
	uint16_t		nanswers;
	uint16_t		nauth;
	uint16_t		nother;
	uint8_t			data[1];
};

static const struct sockaddr sa;

static struct canned_q {
	lws_adns_q_t		q;
	char			n[16];
} q_localhost = {
	{
		.addr		= { 127, 0, 0, 1 },
		.addrlen	= sizeof(sa.sa_data),
		.ret		= LADNS_RET_FOUND,
		.qtype		= LWS_ADNS_RECORD_A,
		.sent		= 1
	},
	.n			= "localhost"
};


static void
lws_adns_q_destroy(lws_adns_q_t *q)
{
	lws_dll2_remove(&q->sul.list);
	lws_dll2_remove(&q->list);
	lws_free(q);
}

static lws_adns_q_t *
lws_adns_get_query(lws_async_dns_t *dns, adns_query_type_t qtype,
		   lws_dll2_owner_t *owner, uint16_t tid, const char *name)
{
	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(owner)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		if (!name && tid == q->tid)
			return q;

		if (name && q->qtype == qtype &&
		    !strcasecmp(name, (const char *)&q[1])) {
			if (owner == &dns->cached) {
				/* Keep sorted by LRU: move to the head */
				lws_dll2_remove(&q->list);
				lws_dll2_add_head(&q->list, &dns->cached);
			}

			return q;
		}
	} lws_end_foreach_dll_safe(d, d1);

	return NULL;
}

static int
lws_async_dns_done(lws_adns_q_t *q, struct lws *wsi, lws_async_dns_retcode_t r)
{
	struct addrinfo ai, *rai = NULL;
	int n = -1;
	struct sockaddr_in sai;

	q->ret = r;

	if (r != LADNS_RET_FAILED && r != LADNS_RET_TIMEDOUT &&
	    r != LADNS_RET_NXDOMAIN) {

		rai = &ai;
		n = 0;

		memset(&sai, 0, sizeof sai);
		memset(&ai, 0, sizeof ai);

		ai.ai_flags = 0;
		ai.ai_family = AF_INET;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol = 0;
		ai.ai_addrlen = q->addrlen;
		ai.ai_addr = (struct sockaddr *)&sai;
		sai.sin_family = AF_INET;
		sai.sin_port = 0;
		memcpy(&sai.sin_addr, q->addr, sizeof(sai.sin_addr));
		ai.ai_canonname = (char *)&q[1];

		lwsl_notice("%s: result %d, %d.%d.%d.%d\n", __func__, r,
			      (uint8_t)sai.sin_addr.s_addr,
			      (uint8_t)(sai.sin_addr.s_addr >> 8),
			      (uint8_t)(sai.sin_addr.s_addr >> 16),
			      (uint8_t)(sai.sin_addr.s_addr >> 24));
	} else
		lwsl_info("%s: result %d\n", __func__, r);

	if (wsi)
		return !lws_client_connect_3(wsi, (const char*)&q[1], rai, n);

	/* inform all of the parent wsi that were interested in us */

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&q->wsi_adns)) {
		struct lws *w = lws_container_of(d, struct lws, adns);

		lws_dll2_remove(d);
		lws_client_connect_3(w, (const char*)&q[1], rai, n);
	} lws_end_foreach_dll_safe(d, d1);

	return 0;
}

static void
sul_cb_expire(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	lws_adns_q_destroy(q);
}

void
lws_async_dns_drop_server(struct lws_context *context)
{
	context->async_dns.dns_server_set = 0;
	lws_set_timeout(context->async_dns.wsi, 1, LWS_TO_KILL_ASYNC);
	context->async_dns.wsi = NULL;
}


static void
sul_cb_timeout(struct lws_sorted_usec_list *sul)
{
	lws_adns_q_t *q = lws_container_of(sul, lws_adns_q_t, sul);

	lws_async_dns_done(q, NULL, LADNS_RET_TIMEDOUT);
	lws_adns_q_destroy(q);

	/*
	 * our policy is to force reloading the dns server info if our
	 * connection ever timed out, in case it or the routing state changed
	 */

	lws_async_dns_drop_server(q->context);
}

static void
parse_udp(lws_async_dns_t *dns, const uint8_t *pkt, int len)
{
	int found, stop, dlen, nlen;
	lws_async_dns_retcode_t ret;
	struct header *header;
	const uint8_t *p, *e;
	lws_adns_q_t *q, *qc;
	char name[1025];
	struct lws *w;
	uint16_t type;
	uint32_t ttl;

	header = (struct header *) pkt;
	if (ntohs(header->nqueries) != 1)
		return;

	q = lws_adns_get_query(dns, 0, &dns->active, header->tid, NULL);
	if (!q) {
		lwsl_notice("%s: dropping unknown query\n", __func__);

		return;
	}

	qc = lws_adns_get_query(dns, q->qtype, &dns->cached, 0,
				(const char *)&q[1]);
	if (qc) {
		lwsl_notice("%s: finishing with already cached\n", __func__);
		lws_async_dns_done(q, NULL, qc->ret);
		lws_adns_q_destroy(q);
		return;
	}

	/* Received 0 answers */
	if (header->nanswers == 0) {
		q->addrlen = 0;

		lwsl_notice("%s: nxdomain\n", __func__);
		ret = LADNS_RET_NXDOMAIN;
		goto save_for_ttl;
	}


	for (e = pkt + len, nlen = 0, p = &header->data[0];
	    p < e && *p != '\0'; p++)
		nlen++;

	/* We sent query class 1, query type 1 */
	if (&p[5] > e || ((p[1] << 8) | p[2]) != q->qtype) {
		lwsl_notice("%s: wrong type\n", __func__);
		return;
	}

	/* Go to the first answer section */
	p += 5;

	/* Loop through the answers, we want A type answer */
	for (found = stop = 0; !stop && &p[12] < e; ) {

		/* Skip possible name in CNAME answer */
		if (*p != 0xc0) {
			while (*p && &p[12] < e)
				p++;
			p--;
		}

		type = htons(((uint16_t *)p)[1]);

		if (type == 5) {
			/* CNAME answer. shift to the next section */
			dlen = htons(((uint16_t *) p)[5]);
			p += 12 + dlen;
		} else if (type == q->qtype)
			found = stop = 1;
		else
			stop = 1;
	}

	if (!found || &p[12] >= e) {
		lwsl_notice("%s: not found\n", __func__);
		return;
	}

	dlen = htons(((uint16_t *) p)[5]);
	p += 12;

	if (p + dlen > e)
		return;

	/* Add to the cache */
	memcpy(&ttl, p - 6, sizeof(ttl));
	w = lws_container_of(lws_dll2_get_head(&q->wsi_adns), struct lws, adns);
	lws_sul_schedule(w->context, w->tsi, &q->sul, sul_cb_expire,
			lws_now_usecs() + (ntohl(ttl) * LWS_US_PER_SEC));

	if (q->qtype == LWS_ADNS_RECORD_MX) {
		const uint8_t	*e = pkt + len, *s = p + 2;
		int		j, i = 0, n = 0;

		while (*s != 0 && s < e) {
			if (n > 0)
				name[i++] = '.';

			if (i >= (int)sizeof(name) - 1)
				break;
			n = *s++;
			if (n == 0xc0) {
				s = ((uint8_t *)header) + *s;
				n = 0;
			} else
				for (j = 0; j < n &&
					    i < (int)sizeof(name) - 1; j++)
					name[i++] = *s++;
		}

		name[i] = '\0';
		p = (const uint8_t *)name;
		dlen = strlen(name);
	}
	q->addrlen = dlen;
	if (q->addrlen > sizeof(q->addr))
		q->addrlen = sizeof(q->addr);

	memcpy(&q->addr, p, q->addrlen);

	ret = LADNS_RET_FOUND;

save_for_ttl:
	lws_dll2_remove(&q->list);
	lws_dll2_add_head(&q->list, &dns->cached);

	lws_async_dns_done(q, NULL, ret);

	if (dns->cached.count >= MAX_CACHE_ENTRIES) {
		q = lws_container_of(lws_dll2_get_tail(&dns->cached),
					 lws_adns_q_t, list);
		lws_adns_q_destroy(q);
	}
}

static int
callback_async_dns(struct lws *wsi, enum lws_callback_reasons reason,
		   void *user, void *in, size_t len)
{
	struct lws_async_dns *dns = &(lws_get_context(wsi)->async_dns);
	uint8_t pkt[DNS_PACKET_LEN];
	struct header *header;
	int fd;

	switch (reason) {

	/* callbacks related to raw socket descriptor */

        case LWS_CALLBACK_RAW_ADOPT:
		// lwsl_user("LWS_CALLBACK_RAW_ADOPT\n");
                break;

	case LWS_CALLBACK_RAW_CLOSE:
		// lwsl_user("LWS_CALLBACK_RAW_CLOSE\n");
		break;

	case LWS_CALLBACK_RAW_RX:
		// lwsl_user("LWS_CALLBACK_RAW_RX (%d)\n", (int)len);
		//lwsl_hexdump_level(LLL_NOTICE, in, len);
		/* Check our socket for new stuff */
		if (len < (int) sizeof(struct header))
			return 0;

		parse_udp(dns, in, len);

		return 0;

	case LWS_CALLBACK_RAW_WRITEABLE:

		lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
					   lws_dll2_get_head(&dns->active)) {
			lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);
			int did = 0;

			if (!q->sent) {
				const char *s, *name = (const char *)&q[1];
				int i, n, name_len;
				uint8_t *p;

				if (did) {
					/* we used up our budget of one send */
					lws_callback_on_writable(wsi);

					return 0;
				}

				header = (struct header *)pkt;
				header->tid = q->tid;
				header->flags = htons(0x100);
				header->nqueries = htons(1);
				header->nanswers = 0;
				header->nauth = 0;
				header->nother = 0;

				name_len = strlen(name);
				p = (uint8_t *)&header->data;

				do {
					if ((s = strchr(name, '.')) == NULL)
						s = name + name_len;

					n = s - name;
					*p++ = n;
					for (i = 0; i < n; i++)
						*p++ = name[i];

					if (*s == '.')
						n++;

					name += n;
					name_len -= n;

				} while (*s);

				*p++ = 0;
				*p++ = 0;
				*p++ = (uint8_t)q->qtype;

				*p++ = 0;
				*p++ = 1;

				assert(p < pkt + sizeof(pkt));
				n = lws_ptr_diff(p, pkt);


				fd = lws_get_socket_fd(wsi);
				if (fd < 0)
					break;

				if (sendto(fd,
#if defined(WIN32)
						(const char *)
#endif
					   pkt, n, 0,
					   (struct sockaddr *)&dns->sa,
					   sizeof(dns->sa)) != n) {
					lws_async_dns_done(q, NULL,
							   LADNS_RET_FAILED);
					lws_adns_q_destroy(q);
				}
				q->sent = 1;
				did = 1;
			}
		} lws_end_foreach_dll_safe(d, d1);
		break;

	default:
		break;
	}

	return 0;
}

struct lws_protocols lws_async_dns_protocol = {
	"lws-async-dns", callback_async_dns, 0, 0
};

int
lws_async_dns_init(struct lws_context *context)
{
	int n = lws_plat_asyncdns_init(context, &context->async_dns.sa);

	if (n < 0) {
		lwsl_warn("%s: no valid dns server, retry\n", __func__);

		return 1;
	}

	context->async_dns.sa.sin_family = AF_INET;
	context->async_dns.sa.sin_port = htons(53);
	context->async_dns.wsi = lws_create_adopt_udp(context->vhost_list, 0, 0,
					   lws_async_dns_protocol.name, NULL);
	if (!context->async_dns.wsi) {
		lwsl_err("%s: foreign socket adoption failed\n", __func__);
		return 1;
	}

	context->async_dns.dns_server_set = 1;

	return 0;
}

static int
clean(struct lws_dll2 *d, void *user)
{
	lws_adns_q_destroy(lws_container_of(d, lws_adns_q_t, list));

	return 0;
}

void
lws_async_dns_deinit(lws_async_dns_t *dns)
{
	lws_dll2_foreach_safe(&dns->active, NULL, clean);
	lws_dll2_foreach_safe(&dns->cached, NULL, clean);
}

void
lws_async_dns_cancel(struct lws *wsi)
{
	lws_async_dns_t *dns = &wsi->context->async_dns;
	struct lws *w;

	lws_start_foreach_dll_safe(struct lws_dll2 *, d, d1,
				   lws_dll2_get_head(&dns->active)) {
		lws_adns_q_t *q = lws_container_of(d, lws_adns_q_t, list);

		lws_start_foreach_dll_safe(struct lws_dll2 *, d3, d4,
					   lws_dll2_get_head(&q->wsi_adns)) {
			w = lws_container_of(d3, struct lws, adns);

			if (wsi == w) {
				lws_dll2_remove(d3);
				if (!q->wsi_adns.count)
					lws_adns_q_destroy(q);
				return;
			}
		} lws_end_foreach_dll_safe(d3, d4);

	} lws_end_foreach_dll_safe(d, d1);
}

lws_async_dns_retcode_t
lws_async_dns_query(struct lws *wsi, const char *name, adns_query_type_t qtype)
{
	lws_async_dns_t *dns = &wsi->context->async_dns;
	size_t nlen = strlen(name);
	uint8_t ads[16];
	lws_adns_q_t *q;
	char *p;
	int m;

	/*
	 * It's a 1.2.3.4 type IP address already?  We don't need a dns
	 * server set up to be able to return that...
	 */

	m = lws_parse_numeric_address(name, ads, sizeof(ads));
	if (m == 4) {
		struct sockaddr_in sai;
		struct addrinfo ai;

		memset(&sai, 0, sizeof sai);
		memset(&ai, 0, sizeof ai);

		ai.ai_flags = 0;
		ai.ai_family = AF_INET;
		ai.ai_socktype = SOCK_STREAM;
		ai.ai_protocol = 0;
		ai.ai_addrlen = m;
		ai.ai_addr = (struct sockaddr *)&sai;
		sai.sin_family = AF_INET;
		sai.sin_port = 0;
		memcpy(&sai.sin_addr, ads, sizeof(sai.sin_addr));
		ai.ai_canonname = (char *)name;

		lws_client_connect_3(wsi, name, &ai, 0);

		return LADNS_RET_FOUND;
	}

	if (!strcmp(name, q_localhost.n)) {
		if (lws_async_dns_done(&q_localhost.q, wsi, LADNS_RET_FOUND))
			return LADNS_RET_FAILED_WSI_CLOSED;
		return LADNS_RET_FOUND;
	}

	if (!wsi->context->async_dns.dns_server_set &&
	    lws_async_dns_init(wsi->context))
		return LADNS_RET_FAILED;

	/* there's a done, cached query we can just reuse */

	q = lws_adns_get_query(dns, qtype, &dns->cached, 0, name);
	if (q) {
		lwsl_debug("%s: reusing cached result\n", __func__);
		if (lws_async_dns_done(q, wsi, q->ret))
			return LADNS_RET_FAILED_WSI_CLOSED;
		return LADNS_RET_FOUND;
	}

	/* there's an ongoing query we can share the result of */

	q = lws_adns_get_query(dns, qtype, &dns->active, 0, name);
	if (q) {
		lwsl_debug("%s: dns piggybacking: %d:%s\n", __func__,
				qtype, name);
		lws_dll2_add_head(&wsi->adns, &q->wsi_adns);

		return LADNS_RET_CONTINUING;
	}

	/* Allocate new query */

	q = (lws_adns_q_t *)lws_zalloc(sizeof(*q) + nlen + 1, __func__);
	if (!q) {
		lws_client_connect_3(wsi, NULL, NULL, LADNS_RET_FAILED);

		return LADNS_RET_FAILED;
	}

	lws_dll2_add_head(&wsi->adns, &q->wsi_adns);
	q->qtype = (uint16_t)qtype;
	q->tid = ++dns->tid;
	q->context = wsi->context;

	lws_sul_schedule(wsi->context, wsi->tsi, &q->sul, sul_cb_timeout,
			 lws_now_usecs() +
			 (DNS_QUERY_TIMEOUT * LWS_US_PER_SEC));

	p = (char *)&q[1];
	while (nlen--)
		*p++ = tolower(*name++);
	*p = '\0';

	lws_callback_on_writable(dns->wsi);

	lws_dll2_add_head(&q->list, &dns->active);

	lwsl_debug("%s: created new query\n", __func__);

	return LADNS_RET_CONTINUING;
}
