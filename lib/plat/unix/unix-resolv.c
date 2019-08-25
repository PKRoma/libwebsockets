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

lws_async_dns_server_check_t
lws_plat_asyncdns_init(struct lws_context *context, struct sockaddr_in *sa)
{
	int	a, b, c, d;
	char	line[96];
	FILE	*fp;

	fp = fopen("/etc/resolv.conf", "r");
	if (!fp)
		return 1;

	/* Try to figure out what DNS server to use */
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "nameserver %d.%d.%d.%d",
		   &a, &b, &c, &d) == 4) {
			sa->sin_addr.s_addr =
			    htonl(a << 24 | b << 16 | c << 8 | d);
			(void)fclose(fp);
			return 0;
		}
	}

	(void) fclose(fp);

	return 1;
}

