/*
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

/** \defgroup smtp SMTP related functions
 * ##SMTP related functions
 * \ingroup lwsapi
 *
 * These apis let you communicate with a local SMTP server to send email from
 * lws.  It handles all the SMTP sequencing and protocol actions.
 *
 * Your system should have postfix, sendmail or another MTA listening on port
 * 25 and able to send email using the "mail" commandline app.  Usually distro
 * MTAs are configured for this by default.
 *
 * It runs via its own libuv events if initialized (which requires giving it
 * a libuv loop to attach to).
 *
 * It operates using three callbacks, on_next() queries if there is a new email
 * to send, on_get_body() asks for the body of the email, and on_sent() is
 * called after the email is successfully sent.
 *
 * To use it
 *
 *  - create an lws_email struct
 *
 *  - initialize data, loop, the email_* strings, max_content_size and
 *    the callbacks
 *
 *  - call lws_email_init()
 *
 *  When you have at least one email to send, call lws_email_check() to
 *  schedule starting to send it.
 */
//@{
#if defined(LWS_WITH_SMTP)

enum {
	LTMI_PSMTP_V_HELO = LTMI_PROTOCOL_BASE,		/* u.value */
	LTMI_PSMTP_LV_RETRY_INTERVAL,			/* u.lvalue */
	LTMI_PSMTP_LV_DELIVERY_TIMEOUT,			/* u.lvalue */
	LTMI_PSMTP_LV_EMAIL_QUEUE_MAX,			/* u.lvalue */
	LTMI_PSMTP_LV_MAX_CONTENT_SIZE,			/* u.lvalue */
};

typedef struct lws_smtp_client lws_smtp_client_t;
typedef struct lws_abs lws_abs_t;

typedef struct lws_smtp_email {
	struct lws_dll2 list;

	void *data;
	void *extra;

	time_t added;
	time_t last_try;

	const char *email_from;
	const char *email_to;
	const char *payload;

	int (*done)(struct lws_smtp_email *e, void *buf, size_t len);

	int tries;
} lws_smtp_email_t;


/**
 * lws_smtp_client_alloc_email_helper() - Allocates and inits an email object
 *
 * \param payload: the email payload string, with headers and terminating .
 * \param payload_len: size in bytes of the payload string
 * \param sender: the sender name and email
 * \param recipient: the recipient name and email
 *
 * Allocates an email object and copies the payload, sender and recipient into
 * it and initializes it.  Returns NULL if OOM, otherwise the allocated email
 * object.
 *
 * Because it copies the arguments into an allocated buffer, the original
 * arguments can be safely destroyed after calling this.
 *
 * The done() callback must free the email object.  It doesn't have to free any
 * individual members.
 */
LWS_VISIBLE LWS_EXTERN lws_smtp_email_t *
lws_smtp_client_alloc_email_helper(const char *payload, size_t payload_len,
				   const char *sender, const char *recipient,
				   const char *extra, size_t extra_len, void *data,
				   int (*done)(struct lws_smtp_email *e,
					       void *buf, size_t len));

/**
 * lws_smtp_client_add_email() - Add email to the list of ones being sent
 *
 * \param instance: smtp client + transport
 * \param e: email to queue for sending on \p c
 *
 * Adds an email to the linked-list of emails to send
 */
LWS_VISIBLE LWS_EXTERN int
lws_smtp_client_add_email(lws_abs_t *instance, lws_smtp_email_t *e);

/**
 * lws_smtp_client_kick() - Request check for new email
 *
 * \param instance: instance to kick
 *
 * Gives smtp client a chance to move things on
 */
LWS_VISIBLE LWS_EXTERN void
lws_smtp_client_kick(lws_abs_t *instance);

#endif
//@}
