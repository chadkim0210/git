#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "gpg-interface.h"
#include "sigchain.h"
#include "tempfile.h"

static char *configured_signing_key;
static const char *default_signing_tool = "gpg";
static struct signing_tool *signing_tool_config;

static struct signing_tool *alloc_signing_tool(void)
{
	struct signing_tool *ret;
	ret = xcalloc(1, sizeof(*ret));
	ret->pemtype.strdup_strings = 1;
	return ret;
}

/*
 * Our default tool config is too complicated to specify as a constant
 * initializer, so we lazily create it as needed.
 */
static void init_signing_tool_defaults(void) {
	struct signing_tool *tool;

	if (signing_tool_config)
		return;

	tool = alloc_signing_tool();
	tool->name = xstrdup("gpg");
	tool->program = xstrdup("gpg");
	string_list_append(&tool->pemtype, "PGP SIGNATURE");
	string_list_append(&tool->pemtype, "PGP MESSAGE");

	tool->next = signing_tool_config;
	signing_tool_config = tool;
}

static struct signing_tool *get_signing_tool(const char *name) {
	struct signing_tool *tool;

	init_signing_tool_defaults();

	for (tool = signing_tool_config; tool; tool = tool->next) {
		if (!strcmp(name, tool->name))
			return tool;
	}
	return NULL;
}

static struct signing_tool *get_or_create_signing_tool(const char *name)
{
	struct signing_tool *tool = get_signing_tool(name);
	if (!tool) {
		tool = alloc_signing_tool();
		tool->name = xstrdup(name);
		tool->next = signing_tool_config;
		signing_tool_config = tool;
	}
	return tool;
}

void signature_check_clear(struct signature_check *sigc)
{
	FREE_AND_NULL(sigc->payload);
	FREE_AND_NULL(sigc->gpg_output);
	FREE_AND_NULL(sigc->gpg_status);
	FREE_AND_NULL(sigc->signer);
	FREE_AND_NULL(sigc->key);
}

static struct {
	char result;
	const char *check;
} sigcheck_gpg_status[] = {
	{ 'G', "\n[GNUPG:] GOODSIG " },
	{ 'B', "\n[GNUPG:] BADSIG " },
	{ 'U', "\n[GNUPG:] TRUST_NEVER" },
	{ 'U', "\n[GNUPG:] TRUST_UNDEFINED" },
	{ 'E', "\n[GNUPG:] ERRSIG "},
	{ 'X', "\n[GNUPG:] EXPSIG "},
	{ 'Y', "\n[GNUPG:] EXPKEYSIG "},
	{ 'R', "\n[GNUPG:] REVKEYSIG "},
};

void parse_gpg_output(struct signature_check *sigc)
{
	const char *buf = sigc->gpg_status;
	int i;

	/* Iterate over all search strings */
	for (i = 0; i < ARRAY_SIZE(sigcheck_gpg_status); i++) {
		const char *found, *next;

		if (!skip_prefix(buf, sigcheck_gpg_status[i].check + 1, &found)) {
			found = strstr(buf, sigcheck_gpg_status[i].check);
			if (!found)
				continue;
			found += strlen(sigcheck_gpg_status[i].check);
		}
		sigc->result = sigcheck_gpg_status[i].result;
		/* The trust messages are not followed by key/signer information */
		if (sigc->result != 'U') {
			sigc->key = xmemdupz(found, 16);
			/* The ERRSIG message is not followed by signer information */
			if (sigc-> result != 'E') {
				found += 17;
				next = strchrnul(found, '\n');
				sigc->signer = xmemdupz(found, next - found);
			}
		}
	}
}

int check_signature(const char *payload, size_t plen, const char *signature,
	size_t slen, struct signature_check *sigc)
{
	struct strbuf gpg_output = STRBUF_INIT;
	struct strbuf gpg_status = STRBUF_INIT;
	int status;

	sigc->result = 'N';

	status = verify_signed_buffer(payload, plen, signature, slen,
				      &gpg_output, &gpg_status, NULL);
	if (status && !gpg_output.len)
		goto out;
	sigc->payload = xmemdupz(payload, plen);
	sigc->gpg_output = strbuf_detach(&gpg_output, NULL);
	sigc->gpg_status = strbuf_detach(&gpg_status, NULL);
	parse_gpg_output(sigc);

 out:
	strbuf_release(&gpg_status);
	strbuf_release(&gpg_output);

	return sigc->result != 'G' && sigc->result != 'U';
}

void print_signature_buffer(const struct signature_check *sigc, unsigned flags)
{
	const char *output = flags & GPG_VERIFY_RAW ?
		sigc->gpg_status : sigc->gpg_output;

	if (flags & GPG_VERIFY_VERBOSE && sigc->payload)
		fputs(sigc->payload, stdout);

	if (output)
		fputs(output, stderr);
}

static int is_pem_start(const char *line, struct signing_tool **out_tool)
{
	struct signing_tool *tool;

	if (!skip_prefix(line, "-----BEGIN ", &line))
		return 0;

	init_signing_tool_defaults();

	for (tool = signing_tool_config; tool; tool = tool->next) {
		int i;
		for (i = 0; i < tool->pemtype.nr; i++) {
			const char *match = tool->pemtype.items[i].string;
			const char *end;
			if (skip_prefix(line, match, &end) &&
			    starts_with(end, "-----")) {
				*out_tool = tool;
				return 1;
			}
		}
	}
	return 0;
}

size_t parse_signature(const char *buf, size_t size,
		       const struct signing_tool **out_tool)
{
	size_t len = 0;
	size_t match = size;
	struct signing_tool *tool = NULL;

	while (len < size) {
		const char *eol;

		if (is_pem_start(buf + len, &tool))
			match = len;

		eol = memchr(buf + len, '\n', size - len);
		len += eol ? eol - (buf + len) + 1 : size - len;
	}

	if (out_tool)
		*out_tool = tool;
	return match;
}

void set_signing_key(const char *key)
{
	free(configured_signing_key);
	configured_signing_key = xstrdup(key);
}

int git_gpg_config(const char *var, const char *value, void *cb)
{
	const char *key, *name = NULL;
	int name_len;

	if (!strcmp(var, "user.signingkey")) {
		if (!value)
			return config_error_nonbool(var);
		set_signing_key(value);
		return 0;
	}

	if (!strcmp(var, "gpg.program")) {
		struct signing_tool *tool = get_or_create_signing_tool("gpg");

		if (!value)
			return config_error_nonbool(var);

		free(tool->program);
		tool->program = xstrdup(value);
		return 0;
	}

	if (!strcmp(var, "signingtool.default"))
		return git_config_string(&default_signing_tool, var, value);

	if (!parse_config_key(var, "signingtool", &name, &name_len, &key) && name) {
		char *tmpname = xmemdupz(name, name_len);
		struct signing_tool *tool = get_or_create_signing_tool(tmpname);

		free(tmpname);

		if (!strcmp(key, "program")) {
			if (!value)
				return config_error_nonbool(var);

			free(tool->program);
			tool->program = xstrdup(value);
			return 0;
		}

		if (!strcmp(key, "pemtype")) {
			if (!value)
				return config_error_nonbool(var);

			string_list_append(&tool->pemtype, value);
			return 0;
		}
	}

	return 0;
}

const char *get_signing_key(void)
{
	if (configured_signing_key)
		return configured_signing_key;
	return git_committer_info(IDENT_STRICT|IDENT_NO_DATE);
}

static int sign_buffer_with(struct strbuf *buffer, struct strbuf *signature,
			    const char *signing_key,
			    const struct signing_tool *tool)
{
	struct child_process gpg = CHILD_PROCESS_INIT;
	int ret;
	size_t i, j, bottom;
	struct strbuf gpg_status = STRBUF_INIT;

	argv_array_pushl(&gpg.args,
			 tool->program,
			 "--status-fd=2",
			 "-bsau", signing_key,
			 NULL);

	bottom = signature->len;

	/*
	 * When the username signingkey is bad, program could be terminated
	 * because gpg exits without reading and then write gets SIGPIPE.
	 */
	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpg, buffer->buf, buffer->len,
			   signature, 1024, &gpg_status, 0);
	sigchain_pop(SIGPIPE);

	ret |= !strstr(gpg_status.buf, "\n[GNUPG:] SIG_CREATED ");
	strbuf_release(&gpg_status);
	if (ret)
		return error(_("gpg failed to sign the data"));

	/* Strip CR from the line endings, in case we are on Windows. */
	for (i = j = bottom; i < signature->len; i++)
		if (signature->buf[i] != '\r') {
			if (i != j)
				signature->buf[j] = signature->buf[i];
			j++;
		}
	strbuf_setlen(signature, j);

	return 0;
}

int sign_buffer(struct strbuf *buffer, struct strbuf *signature, const char *signing_key)
{
	struct signing_tool *tool = get_signing_tool(default_signing_tool);
	if (!tool || !tool->program)
		return error(_("default signing tool '%s' has no program configured"),
			     default_signing_tool);
	return sign_buffer_with(buffer, signature, signing_key, tool);
}

int verify_signed_buffer(const char *payload, size_t payload_size,
			 const char *signature, size_t signature_size,
			 struct strbuf *gpg_output, struct strbuf *gpg_status,
			 const struct signing_tool *tool)
{
	struct child_process gpg = CHILD_PROCESS_INIT;
	struct tempfile *temp;
	int ret;
	struct strbuf buf = STRBUF_INIT;

	if (!tool) {
		parse_signature(signature, signature_size, &tool);
		if (!tool) {
			/*
			 * The caller didn't tell us which tool to use, and we
			 * didn't recognize the format. Historically we've fed
			 * these cases to blindly to gpg, so let's continue to
			 * do so.
			 */
			tool = get_signing_tool("gpg");
		}
	}

	if (!tool->program)
		return error(_("signing tool '%s' has no program configured"),
			     tool->name);

	temp = mks_tempfile_t(".git_vtag_tmpXXXXXX");
	if (!temp)
		return error_errno(_("could not create temporary file"));
	if (write_in_full(temp->fd, signature, signature_size) < 0 ||
	    close_tempfile_gently(temp) < 0) {
		error_errno(_("failed writing detached signature to '%s'"),
			    temp->filename.buf);
		delete_tempfile(&temp);
		return -1;
	}

	argv_array_pushl(&gpg.args,
			 tool->program,
			 "--status-fd=1",
			 "--keyid-format=long",
			 "--verify", temp->filename.buf, "-",
			 NULL);

	if (!gpg_status)
		gpg_status = &buf;

	sigchain_push(SIGPIPE, SIG_IGN);
	ret = pipe_command(&gpg, payload, payload_size,
			   gpg_status, 0, gpg_output, 0);
	sigchain_pop(SIGPIPE);

	delete_tempfile(&temp);

	ret |= !strstr(gpg_status->buf, "\n[GNUPG:] GOODSIG ");
	strbuf_release(&buf); /* no matter it was used or not */

	return ret;
}
