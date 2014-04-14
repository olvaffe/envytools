#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "rnn.h"
#include "rnndec.h"

#include "../gendb/gen_mi.xml.h"
#include "../gendb/gen_blitter.xml.h"
#include "../gendb/gen_render_surface.xml.h"
#include "../gendb/gen_render_dynamic.xml.h"
#include "../gendb/gen_render_3d.xml.h"
#include "../gendb/gen_aub.xml.h"

#define GEN(gen) ((int) ((gen) * 100))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

struct context {
	const uint32_t *dwords;
	size_t size;
	struct rnndb *db;
	struct rnndeccontext *dec;
	int gen;
	int indent;

	size_t cur;
	struct rnndomain *dom;
};

static void ctx_end(struct context *ctx)
{
	ctx->cur = ctx->size;
}

static size_t ctx_len(struct context *ctx)
{
	return ctx->size - ctx->cur;
}

static void out(struct context *ctx, int idx, const char *format, ...)
{
	FILE *fp = stdout;
	int indent = ctx->indent + ((idx) ? 1 : 0);

	fprintf(fp, "0x%08zd:  0x%08" PRIx32 ": ", (ctx->cur + idx) * 4, ctx->dwords[ctx->cur + idx]);
	while (indent--)
		fprintf(fp, "  ");

	if (format) {
		va_list ap;
		va_start(ap, format);
		vfprintf(fp, format, ap);
		va_end(ap);
	}

	fprintf(fp, "\n");
}

static void decode_mi(struct context *ctx)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	const char *op;
	int len, i;

	switch ((ctx->dwords[ctx->cur] & GEN6_MI_OPCODE__MASK)) {
	case GEN6_MI_OPCODE_MI_NOOP:
	case GEN6_MI_OPCODE_MI_BATCH_BUFFER_END:
		len = 1;
		break;
	default:
		len = (dw[0] & GEN6_RENDER_LENGTH__MASK) + 2;
		break;
	}

	switch ((ctx->dwords[ctx->cur] & GEN6_MI_OPCODE__MASK)) {
	case GEN6_MI_OPCODE_MI_NOOP:
		op = "MI_NOOP";
		break;
	case GEN6_MI_OPCODE_MI_BATCH_BUFFER_END:
		op = "MI_BATCH_BUFFER_END";
		break;
	case GEN6_MI_OPCODE_MI_BATCH_BUFFER_START:
		op = "MI_BATCH_BUFFER_START";
		break;
	default:
		op = NULL;
		break;
	}

	out(ctx, 0, op);
	for (i = 1; i < len; i++)
		out(ctx, i, NULL);

	ctx->cur += len;
}

static void decode_render(struct context *ctx)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	const char *op;
	int len, i;

	switch ((ctx->dwords[ctx->cur] & GEN6_RENDER_SUBTYPE__MASK)) {
	case GEN6_RENDER_SUBTYPE_SINGLE_DW:
		len = 1;
		break;
	default:
		len = (dw[0] & GEN6_RENDER_LENGTH__MASK) + 2;
		break;
	}

	switch ((ctx->dwords[ctx->cur] & GEN6_RENDER_OPCODE__MASK)) {
	case GEN6_RENDER_OPCODE_STATE_BASE_ADDRESS:
		op = "STATE_BASE_ADDRESS";
		break;
	case GEN6_RENDER_OPCODE_STATE_SIP:
		op = "STATE_SIP";
		break;
	case GEN6_RENDER_OPCODE_3DSTATE_VF_STATISTICS:
		op = "3DSTATE_VF_STATISTICS";
		break;
	case GEN6_RENDER_OPCODE_PIPELINE_SELECT:
		op = "PIPELINE_SELECT";
		break;
	case GEN6_RENDER_OPCODE_3DSTATE_MULTISAMPLE:
		op = "3DSTATE_MULTISAMPLE";
		break;
	case GEN6_RENDER_OPCODE_3DSTATE_SAMPLE_MASK:
		op = "3DSTATE_SAMPLE_MASK";
		break;
	case GEN6_RENDER_OPCODE_PIPE_CONTROL:
		op = "PIPE_CONTROL";
		break;
	default:
		op = NULL;
		break;
	}

	out(ctx, 0, op);
	for (i = 1; i < len; i++)
		out(ctx, i, NULL);

	ctx->cur += len;
}

static void decode_any_unknown(struct context *ctx)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	const int len = (dw[0] & 0x3f) + 2;
	int i;

	for (i = 0; i < len; i++)
		out(ctx, i, NULL);

	ctx->cur += len;
}

static void decode_state(struct context *ctx, int len, int type, int subtype)
{
	static const struct {
		int type, subtype;
		int min_len;
		const char *dom_name;
	} state_map[] = {
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_VS_CONSTANTS, 1, NULL, },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_WM_CONSTANTS, 1, NULL, },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_SURFACE, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_BINDING_TABLE, 1, "BINDING_TABLE_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_SURFACE, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_SURFACE_STATE, 6, "SURFACE_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_CC_STATE, 1, "CC_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_CLIP_VP_STATE, 1, "CLIP_VIEWPORT_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_SF_VP_STATE, 1, "SF_VIEWPORT_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_CC_VP_STATE, 1, "CC_VIEWPORT_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_SAMPLER_STATE, 1, "SAMPLER_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_SAMPLER_DEFAULT_COLOR, 1, "SAMPLER_BORDER_COLOR_STATEA", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_SCISSOR_STATE, 1, "SCISSOR_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_BLEND_STATE, 1, "BLEND_STATE", },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_DEPTH_STENCIL_STATE, 1, "DEPTH_STENCIL_STATE", },
	};
	int st, i;

	for (st = 0; st < ARRAY_SIZE(state_map); st++) {
		if (state_map[st].type == type &&
		    state_map[st].subtype == subtype)
			break;
	}
	if (st >= ARRAY_SIZE(state_map))
		return;

	if (len < state_map[st].min_len) {
		out(ctx, 0, "STATE_ERR_PREMATURE");
		ctx_end(ctx);
		return;
	}

	if (state_map[st].dom_name) {
		const uint32_t *dw = &ctx->dwords[ctx->cur];

		ctx->dom = rnn_finddomain(ctx->db, state_map[st].dom_name);
		for (i = 0; i < len; i++) {
			struct rnndecaddrinfo *res =
				rnndec_decodeaddr(ctx->dec, ctx->dom, i, 0);
			char *desc = rnndec_decodeval(ctx->dec,
					res->typeinfo, dw[i], 32);

			out(ctx, i, "%s %s", res->name, desc);

			free(desc);
			free(res);
		}
	}
	else {
		for (i = 0; i < len; i++)
			out(ctx, i, "DW%d", i);
	}

	ctx->cur += len;
}

static void decode_ring(struct context *ctx, int len)
{
	size_t end = ctx->cur + len;

	while (ctx->cur < end) {
		switch ((ctx->dwords[ctx->cur] & GEN6_MI_TYPE__MASK)) {
		case GEN6_MI_TYPE_MI:
			decode_mi(ctx);
			break;
		case GEN6_RENDER_TYPE_RENDER:
			decode_render(ctx);
			break;
		default:
			decode_any_unknown(ctx);
			break;
		}
	}
}

static void decode_aub_trace_header_block(struct context *ctx)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	const int len = (dw[0] & GEN6_AUB_LENGTH__MASK) + 2;
	int op, type, subtype, size;
	size_t end;
	int i;

	ctx->dom = rnn_finddomain(ctx->db, "AUB_TRACE_HEADER_BLOCK");
	for (i = 0; i < len; i++) {
		struct rnndecaddrinfo *res =
			rnndec_decodeaddr(ctx->dec, ctx->dom, i, 0);
		char *desc = rnndec_decodeval(ctx->dec,
				res->typeinfo, dw[i], 32);

		out(ctx, i, "%s %s", res->name, desc);

		free(desc);
		free(res);
	}

	op = dw[1] & GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP__MASK;
	type = dw[1] & GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE__MASK;
	subtype = dw[2] & GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE__MASK;
	size = dw[4] / 4;

	ctx->cur += len;

	end = ctx->cur + size;
	ctx->indent++;

	switch (op) {
	case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP_COMMAND_WRITE:
		decode_ring(ctx, size);
		break;
	case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP_DATA_WRITE:
		switch (type) {
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_BATCH:
			decode_ring(ctx, size);
			break;
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL:
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_SURFACE:
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER:
			decode_state(ctx, size, type, subtype);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (ctx->cur < end) {
		out(ctx, 0, "PAYLOAD (%d bytes)", (end - ctx->cur) * 4);
		ctx->cur = end;
	}

	ctx->indent--;
}

static void decode_aub(struct context *ctx)
{
	static const struct {
		int opcode;
		int min_len;
		const char *dom_name;
	} aub_map[] = {
		{ GEN6_AUB_OPCODE_AUB_HEADER, 13, "AUB_HEADER" },
		{ GEN6_AUB_OPCODE_AUB_TRACE_HEADER_BLOCK, 5, "AUB_TRACE_HEADER_BLOCK" },
		{ GEN6_AUB_OPCODE_AUB_DUMP_BMP, 6, "AUB_DUMP_BMP" },
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len, i;

	for (cmd = 0; cmd < ARRAY_SIZE(aub_map); cmd++) {
		if ((dw[0] & GEN6_AUB_OPCODE__MASK) == aub_map[cmd].opcode)
			break;
	}
	if (cmd >= ARRAY_SIZE(aub_map)) {
		out(ctx, 0, "AUB_ERR_UNKNOWN");
		ctx_end(ctx);
		return;
	}

	len = (dw[0] & GEN6_AUB_LENGTH__MASK) + 2;
	if (len < aub_map[cmd].min_len ||
	    ctx_len(ctx) < aub_map[cmd].min_len) {
		out(ctx, 0, "AUB_ERR_PREMATURE");
		ctx_end(ctx);
		return;
	}

	switch (aub_map[cmd].opcode) {
	case GEN6_AUB_OPCODE_AUB_TRACE_HEADER_BLOCK:
		decode_aub_trace_header_block(ctx);
		break;
	default:
		ctx->dom = rnn_finddomain(ctx->db, aub_map[cmd].dom_name);
		for (i = 0; i < len; i++) {
			struct rnndecaddrinfo *res =
				rnndec_decodeaddr(ctx->dec, ctx->dom, i, 0);
			char *desc = rnndec_decodeval(ctx->dec,
					res->typeinfo, dw[i], 32);

			out(ctx, i, "%s %s", res->name, desc);

			free(desc);
			free(res);
		}

		ctx->cur += len;
		break;
	}
}

static void err(const char *reason)
{
	fputs(reason, stderr);
	exit(1);
}

int main(int argc, char **argv)
{
	const char filename[] = "intel.aub";
	struct context ctx;
	struct stat st;
	int fd = -1;
	void *ptr = NULL;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		err("failed to open .aub file\n");

	if (fstat(fd, &st)) {
		close(fd);
		err("failed to stat()\n");
	}

	ptr = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		close(fd);
		err("failed to mmap()\n");
	}

	ctx.dwords = ptr;
	ctx.size = st.st_size / 4;

	rnn_init();
	ctx.db = rnn_newdb();
	rnn_parsefile(ctx.db, "root.xml");
	rnn_prepdb(ctx.db);
	ctx.dec = rnndec_newcontext(ctx.db);

	ctx.gen = GEN(6);
	ctx.indent = 0;
	ctx.cur = 0;

	while (ctx.cur < ctx.size)
		decode_aub(&ctx);

	munmap(ptr, st.st_size);
	close(fd);

	return 0;
}
