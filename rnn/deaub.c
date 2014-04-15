#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#define CTX_MAX_LEVELS (3)

struct context {
	const uint32_t *dwords;
	size_t size;
	struct rnndb *db;
	struct rnndeccontext *dec;
	int gen;

	int err;
	int level;
	size_t cur, end[CTX_MAX_LEVELS];
};

static void ctx_err(struct context *ctx)
{
	ctx->err = 1;
}

static size_t ctx_len(struct context *ctx)
{
	return ctx->end[ctx->level] - ctx->cur;
}

static void ctx_nest(struct context *ctx, size_t len)
{
	size_t end = ctx->cur + len;

	assert(ctx->level + 1 < CTX_MAX_LEVELS);

	if (end > ctx->end[ctx->level])
		end = ctx->end[ctx->level];

	ctx->level++;
	ctx->end[ctx->level] = end;
}

static void ctx_unnest(struct context *ctx)
{
	assert(ctx->level);
	ctx->level--;
}

static void out(struct context *ctx, int idx, const char *format, ...)
{
	FILE *fp = stdout;
	int indent = ctx->level + ((idx) ? 1 : 0);

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

static void decode_auto(struct context *ctx, const char *dom_name, int len)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	struct rnndomain *dom;
	int i;

	assert(len <= ctx_len(ctx));

	dom = rnn_finddomain(ctx->db, dom_name);
	for (i = 0; i < len; i++) {
		struct rnndecaddrinfo *res =
			rnndec_decodeaddr(ctx->dec, dom, i, 0);
		char *desc = rnndec_decodeval(ctx->dec,
				res->typeinfo, dw[i], 32);

		out(ctx, i, "%s %s", res->name, desc);

		free(desc);
		free(res);
	}

	ctx->cur += len;
}

static void decode_mi(struct context *ctx)
{
	static const struct {
		int opcode;
		int min_len, max_len;
		const char *dom_name;
	} mi_map[] = {
#define GEN6_ENTRY(op, min_len) { GEN6_MI_OPCODE_ ## op, min_len, GEN6_ ## op ## __SIZE, #op }
		GEN6_ENTRY(MI_NOOP, 1),
		GEN6_ENTRY(MI_BATCH_BUFFER_END, 1),
		GEN6_ENTRY(MI_BATCH_BUFFER_START, 2),
#undef GEN6_ENTRY
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len;

	for (cmd = 0; cmd < ARRAY_SIZE(mi_map); cmd++) {
		if ((dw[0] & GEN6_MI_OPCODE__MASK) == mi_map[cmd].opcode)
			break;
	}
	if (cmd >= ARRAY_SIZE(mi_map)) {
		out(ctx, 0, "MI_ERR_UNKNOWN_COMMAND");
		ctx_err(ctx);
		return;
	}
	if (ctx_len(ctx) < mi_map[cmd].min_len) {
		out(ctx, 0, "%s end prematurely", mi_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	switch ((ctx->dwords[ctx->cur] & GEN6_MI_OPCODE__MASK)) {
	case GEN6_MI_OPCODE_MI_NOOP:
	case GEN6_MI_OPCODE_MI_BATCH_BUFFER_END:
		len = 1;
		break;
	default:
		len = (dw[0] & GEN6_MI_LENGTH__MASK) + 2;
		break;
	}

	if (len < mi_map[cmd].min_len || len > mi_map[cmd].max_len) {
		out(ctx, 0, "%s wrong size", mi_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	decode_auto(ctx, mi_map[cmd].dom_name, len);
}

static void decode_blitter(struct context *ctx)
{
	static const struct {
		int opcode;
		int min_len, max_len;
		const char *dom_name;
	} blitter_map[] = {
#define GEN6_ENTRY(op, min_len) { GEN6_BLITTER_OPCODE_ ## op, min_len, GEN6_ ## op ## __SIZE, #op }
		GEN6_ENTRY(COLOR_BLT, 5),
		GEN6_ENTRY(SRC_COPY_BLT, 6),
		GEN6_ENTRY(XY_COLOR_BLT, 6),
		GEN6_ENTRY(XY_SRC_COPY_BLT, 8),
#undef GEN6_ENTRY
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len;

	for (cmd = 0; cmd < ARRAY_SIZE(blitter_map); cmd++) {
		if ((dw[0] & GEN6_BLITTER_OPCODE__MASK) == blitter_map[cmd].opcode)
			break;
	}
	if (cmd >= ARRAY_SIZE(blitter_map)) {
		out(ctx, 0, "BLITTER_ERR_UNKNOWN_COMMAND");
		ctx_err(ctx);
		return;
	}
	if (ctx_len(ctx) < blitter_map[cmd].min_len) {
		out(ctx, 0, "%s end prematurely", blitter_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	len = (dw[0] & GEN6_BLITTER_LENGTH__MASK) + 2;
	if (len < blitter_map[cmd].min_len || len > blitter_map[cmd].max_len) {
		out(ctx, 0, "%s wrong size", blitter_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	decode_auto(ctx, blitter_map[cmd].dom_name, len);
}

static void decode_render_3d(struct context *ctx)
{
	static const struct {
		int subtype;
		int opcode;
		int min_len, max_len;
		const char *dom_name;
	} render_3d_map[] = {
#define GEN6_ENTRY(subtype, op, min_len) { GEN6_RENDER_SUBTYPE_ ## subtype, GEN6_RENDER_OPCODE_ ## op, min_len, GEN6_ ## op ## __SIZE, #op }
		GEN6_ENTRY(COMMON, STATE_BASE_ADDRESS, 10),
		GEN6_ENTRY(COMMON, STATE_SIP, 2),
		GEN6_ENTRY(SINGLE_DW, 3DSTATE_VF_STATISTICS, 1),
		GEN6_ENTRY(SINGLE_DW, PIPELINE_SELECT, 1),
		GEN6_ENTRY(3D, 3DSTATE_MULTISAMPLE, 3),
		GEN6_ENTRY(3D, 3DSTATE_SAMPLE_MASK, 2),
		GEN6_ENTRY(3D, PIPE_CONTROL, 4),
		GEN6_ENTRY(3D, 3DSTATE_VERTEX_BUFFERS, 5),
		GEN6_ENTRY(3D, 3DSTATE_VERTEX_ELEMENTS, 3),
		GEN6_ENTRY(3D, 3DSTATE_URB, 3),
		GEN6_ENTRY(3D, 3DSTATE_CC_STATE_POINTERS, 4),
		{ GEN6_RENDER_SUBTYPE_3D, GEN6_RENDER_OPCODE_3DSTATE_CONSTANT_VS, 5, GEN6_3DSTATE_CONSTANT_ANY__SIZE, "3DSTATE_CONSTANT_ANY" },
		GEN6_ENTRY(3D, 3DSTATE_VS, 6),
#undef GEN6_ENTRY
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len;

	for (cmd = 0; cmd < ARRAY_SIZE(render_3d_map); cmd++) {
		if ((dw[0] & GEN6_RENDER_SUBTYPE__MASK) == render_3d_map[cmd].subtype &&
		    (dw[0] & GEN6_RENDER_OPCODE__MASK) == render_3d_map[cmd].opcode)
			break;
	}
	if (cmd >= ARRAY_SIZE(render_3d_map)) {
		out(ctx, 0, "RENDER_ERR_UNKNOWN_COMMAND");
		ctx_err(ctx);
		return;
	}
	if (ctx_len(ctx) < render_3d_map[cmd].min_len) {
		out(ctx, 0, "%s end prematurely", render_3d_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	len = (render_3d_map[cmd].subtype == GEN6_RENDER_SUBTYPE_SINGLE_DW) ? 1 :
		(dw[0] & GEN6_RENDER_LENGTH__MASK) + 2;

	if (len < render_3d_map[cmd].min_len || len > render_3d_map[cmd].max_len) {
		out(ctx, 0, "%s wrong size", render_3d_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	decode_auto(ctx, render_3d_map[cmd].dom_name, len);
}

static void decode_render_state(struct context *ctx, int type, int subtype)
{
	static const struct {
		int type, subtype;
		int min_len, max_len;
		const char *dom_name;
	} render_state_map[] = {
#define GEN6_ENTRY(type, subtype, dom, min_len) { GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_ ## type, \
	GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_ ## subtype, min_len, GEN6_ ## dom ## __SIZE, #dom }
		GEN6_ENTRY(SURFACE, BINDING_TABLE, BINDING_TABLE_STATE, 1),
		GEN6_ENTRY(SURFACE, SURFACE_STATE, SURFACE_STATE, 6),
		GEN6_ENTRY(GENERAL, CC_STATE, COLOR_CALC_STATE, 1),
		GEN6_ENTRY(GENERAL, CLIP_VP_STATE, CLIP_VIEWPORT, 1),
		GEN6_ENTRY(GENERAL, SF_VP_STATE, SF_VIEWPORT, 1),
		GEN6_ENTRY(GENERAL, CC_VP_STATE, CC_VIEWPORT, 1),
		GEN6_ENTRY(GENERAL, SAMPLER_STATE, SAMPLER_STATE, 1),
		GEN6_ENTRY(GENERAL, SAMPLER_DEFAULT_COLOR, SAMPLER_BORDER_COLOR, 1),
		GEN6_ENTRY(GENERAL, SCISSOR_STATE, SCISSOR_RECT, 1),
		GEN6_ENTRY(GENERAL, BLEND_STATE, BLEND_STATE, 1),
		GEN6_ENTRY(GENERAL, DEPTH_STENCIL_STATE, DEPTH_STENCIL_STATE, 1),
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_VS_CONSTANTS, 1, 512, NULL, },
		{ GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER, GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE_WM_CONSTANTS, 1, 512, NULL, },
#undef GEN6_ENTRY
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len;

	for (cmd = 0; cmd < ARRAY_SIZE(render_state_map); cmd++) {
		if (render_state_map[cmd].type == type &&
		    render_state_map[cmd].subtype == subtype)
			break;
	}
	if (cmd >= ARRAY_SIZE(render_state_map)) {
		out(ctx, 0, "RENDER_ERR_UNKNOWN_STATE");
		ctx_err(ctx);
		return;
	}
	if (ctx_len(ctx) < render_state_map[cmd].min_len) {
		out(ctx, 0, "%s end prematurely", render_state_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	len = ctx_len(ctx);
	if (len < render_state_map[cmd].min_len ||
	    len > render_state_map[cmd].max_len) {
		out(ctx, 0, "%s wrong size", render_state_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	if (render_state_map[cmd].dom_name) {
		decode_auto(ctx, render_state_map[cmd].dom_name, len);
	}
	else {
		int i;

		/* constants */
		for (i = 0; i < len; i++) {
			union { float f32; int32_t i32; uint32_t u32; } u;
			u.u32 = dw[i];
			out(ctx, i, "f32 %-15f, i32 %-15d, u32 %-15u",
					u.f32, u.i32, u.u32);
		}

		ctx->cur += len;
	}
}

static void decode_ring(struct context *ctx)
{
	while (ctx_len(ctx) && !ctx->err) {
		switch ((ctx->dwords[ctx->cur] & GEN6_MI_TYPE__MASK)) {
		case GEN6_MI_TYPE_MI:
			decode_mi(ctx);
			break;
		case GEN6_BLITTER_TYPE_BLITTER:
			decode_blitter(ctx);
			break;
		case GEN6_RENDER_TYPE_RENDER:
			decode_render_3d(ctx);
			break;
		default:
			out(ctx, 0, "RING_ERR_UNKNOWN_COMMAND");
			ctx_err(ctx);
			break;
		}
	}
}

static void decode_aub_trace_header_block(struct context *ctx, int len)
{
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int op, type, subtype, size;

	op = dw[1] & GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP__MASK;
	type = dw[1] & GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE__MASK;
	subtype = dw[2] & GEN6_AUB_TRACE_HEADER_BLOCK_DW2_SUBTYPE__MASK;
	size = dw[4] / 4;

	decode_auto(ctx, "AUB_TRACE_HEADER_BLOCK", len);

	/* ready to decode data */
	ctx_nest(ctx, size);

	switch (op) {
	case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP_COMMAND_WRITE:
		decode_ring(ctx);
		break;
	case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_OP_DATA_WRITE:
		switch (type) {
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_BATCH:
			decode_ring(ctx);
			break;
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_GENERAL:
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_SURFACE:
		case GEN6_AUB_TRACE_HEADER_BLOCK_DW1_TYPE_CONSTANT_BUFFER:
			decode_render_state(ctx, type, subtype);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	/* it is fine because we can simply skip the data */
	if (ctx->err)
		ctx->err = 0;

	if (ctx_len(ctx)) {
		out(ctx, 0, "SKIPPED DATA (%d bytes)", ctx_len(ctx) * 4);
		ctx->cur += ctx_len(ctx);
	}

	ctx_unnest(ctx);
}

static void decode_aub(struct context *ctx)
{
	static const struct {
		int opcode;
		int min_len, max_len;
		const char *dom_name;
	} aub_map[] = {
#define GEN6_ENTRY(op, min_len) { GEN6_AUB_OPCODE_ ## op, min_len, GEN6_ ## op ## __SIZE, #op }
		GEN6_ENTRY(AUB_HEADER, 13),
		GEN6_ENTRY(AUB_TRACE_HEADER_BLOCK, 5),
		GEN6_ENTRY(AUB_DUMP_BMP, 6),
#undef GEN6_ENTRY
	};
	const uint32_t *dw = &ctx->dwords[ctx->cur];
	int cmd, len;

	for (cmd = 0; cmd < ARRAY_SIZE(aub_map); cmd++) {
		if ((dw[0] & GEN6_AUB_OPCODE__MASK) == aub_map[cmd].opcode)
			break;
	}
	if (cmd >= ARRAY_SIZE(aub_map)) {
		out(ctx, 0, "AUB_ERR_UNKNOWN_COMMAND");
		ctx_err(ctx);
		return;
	}
	if (ctx_len(ctx) < aub_map[cmd].min_len) {
		out(ctx, 0, "%s end prematurely", aub_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	len = (dw[0] & GEN6_AUB_LENGTH__MASK) + 2;
	if (len < aub_map[cmd].min_len || len > aub_map[cmd].max_len) {
		out(ctx, 0, "%s wrong size", aub_map[cmd].dom_name);
		ctx_err(ctx);
		return;
	}

	if (aub_map[cmd].opcode == GEN6_AUB_OPCODE_AUB_TRACE_HEADER_BLOCK) {
		decode_aub_trace_header_block(ctx, len);
		return;
	}

	decode_auto(ctx, aub_map[cmd].dom_name, len);
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

	memset(&ctx, 0, sizeof(ctx));
	ctx.dwords = ptr;
	ctx.size = st.st_size / 4;

	rnn_init();
	ctx.db = rnn_newdb();
	rnn_parsefile(ctx.db, "root.xml");
	rnn_prepdb(ctx.db);

	ctx.gen = GEN(6);
	ctx.dec = rnndec_newcontext(ctx.db);
	rnndec_varadd(ctx.dec, "gen", "GEN6");

	ctx.end[ctx.level] = ctx.size;

	while (ctx_len(&ctx) && !ctx.err)
		decode_aub(&ctx);

	munmap(ptr, st.st_size);
	close(fd);

	return 0;
}
