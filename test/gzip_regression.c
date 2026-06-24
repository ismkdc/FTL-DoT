#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// Include the implementation directly so the tests can exercise the same
// private constants as gzip.c.
#include "zip/gzip.c"

#undef calloc
#undef free
#undef fprintf
#undef fopen
#undef printf
#undef realloc
#undef snprintf
#undef strlen
#undef strcmp
#undef strstr
#undef vfprintf
#undef vsnprintf
#undef memcmp
#undef memcpy
#undef memmove
#undef memset

#define GZIP_FLG_FEXTRA 0x04u
#define GZIP_FLG_FNAME 0x08u
#define GZIP_FLG_FCOMMENT 0x10u

static char last_log[512];
static int failures = 0;

struct gzip_test {
	const char *name;
	void (*run)(void);
};

void _FTL_log(const int priority, const enum debug_flag flag, const char *format, ...)
{
	(void)priority;
	(void)flag;

	va_list args;
	va_start(args, format);
	vsnprintf(last_log, sizeof(last_log), format, args);
	va_end(args);

	fprintf(stderr, "%s\n", last_log);
}

void format_memory_size(char prefix[2], const off_t bytes, double * const formatted)
{
	prefix[0] = '\0';
	prefix[1] = '\0';
	*formatted = (double)bytes;
}

bool FTLfree(void *ptr, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	free(ptr);
	return true;
}

void *FTLcalloc(size_t n, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return calloc(n, size);
}

void *FTLrealloc(void *ptr, size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return realloc(ptr, size);
}

FILE *FTLfopen(const char *pathname, const char *mode, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return fopen(pathname, mode);
}

int FTLfprintf(FILE *stream, const char *file, const char *func, const int line, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;

	va_list args;
	va_start(args, format);
	const int ret = vfprintf(stream, format, args);
	va_end(args);
	return ret;
}

int FTLvfprintf(FILE *stream, const char *file, const char *func, const int line, const char *format, va_list args)
{
	(void)file;
	(void)func;
	(void)line;
	return vfprintf(stream, format, args);
}

int FTLsnprintf(const char *file, const char *func, const int line, char *buffer, const size_t maxlen, const char *format, ...)
{
	(void)file;
	(void)func;
	(void)line;

	va_list args;
	va_start(args, format);
	const int ret = vsnprintf(buffer, maxlen, format, args);
	va_end(args);
	return ret;
}

int FTLvsnprintf(const char *file, const char *func, const int line, char *buffer, const size_t maxlen, const char *format, va_list args)
{
	(void)file;
	(void)func;
	(void)line;
	return vsnprintf(buffer, maxlen, format, args);
}

void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memset(s, c, n);
}

void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcpy(dest, src, n);
}

void *FTLmemmove(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memmove(dest, src, n);
}

size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strlen(s);
}

int FTLmemcmp(const void *s1, const void *s2, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcmp(s1, s2, n);
}

struct gzip_blob {
	unsigned char *data;
	mz_ulong size;
};

static void reset_log(void)
{
	last_log[0] = '\0';
}

static void expect(const bool condition, const char *message)
{
	if(condition)
		return;

	fprintf(stderr, "FAIL: %s\n", message);
	failures++;
}

static bool failf(const char *format, ...)
{
	fprintf(stderr, "FAIL: ");
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
	fputc('\n', stderr);
	failures++;
	return false;
}

static void write_le32(unsigned char *dest, uint32_t value)
{
	for(unsigned int i = 0; i < 4; i++)
		dest[i] = (unsigned char)((value >> (i * 8)) & 0xffu);
}

static bool build_gzip(const unsigned char *payload, const mz_ulong payload_size,
                       const unsigned char flags,
                       const unsigned char *extra, const uint16_t extra_size,
                       const char *name, const char *comment,
                       struct gzip_blob *blob)
{
	blob->data = NULL;
	blob->size = 0;

	mz_ulong zlib_size = compressBound(payload_size);
	unsigned char *zlib_stream = malloc(zlib_size);
	if(zlib_stream == NULL)
		return failf("failed to allocate zlib stream");

	int ret = compress2(zlib_stream, &zlib_size, payload, payload_size, Z_BEST_COMPRESSION);
	if(ret != Z_OK)
	{
		free(zlib_stream);
		return failf("compress2 failed: %s", zError(ret));
	}
	if(zlib_size < 6)
	{
		free(zlib_stream);
		return failf("compressed stream is unexpectedly short");
	}

	size_t optional_size = 0;
	if(flags & GZIP_FLG_FEXTRA)
		optional_size += 2u + extra_size;
	if(flags & GZIP_FLG_FNAME)
		optional_size += strlen(name != NULL ? name : "") + 1u;
	if(flags & GZIP_FLG_FCOMMENT)
		optional_size += strlen(comment != NULL ? comment : "") + 1u;

	const mz_ulong raw_deflate_size = zlib_size - 6u;
	const size_t total_size = GZIP_HEADER_SIZE + optional_size + raw_deflate_size + GZIP_FOOTER_SIZE;
	unsigned char *gzip_stream = calloc(total_size, sizeof(*gzip_stream));
	if(gzip_stream == NULL)
	{
		free(zlib_stream);
		return failf("failed to allocate gzip stream");
	}

	unsigned char header[GZIP_HEADER_SIZE] = {
		0x1f, 0x8b, 0x08, flags, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03
	};
	memcpy(gzip_stream, header, sizeof(header));

	size_t offset = GZIP_HEADER_SIZE;
	if(flags & GZIP_FLG_FEXTRA)
	{
		gzip_stream[offset++] = (unsigned char)(extra_size & 0xffu);
		gzip_stream[offset++] = (unsigned char)(extra_size >> 8);
		if(extra_size > 0)
		{
			memcpy(gzip_stream + offset, extra, extra_size);
			offset += extra_size;
		}
	}
	if(flags & GZIP_FLG_FNAME)
	{
		const char *field = name != NULL ? name : "";
		const size_t field_size = strlen(field) + 1u;
		memcpy(gzip_stream + offset, field, field_size);
		offset += field_size;
	}
	if(flags & GZIP_FLG_FCOMMENT)
	{
		const char *field = comment != NULL ? comment : "";
		const size_t field_size = strlen(field) + 1u;
		memcpy(gzip_stream + offset, field, field_size);
		offset += field_size;
	}

	memcpy(gzip_stream + offset, zlib_stream + 2, raw_deflate_size);
	offset += raw_deflate_size;

	const uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, payload, payload_size);
	write_le32(gzip_stream + offset, crc);
	offset += sizeof(uint32_t);
	write_le32(gzip_stream + offset, (uint32_t)payload_size);
	offset += sizeof(uint32_t);

	free(zlib_stream);

	if(offset != total_size)
	{
		free(gzip_stream);
		return failf("internal gzip builder size mismatch");
	}

	blob->data = gzip_stream;
	blob->size = (mz_ulong)total_size;
	return true;
}

static void free_blob(struct gzip_blob *blob)
{
	free(blob->data);
	blob->data = NULL;
	blob->size = 0;
}

static bool inflate_copy(const unsigned char *data, const mz_ulong size,
                         unsigned char **output, mz_ulong *output_size)
{
	unsigned char *scratch = malloc(size);
	if(scratch == NULL)
		return failf("failed to allocate mutable gzip input");

	memcpy(scratch, data, size);
	*output = NULL;
	*output_size = 0;
	const bool success = inflate_buffer(scratch, size, output, output_size);
	free(scratch);
	return success;
}

static void expect_inflate_log_contains(const char *expected_log)
{
	if(strstr(last_log, expected_log) != NULL)
		return;

	fprintf(stderr, "FAIL: expected log containing \"%s\", got \"%s\"\n", expected_log, last_log);
	failures++;
}

static void expect_inflate_failure_with_log(const unsigned char *data, const mz_ulong size,
                                            const char *expected_log)
{
	unsigned char *output = NULL;
	mz_ulong output_size = 0;

	reset_log();
	const bool success = inflate_copy(data, size, &output, &output_size);
	free(output);

	expect(!success, "inflate_buffer rejects invalid input");
	if(!success)
		expect_inflate_log_contains(expected_log);
}

static void expect_inflate_success_payload(const struct gzip_blob *blob,
                                           const unsigned char *payload,
                                           const mz_ulong payload_size)
{
	unsigned char *output = NULL;
	mz_ulong output_size = 0;

	reset_log();
	const bool success = inflate_copy(blob->data, blob->size, &output, &output_size);
	if(!success)
	{
		free(output);
		failf("inflate_buffer rejected a valid gzip stream: %s", last_log);
		return;
	}
	if(output_size != payload_size)
	{
		free(output);
		failf("expected %lu output bytes, got %lu",
		      (unsigned long)payload_size, (unsigned long)output_size);
		return;
	}
	expect(memcmp(output, payload, payload_size) == 0, "inflated payload matches");

	free(output);
}

static void test_short_stream_is_rejected(void)
{
	unsigned char data[1] = { 0x1f };
	expect_inflate_failure_with_log(data, sizeof(data), "This is not a valid GZIP stream");
}

static void test_extra_field_overlapping_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FEXTRA
	};
	data[GZIP_HEADER_SIZE] = 1u;
	data[GZIP_HEADER_SIZE + 1u] = 0u;

	expect_inflate_failure_with_log(data, sizeof(data), "Invalid GZIP header");
}

static void test_name_field_starting_in_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FNAME
	};

	expect_inflate_failure_with_log(data, sizeof(data), "GZIP file name field overruns into the footer");
}

static void test_name_field_missing_nul_before_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + 2u + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FNAME
	};
	data[GZIP_HEADER_SIZE] = 'n';
	data[GZIP_HEADER_SIZE + 1u] = 'm';

	expect_inflate_failure_with_log(data, sizeof(data), "File name is missing or invalid in GZIP header");
}

static void test_name_field_terminator_in_footer_is_rejected(void)
{
	const size_t size = 40u;
	const size_t nul_at = 39u;
	unsigned char *gz = calloc(1, size);
	expect(gz != NULL, "crafted gzip allocation succeeds");
	if(gz == NULL)
		return;

	gz[0] = 0x1f;
	gz[1] = 0x8b;
	gz[2] = 0x08;
	gz[3] = GZIP_FLG_FNAME;
	gz[8] = 0x02;
	gz[9] = 0x03;

	memset(gz + GZIP_HEADER_SIZE, 'A', size - GZIP_HEADER_SIZE);
	gz[nul_at] = 0x00;

	const size_t new_size = size - (nul_at + 1u - GZIP_HEADER_SIZE);
	write_le32(gz + new_size - 4u, 1u);

	expect_inflate_failure_with_log(gz, size, "File name is missing or invalid in GZIP header");

	free(gz);
}

static void test_comment_field_starting_in_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FCOMMENT
	};

	expect_inflate_failure_with_log(data, sizeof(data), "GZIP file comment field overruns into the footer");
}

static void test_comment_field_missing_nul_before_footer_is_rejected(void)
{
	unsigned char data[GZIP_HEADER_SIZE + 2u + GZIP_FOOTER_SIZE] = {
		0x1f, 0x8b, 0x08, GZIP_FLG_FCOMMENT
	};
	data[GZIP_HEADER_SIZE] = 'c';
	data[GZIP_HEADER_SIZE + 1u] = 'm';

	expect_inflate_failure_with_log(data, sizeof(data), "File comment is missing or invalid in GZIP header");
}

static void test_crc32_high_bit_decompresses(void)
{
	static const unsigned char payload[] = "test";
	const uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, payload, sizeof(payload) - 1u);
	if((crc & 0x80000000u) == 0)
	{
		failf("test payload does not exercise the CRC32 high bit");
		return;
	}

	struct gzip_blob blob;
	if(!build_gzip(payload, sizeof(payload) - 1u, 0, NULL, 0, NULL, NULL, &blob))
		return;

	expect_inflate_success_payload(&blob, payload, sizeof(payload) - 1u);
	free_blob(&blob);
}

static void test_empty_optional_fields_decompress(void)
{
	static const unsigned char payload[] = "payload with optional fields";
	static const unsigned char extra[] = { 0x70, 0x69 };

	struct gzip_blob blob;
	if(!build_gzip(payload, sizeof(payload) - 1u,
	               GZIP_FLG_FEXTRA | GZIP_FLG_FNAME | GZIP_FLG_FCOMMENT,
	               extra, sizeof(extra), "", "", &blob))
		return;

	expect_inflate_success_payload(&blob, payload, sizeof(payload) - 1u);
	free_blob(&blob);
}

static const struct gzip_test tests[] = {
	{ "short_stream_is_rejected", test_short_stream_is_rejected },
	{ "extra_field_overlapping_footer_is_rejected", test_extra_field_overlapping_footer_is_rejected },
	{ "name_field_starting_in_footer_is_rejected", test_name_field_starting_in_footer_is_rejected },
	{ "name_field_missing_nul_before_footer_is_rejected", test_name_field_missing_nul_before_footer_is_rejected },
	{ "name_field_terminator_in_footer_is_rejected", test_name_field_terminator_in_footer_is_rejected },
	{ "comment_field_starting_in_footer_is_rejected", test_comment_field_starting_in_footer_is_rejected },
	{ "comment_field_missing_nul_before_footer_is_rejected", test_comment_field_missing_nul_before_footer_is_rejected },
	{ "crc32_high_bit_decompresses", test_crc32_high_bit_decompresses },
	{ "empty_optional_fields_decompress", test_empty_optional_fields_decompress },
};

static int run_test(const struct gzip_test *test)
{
	failures = 0;
	test->run();

	if (failures != 0) {
		fprintf(stderr, "FAIL %s: %d assertion(s) failed\n", test->name, failures);
		return 1;
	}

	printf("PASS %s\n", test->name);
	return 0;
}

static int run_named_test(const char *name)
{
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (strcmp(tests[i].name, name) == 0)
			return run_test(&tests[i]);

	fprintf(stderr, "unknown gzip regression test: %s\n", name);
	fprintf(stderr, "available tests:\n");
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		fprintf(stderr, "  %s\n", tests[i].name);

	return 2;
}

// Run a single test in a forked child so a sanitizer abort (or any crash)
// fails only that case instead of taking down the rest of the suite. Named
// cases stay in-process for straightforward debugging.
static int run_test_isolated(const struct gzip_test *test)
{
	fflush(NULL);

	pid_t pid = fork();
	if (pid < 0) {
		// fork() is unavailable - fall back to running in-process. A
		// sanitizer abort would still stop the suite here, but a clean
		// build runs every case.
		return run_test(test);
	}

	if (pid == 0) {
		int rc = run_test(test);
		// _exit() does not flush stdio, so drain the child's PASS/FAIL
		// output (fully buffered when stdout is not a terminal) first.
		fflush(NULL);
		_exit(rc);
	}

	int wstatus = 0;
	while (waitpid(pid, &wstatus, 0) < 0) {
		if (errno != EINTR) {
			fprintf(stderr, "FAIL %s: waitpid failed (%s)\n",
			        test->name, strerror(errno));
			return 1;
		}
	}

	if (WIFEXITED(wstatus))
		return WEXITSTATUS(wstatus) == 0 ? 0 : 1;

	if (WIFSIGNALED(wstatus))
		fprintf(stderr, "FAIL %s: terminated by signal %d\n",
		        test->name, WTERMSIG(wstatus));
	else
		fprintf(stderr, "FAIL %s: abnormal termination\n", test->name);

	return 1;
}

static void list_tests(void)
{
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		printf("%s\n", tests[i].name);
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--list") == 0) {
		list_tests();
		return 0;
	}

	if (argc > 1) {
		int status = 0;
		for (int i = 1; i < argc; i++)
			if (run_named_test(argv[i]) != 0)
				status = 1;
		return status;
	}

	int status = 0;
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (run_test_isolated(&tests[i]) != 0)
			status = 1;

	return status;
}
