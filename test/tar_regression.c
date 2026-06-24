#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

// Include the implementation directly so the tests can exercise the
// file-internal helpers (parse_tar_size(), tar_entry_span()) and reuse the
// TAR_* layout constants instead of duplicating them here. tar.c pulls in
// FTL.h, which redefines the libc string/memory calls to FTL* wrappers; the
// #undef block below restores the plain libc names for the test code itself,
// and the handful of FTL* wrappers tar.c needs are provided as thin stubs
// further down.
#include "zip/tar.c"

#undef calloc
#undef free
#undef fprintf
#undef printf
#undef snprintf
#undef strlen
#undef strnlen
#undef strcmp
#undef strncmp
#undef vfprintf
#undef memcpy
#undef memset

// Header-field offsets the parser never reads (so they are not defined in
// tar.c) but which the fixtures below need to assemble valid headers. The
// layout/size constants the parser does use - TAR_BLOCK_SIZE, TAR_NAME_SIZE,
// TAR_SIZE_SIZE, TAR_SIZE_OFFSET, TAR_MAGIC_OFFSET - come from tar.c.
#define TAR_CHECKSUM_OFFSET 148
#define TAR_TYPEFLAG_OFFSET 156
#define TAR_VERSION_OFFSET 263

static int failures = 0;

struct tar_test {
	const char *name;
	void (*run)(void);
};

size_t FTLstrlen(const char *s, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strlen(s);
}

size_t FTLstrnlen(const char *s, const size_t maxlen, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	size_t len = 0;
	while (len < maxlen && s[len] != '\0')
		len++;
	return len;
}

int FTLstrncmp(const char *s1, const char *s2, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strncmp(s1, s2, n);
}

int FTLstrcmp(const char *s1, const char *s2, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return strcmp(s1, s2);
}

void *FTLmemcpy(void *dest, const void *src, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memcpy(dest, src, n);
}

void *FTLmemset(void *s, const int c, const size_t n, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return memset(s, c, n);
}

void *FTLcalloc(const size_t nmemb, const size_t size, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	return calloc(nmemb, size);
}

bool FTLfree(void *ptr, const char *file, const char *func, const int line)
{
	(void)file;
	(void)func;
	(void)line;
	free(ptr);
	return true;
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

static void expect(const bool condition, const char *message)
{
	if (condition)
		return;

	fprintf(stderr, "FAIL: %s\n", message);
	failures++;
}

static void write_size_octal(uint8_t *field, const size_t size)
{
	memset(field, '0', TAR_SIZE_SIZE);
	field[TAR_SIZE_SIZE - 1] = '\0';

	size_t value = size;
	for (size_t i = TAR_SIZE_SIZE - 2; i > 0; i--) {
		field[i] = (uint8_t)('0' + (value & 7u));
		value >>= 3;
	}
}

static void finish_header(uint8_t *header)
{
	memset(header + TAR_CHECKSUM_OFFSET, ' ', 8);

	unsigned int checksum = 0;
	for (size_t i = 0; i < TAR_BLOCK_SIZE; i++)
		checksum += header[i];

	snprintf((char *)header + TAR_CHECKSUM_OFFSET, 8, "%06o", checksum);
	header[TAR_CHECKSUM_OFFSET + 6] = '\0';
	header[TAR_CHECKSUM_OFFSET + 7] = ' ';
}

static void write_entry(uint8_t *tar, const size_t offset, const char *name, const size_t size, const int payload_byte)
{
	uint8_t *header = tar + offset;
	memset(header, 0, TAR_BLOCK_SIZE);
	memcpy(header, name, strlen(name));
	write_size_octal(header + TAR_SIZE_OFFSET, size);
	header[TAR_TYPEFLAG_OFFSET] = '0';
	memcpy(header + TAR_MAGIC_OFFSET, "ustar", 6);
	memcpy(header + TAR_VERSION_OFFSET, "00", 2);
	finish_header(header);

	if (size > 0)
		memset(tar + offset + TAR_BLOCK_SIZE, payload_byte, size);
}

static void write_raw_name_entry(uint8_t *tar, const size_t offset, const uint8_t name[TAR_NAME_SIZE], const size_t size)
{
	uint8_t *header = tar + offset;
	memset(header, 0, TAR_BLOCK_SIZE);
	memcpy(header, name, TAR_NAME_SIZE);
	write_size_octal(header + TAR_SIZE_OFFSET, size);
	header[TAR_TYPEFLAG_OFFSET] = '0';
	memcpy(header + TAR_MAGIC_OFFSET, "ustar", 6);
	memcpy(header + TAR_VERSION_OFFSET, "00", 2);
	finish_header(header);
}

static void write_entry_with_size_field(uint8_t *tar, const uint8_t size_field[TAR_SIZE_SIZE])
{
	uint8_t *header = tar;
	memset(header, 0, TAR_BLOCK_SIZE);
	memcpy(header, "bad-size", 8);
	memcpy(header + TAR_SIZE_OFFSET, size_field, TAR_SIZE_SIZE);
	header[TAR_TYPEFLAG_OFFSET] = '0';
	memcpy(header + TAR_MAGIC_OFFSET, "ustar", 6);
	memcpy(header + TAR_VERSION_OFFSET, "00", 2);
	finish_header(header);
}

static cJSON *list_archive(const uint8_t *tar, const size_t tar_size)
{
	cJSON *files = list_files_in_tar(tar, tar_size);
	expect(files != NULL, "list_files_in_tar returns an array");
	return files;
}

static void expect_find_missing(const uint8_t *tar, const size_t tar_size, const char *name, const char *message)
{
	size_t file_size = 12345;
	const char *file = find_file_in_tar(tar, tar_size, name, &file_size);
	expect(file == NULL, message);
	expect(file_size == 0, "missing find resets fileSize");
}

static void expect_list_count(const uint8_t *tar, const size_t tar_size, const int expected, const char *message)
{
	cJSON *files = list_archive(tar, tar_size);
	expect(cJSON_GetArraySize(files) == expected, message);
	cJSON_Delete(files);
}

static const char *listed_name(cJSON *files, const int index)
{
	cJSON *file = cJSON_GetArrayItem(files, index);
	if (file == NULL)
		return NULL;

	cJSON *name = cJSON_GetObjectItemCaseSensitive(file, "name");
	return cJSON_GetStringValue(name);
}

static double listed_size(cJSON *files, const int index)
{
	cJSON *file = cJSON_GetArrayItem(files, index);
	if (file == NULL)
		return -1;

	cJSON *size = cJSON_GetObjectItemCaseSensitive(file, "size");
	return cJSON_GetNumberValue(size);
}

static bool listed_name_equals(cJSON *files, const int index, const char *expected)
{
	const char *name = listed_name(files, index);
	return name != NULL && strcmp(name, expected) == 0;
}

static bool listed_size_equals(cJSON *files, const int index, const size_t expected)
{
	return (size_t)listed_size(files, index) == expected;
}

static void test_short_archives_are_rejected(void)
{
	uint8_t tar[TAR_BLOCK_SIZE] = { 0 };

	expect_find_missing(tar, 0, "entry", "zero-byte archive is rejected");
	expect_find_missing(tar, 16, "entry", "short archive is rejected before magic read");
	expect_find_missing(tar, TAR_BLOCK_SIZE - 1, "entry", "511-byte archive is rejected before magic read");

	expect_list_count(tar, 0, 0, "zero-byte archive lists no files");
	expect_list_count(tar, 16, 0, "short archive lists no files");
	expect_list_count(tar, TAR_BLOCK_SIZE - 1, 0, "511-byte archive lists no files");
}

static void test_valid_size_boundaries(void)
{
	const size_t sizes[] = { 0, 1, 511, 512, 513 };

	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		uint8_t tar[2048] = { 0 };
		const size_t size = sizes[i];
		size_t tar_size = 0;
		expect(tar_entry_span(size, &tar_size), "tar_entry_span calculates valid size boundary span");
		write_entry(tar, 0, "entry", size, 'A' + (int)i);

		size_t file_size = 999;
		const char *file = find_file_in_tar(tar, tar_size, "entry", &file_size);
		expect(file == (const char *)tar + TAR_BLOCK_SIZE, "valid size boundary is found");
		expect(file_size == size, "valid size boundary reports expected fileSize");
		if (size > 0)
			expect(file[0] == 'A' + (int)i, "valid size boundary points at payload");

		cJSON *files = list_archive(tar, tar_size);
		expect(cJSON_GetArraySize(files) == 1, "valid size boundary is listed");
		expect(listed_name_equals(files, 0, "entry"), "valid size boundary lists the name");
		expect(listed_size_equals(files, 0, size), "valid size boundary lists the size");
		cJSON_Delete(files);
	}
}

static void test_invalid_size_fields_are_rejected(void)
{
	const uint8_t cases[][TAR_SIZE_SIZE] = {
		{ 0 },
		{ ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ' },
		{ '0', '0', '0', '0', '0', '0', '0', 'x', '0', '0', '1', '\0' },
		{ '0', '0', '0', '0', '0', '0', '0', '8', '0', '0', '1', '\0' },
		{ '0', '0', '0', '1', ' ', '0', '0', '0', '0', '0', '1', '\0' },
		{ '1', '\0', '1', '0', '0', '0', '0', '0', '0', '0', '0', '\0' },
	};

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		uint8_t tar[1024] = { 0 };
		write_entry_with_size_field(tar, cases[i]);
		expect_find_missing(tar, sizeof(tar), "bad-size", "invalid size field is rejected by find");
		expect_list_count(tar, sizeof(tar), 0, "invalid size field is rejected by list");
	}
}

static void test_huge_size_stops_traversal(void)
{
	uint8_t tar[1024] = { 0 };
	const uint8_t size_field[TAR_SIZE_SIZE] = {
		'3', '7', '7', '7', '7', '7', '7', '7', '7', '7', '7', '\0'
	};

	write_entry_with_size_field(tar, size_field);

	expect_find_missing(tar, sizeof(tar), "target", "huge padded size stops traversal");
	expect_list_count(tar, sizeof(tar), 0, "huge padded size is not listed without payload");
}

static void test_leading_space_size_field_is_accepted(void)
{
	uint8_t tar[1024] = { 0 };
	const uint8_t size_field[TAR_SIZE_SIZE] = {
		' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', '1', '\0', ' '
	};

	write_entry_with_size_field(tar, size_field);
	tar[TAR_BLOCK_SIZE] = 'x';

	size_t file_size = 0;
	const char *file = find_file_in_tar(tar, sizeof(tar), "bad-size", &file_size);
	expect(file == (const char *)tar + TAR_BLOCK_SIZE, "leading-space size field is accepted");
	expect(file_size == 1, "leading-space size field parses expected size");
}

static void test_truncated_payloads_are_rejected(void)
{
	uint8_t tar[1024] = { 0 };
	write_entry(tar, 0, "entry", 4, 'A');

	expect_find_missing(tar, TAR_BLOCK_SIZE + 2, "entry", "matching truncated payload is rejected");
	expect_list_count(tar, TAR_BLOCK_SIZE + 2, 0, "truncated payload is not listed");
}

static void test_sample_short_archive_rejection(void)
{
	uint8_t *short_tar = calloc(1, 16);
	expect(short_tar != NULL, "short archive allocation succeeds");
	if (short_tar != NULL) {
		size_t file_size = 0;
		const char *file = find_file_in_tar(short_tar, 16, "adlist.json", &file_size);
		expect(file == NULL, "short archive lookup returns NULL");
		expect(file_size == 0, "short archive lookup leaves fileSize zero");
		free(short_tar);
	}
}

static void test_sample_truncated_archive_rejection(void)
{
	uint8_t *truncated_tar = calloc(1, TAR_BLOCK_SIZE);
	expect(truncated_tar != NULL, "truncated archive allocation succeeds");
	if (truncated_tar != NULL) {
		memcpy(truncated_tar, "adlist.json", strlen("adlist.json"));
		memcpy(truncated_tar + TAR_MAGIC_OFFSET, "ustar", 5);
		memset(truncated_tar + TAR_SIZE_OFFSET, '0', TAR_SIZE_SIZE);
		memcpy(truncated_tar + TAR_SIZE_OFFSET, "77777777777", strlen("77777777777"));

		size_t file_size = 0;
		const char *file = find_file_in_tar(truncated_tar, TAR_BLOCK_SIZE, "adlist.json", &file_size);
		expect(file == NULL, "truncated archive lookup returns NULL");
		expect(file_size == 0, "truncated archive lookup leaves fileSize zero");
		if (file != NULL && file_size > 0) {
			volatile unsigned char byte = (unsigned char)file[file_size - 1];
			(void)byte;
			expect(false, "truncated archive exposed an out-of-bounds payload");
		}

		free(truncated_tar);
	}
}

static void test_nonmatching_missing_padding_is_rejected(void)
{
	uint8_t tar[1024] = { 0 };
	write_entry(tar, 0, "skip", 1, 'A');

	expect_find_missing(tar, TAR_BLOCK_SIZE + 1, "target", "nonmatching entry missing padding stops traversal");
}

static void test_nonterminated_names_are_rejected(void)
{
	uint8_t tar[1024] = { 0 };
	uint8_t name[TAR_NAME_SIZE];
	char needle[TAR_NAME_SIZE + 1];

	memset(name, 'a', sizeof(name));
	memset(needle, 'a', TAR_NAME_SIZE);
	needle[TAR_NAME_SIZE] = '\0';

	write_raw_name_entry(tar, 0, name, 0);

	expect_find_missing(tar, sizeof(tar), needle, "nonterminated name field is rejected by find");
	expect_list_count(tar, sizeof(tar), 0, "nonterminated name field is rejected by list");
}

static void test_skip_offsets_find_later_entries(void)
{
	const size_t sizes[] = { 1, 512, 513 };

	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		uint8_t tar[4096] = { 0 };
		const size_t first_size = sizes[i];
		size_t second_offset = 0;
		size_t second_span = 0;
		expect(tar_entry_span(first_size, &second_offset), "tar_entry_span calculates skipped entry span");
		expect(tar_entry_span(3, &second_span), "tar_entry_span calculates target entry span");

		write_entry(tar, 0, "skip", first_size, 'S');
		write_entry(tar, second_offset, "target", 3, 'T');

		const size_t tar_size = second_offset + second_span;
		size_t file_size = 0;
		const char *file = find_file_in_tar(tar, tar_size, "target", &file_size);
		expect(file == (const char *)tar + second_offset + TAR_BLOCK_SIZE, "skip offset reaches later entry");
		expect(file_size == 3, "skip offset returns later entry size");
		expect(file != NULL && file[0] == 'T', "skip offset returns later entry payload");

		cJSON *files = list_archive(tar, tar_size);
		expect(cJSON_GetArraySize(files) == 2, "skip offset lists both entries");
		expect(listed_name_equals(files, 0, "skip"), "skip offset lists first name");
		expect(listed_name_equals(files, 1, "target"), "skip offset lists second name");
		cJSON_Delete(files);
	}
}

static void test_malformed_second_entry_stops_listing(void)
{
	uint8_t tar[2048] = { 0 };
	size_t second_offset = 0;
	const uint8_t bad_size[TAR_SIZE_SIZE] = {
		'0', '0', '0', '0', '0', '0', '0', 'x', '0', '0', '1', '\0'
	};

	expect(tar_entry_span(0, &second_offset), "tar_entry_span calculates empty entry span");

	write_entry(tar, 0, "first", 0, 0);
	write_entry_with_size_field(tar + second_offset, bad_size);

	cJSON *files = list_archive(tar, sizeof(tar));
	expect(cJSON_GetArraySize(files) == 1, "malformed second entry stops listing after prior valid entries");
	expect(listed_name_equals(files, 0, "first"), "malformed second entry preserves prior valid listing");
	cJSON_Delete(files);
}

static const struct tar_test tests[] = {
	{ "short-archives", test_short_archives_are_rejected },
	{ "valid-size-boundaries", test_valid_size_boundaries },
	{ "invalid-size-fields", test_invalid_size_fields_are_rejected },
	{ "huge-size", test_huge_size_stops_traversal },
	{ "leading-space-size", test_leading_space_size_field_is_accepted },
	{ "truncated-payloads", test_truncated_payloads_are_rejected },
	{ "short-sample-archive", test_sample_short_archive_rejection },
	{ "truncated-sample-archive", test_sample_truncated_archive_rejection },
	{ "missing-padding", test_nonmatching_missing_padding_is_rejected },
	{ "nonterminated-names", test_nonterminated_names_are_rejected },
	{ "skip-offsets", test_skip_offsets_find_later_entries },
	{ "malformed-second-entry", test_malformed_second_entry_stops_listing },
};

static int run_test(const struct tar_test *test)
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

	fprintf(stderr, "unknown tar regression test: %s\n", name);
	fprintf(stderr, "available tests:\n");
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		fprintf(stderr, "  %s\n", tests[i].name);

	return 2;
}

// Run a single test in a forked child so a sanitizer abort (or any crash)
// fails only that case instead of taking down the rest of the suite. This
// restores the per-case isolation of the previous Python harness without
// duplicating the parser: a single `./tar_regression` invocation still runs
// every case under -DTAR_REGRESSION_SANITIZE=ON. The child prints its own
// PASS/FAIL line via run_test(); the parent only reports cases that died by
// signal, where run_test() never got to return.
static int run_test_isolated(const struct tar_test *test)
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

	// Full suite: isolate each case in its own process so one sanitizer
	// abort does not hide the results of the cases that follow. Named
	// cases (handled above) stay in-process for straightforward debugging.
	int status = 0;
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		if (run_test_isolated(&tests[i]) != 0)
			status = 1;

	return status;
}
