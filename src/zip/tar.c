/* Pi-hole: A black hole for Internet advertisements
 *  (c) 2023 Pi-hole, LLC (https://pi-hole.net)
 *  Network-wide ad blocking via your own hardware.
 *
 *  FTL Engine
 *  In-memory tar reading routines
 *
 *  This file is copyright under the latest version of the EUPL.
 *  Please see LICENSE file for your rights under this license. */

#include "zip/tar.h"
#include "log.h"

// TAR offsets
#define TAR_NAME_OFFSET 0
#define TAR_SIZE_OFFSET 124
#define TAR_MAGIC_OFFSET 257

// TAR constants
#define TAR_BLOCK_SIZE 512
#define TAR_NAME_SIZE 100
#define TAR_SIZE_SIZE 12
#define TAR_MAGIC_SIZE 5

static const char MAGIC_CONST[] = "ustar"; // Modern GNU tar's magic const */

/**
 * Parse the size field in the TAR header
 * @param ptr Pointer to a size field in the TAR header in memory
 * @param size Pointer to a size_t variable to store the parsed size in
 * @return Returns true if the size field is successfully parsed, and returns false otherwise
 */
static bool parse_tar_size(const char *ptr, size_t *size)
{
	size_t parsed = 0;
	bool seen_digit = false;
	bool is_trailing = false;

	for (size_t i = 0; i < TAR_SIZE_SIZE; i++)
	{
		const unsigned char c = (const unsigned char)ptr[i];
		if (c == ' ')
		{
			if (seen_digit)
				is_trailing = true;
			continue;
		}
		if (c == '\0')
		{
			if (!seen_digit)
				return false;
			is_trailing = true;
			continue;
		}

		if (is_trailing || c < '0' || c > '7')
			return false;

		const size_t digit = c - '0';

		if (parsed > (SIZE_MAX - digit) / 8)
			return false;

		parsed = parsed * 8 + digit;
		seen_digit = true;
	}

	if (!seen_digit)
		return false;

	*size = parsed;

	return true;
}

/**
 * Calculate the span of a tar entry
 * @param size Size of the tar entry
 * @param span Pointer to a size_t variable to store the span of the entry in
 * @return Returns true if the entry span is successfully calculated, and returns false otherwise
 */
static bool tar_entry_span(const size_t size, size_t *span)
{
	if (size % TAR_BLOCK_SIZE)
	{
		if (size > SIZE_MAX - TAR_BLOCK_SIZE * 2)
			return false;

		*span = (2 + size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
	}
	else
	{
		if (size > SIZE_MAX - TAR_BLOCK_SIZE)
			return false;

		*span = (1 + size / TAR_BLOCK_SIZE) * TAR_BLOCK_SIZE;
	}

	return true;
}

/**
 * Find a file in a TAR archive
 * @param tarData Pointer to the TAR archive in memory
 * @param tarSize Size of the TAR archive in memory in bytes
 * @param fileName Name of the file to find
 * @param fileSize Pointer to a size_t variable to store the file size in
 * @return Pointer to the file data or NULL if not found
 */
const char * __attribute__((nonnull (1,3,4))) find_file_in_tar(const uint8_t *tarData, const size_t tarSize,
                                                               const char *fileName, size_t *fileSize)
{
	size_t size, p = 0, entrySpan = 0;

	// Convert to char * to be able to do pointer arithmetic more easily
	const char *tar = (const char *)tarData;

	// Initialize fileSize to 0
	*fileSize = 0;

	// Loop through TAR file
	while (p <= tarSize && TAR_BLOCK_SIZE <= tarSize - p)
	{
		const char *header = tar + p;
		const char *name = header + TAR_NAME_OFFSET;
		const char *sz = header + TAR_SIZE_OFFSET;

		// Check for supported TAR version
		for (size_t i = 0; i < TAR_MAGIC_SIZE; i++)
			if (header[TAR_MAGIC_OFFSET + i] != MAGIC_CONST[i])
				return NULL;

		if (!parse_tar_size(sz, &size))
			return NULL;

		// Span size in bytes. Depends on file size and TAR block size
		if (!tar_entry_span(size, &entrySpan))
			return NULL;


		// Reject names that are not null terminated
		// This is slightly stricter than POSIX ustar, which allows non null terminated names
		if(strnlen(name, TAR_NAME_SIZE) == TAR_NAME_SIZE)
			return NULL;

		// File found in TAR - return pointer to file data and set fileSize
		if (!strncmp(name, fileName, TAR_NAME_SIZE))
		{
			// p + TAR_BLOCK_SIZE <= tarSize is guaranteed to hold from the loop invariant
			const size_t payload = p + TAR_BLOCK_SIZE;

			// Invalid size in tar - return NULL
			if (size > tarSize - payload)
				return NULL;

			*fileSize = size;
			return tar + payload;
		}

		// Invalid offset in tar - return NULL
		if (entrySpan > tarSize - p)
			return NULL;

		p += entrySpan;
	}
	return NULL; // No file found in TAR - return NULL
}

/**
 * List all files in a TAR archive
 * @param tarData Pointer to the TAR archive in memory
 * @param tarSize Size of the TAR archive in memory in bytes
 * @return Pointer to a cJSON array containing all file names with file size
 */
cJSON * __attribute__((nonnull (1))) list_files_in_tar(const uint8_t *tarData, const size_t tarSize)
{
	cJSON *files = cJSON_CreateArray();
	size_t size, p = 0, entrySpan = 0;

	// Convert to char * to be able to do pointer arithmetic more easily
	const char *tar = (const char *)tarData;

	// Loop through TAR file
	while (p <= tarSize && TAR_BLOCK_SIZE <= tarSize - p)
	{
		const char *header = tar + p;
		const char *name = header + TAR_NAME_OFFSET;
		const char *sz = header + TAR_SIZE_OFFSET;

		// Check for supported TAR version
		for (size_t i = 0; i < TAR_MAGIC_SIZE; i++)
			if (header[TAR_MAGIC_OFFSET + i] != MAGIC_CONST[i])
				return files;

		if (!parse_tar_size(sz, &size))
			return files;

		// Span size in bytes. Depends on file size and TAR block size
		if (!tar_entry_span(size, &entrySpan))
			return files;

		// Reject names that are not null terminated
		// This is slightly stricter than POSIX ustar, which allows non null terminated names
		if(strnlen(name, TAR_NAME_SIZE) == TAR_NAME_SIZE)
			return files;

		// p + TAR_BLOCK_SIZE <= tarSize is guaranteed to hold from the loop invariant
		const size_t payload = p + TAR_BLOCK_SIZE;

		// Invalid size in tar - return files
		if (size > tarSize - payload)
			return files;

		// Add file name to cJSON array
		cJSON *file = cJSON_CreateObject();
		cJSON_AddItemToObject(file, "name", cJSON_CreateString(name));
		cJSON_AddItemToObject(file, "size", cJSON_CreateNumber(size));
		cJSON_AddItemToArray(files, file);

		// Invalid offset in tar - return files
		if (entrySpan > tarSize - p)
			return files;

		p += entrySpan;
	}
	return files;
}
