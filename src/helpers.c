#include <stdio.h>  // snprintf()
#include <stdlib.h> // malloc(), free(), getenv()
#include <string.h> // strlen(), strcmp()
#include <time.h>   // clock_gettime(), clockid_t, struct timespec

/*
 * Returns 1 if both input strings are equal, otherwise 0.
 */
int equals(const char *str1, const char *str2)
{
	return strcmp(str1, str2) == 0;
}

/*
 * Returns 1 if the input string is NULL or empty, otherwise 0.
 */
int empty(const char *str)
{
	return (str == NULL || str[0] == '\0');
}

/*
 * Returns 1 if the input string is quoted, otherwise 0.
 */
int is_quoted(const char *str)
{
	size_t len = strlen(str); // Length without null terminator
	if (len < 2) return 0;    // We need at least two quotes (empty string)
	char first = str[0];
	char last  = str[len - 1];
	if (first == '\'' && last == '\'') return 1; // Single-quoted string
	if (first == '"'  && last == '"')  return 1; // Double-quoted string
	return 0;
}

/*
 * Returns a pointer to a string that is the same as the input string, 
 * minus the enclosing quotation chars (either single or double quotes).
 * The pointer is allocated with malloc(), the caller needs to free it.
 */
char *unquote(const char *str)
{
	char *trimmed = NULL;
	size_t len = strlen(str);
	if (len < 2) // Prevent zero-length allocation
	{
		trimmed = malloc(1); // Make space for null terminator
		trimmed[0] = '\0';   // Add the null terminator
	}
	else
	{
		trimmed = malloc(len-2+1);        // No quotes, null terminator
		strncpy(trimmed, &str[1], len-2); // Copy everything in between
		trimmed[len-2] = '\0';            // Add the null terminator
	}
	return trimmed;
}

/*
 * Escapes the given string `str` by finding all occurences of the character
 * given in `e`, then creating a new string where each occurence of `e` will 
 * have another one prepended in front of it. The new string is allocated with 
 * malloc(), so it is upon the caller to free the result at some point. 
 * If `diff` is not NULL, it will be set to the number of inserted characters, 
 * effectively giving the difference in size between `str` and the result.
 * `str` is assumed to be null terminated, otherwise the behavior is undefined.
 */
char *escape(const char *str, const char e, size_t *diff)
{
	char   c = 0; // current char
	size_t i = 0; // index of current char
	size_t n = 0; // number of `e` chars found

	// Count the occurences of `e` in `str`
	while ((c = str[i]) != '\0')
	{
		if (c == e)
		{
			++n;
		}
		++i;
	}

	// Return the number of `e`s in `str` via `diff`
	if (diff != NULL)
	{
		*diff = n;
	}

	// Allocate memory for the escaped string
	char *escstr = malloc(i + n + 1); 

	// Create the escaped string
	size_t k = 0;
	for (size_t j = 0; j < i; ++j)
	{
		// Insert two `e` if we find one `e` char
		if (str[j] == e)
		{
			escstr[k++] = e;
			escstr[k++] = e;
		}
		// Otherwise just copy the char as is
		else
		{
			escstr[k++] = str[j];
		}
	}
	
	// Add the null terminator and return
	escstr[k] = '\0';
	return escstr;
}

