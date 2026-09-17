#ifndef BOLT12_H
#define BOLT12_H

#ifdef __cplusplus
extern "C" {
#endif

/* NULL = safe for Tides CLN v24.02. Non-NULL = reason string; free with
 * bolt12_string_free. */
char *bolt12_tides_unsafe_invoice(const char *invoice);

void bolt12_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* BOLT12_H */
