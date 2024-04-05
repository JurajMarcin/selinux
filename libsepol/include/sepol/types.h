#ifndef _SEPOL_TYPES_H_
#define _SEPOL_TYPES_H_

#include <sepol/policydb.h>
#include <sepol/type_record.h>
#include <sepol/handle.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_type_iter;
typedef struct sepol_type_iter sepol_type_iter_t;


/* Modify the type, or add it, if the key is not found */
extern int sepol_type_modify(sepol_handle_t *handle,
			     sepol_policydb_t *policydb,
			     const sepol_type_key_t *key,
			     const sepol_type_t *data);

/* Return the number of types */
extern int sepol_type_count(sepol_handle_t *handle,
			    const sepol_policydb_t *p, unsigned int *response);

/* Check if the specified type exists */
extern int sepol_type_exists(sepol_handle_t *handle,
			     const sepol_policydb_t *policydb,
			     const sepol_type_key_t *key, int *response);

/* Query a type - returns the type or NULL if not found */
extern int sepol_type_query(sepol_handle_t *handle,
			    const sepol_policydb_t *p,
			    const sepol_type_key_t *key,
			    sepol_type_t **response);

/* Iterating types */
extern int sepol_type_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_type_iter_t **iter);
extern void sepol_type_iter_destroy(sepol_type_iter_t *iter);
extern int sepol_type_iter_next(sepol_handle_t *handle, sepol_type_iter_t *iter,
				sepol_type_t **item);

#ifdef __cplusplus
}
#endif

#endif
