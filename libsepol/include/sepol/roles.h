#ifndef _SEPOL_ROLES_H_
#define _SEPOL_ROLES_H_

#include <sepol/policydb.h>
#include <sepol/role_record.h>
#include <sepol/handle.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_role_iter;
typedef struct sepol_role_iter sepol_role_iter_t;


/* Return the number of roles */
extern int sepol_role_count(sepol_handle_t *handle,
			    const sepol_policydb_t *p, unsigned int *response);

/* Check if the specified role exists */
extern int sepol_role_exists(sepol_handle_t *handle,
			     const sepol_policydb_t *p,
			     const sepol_role_key_t *key, int *response);

/* Query a role - returns the role or NULL if not found */
extern int sepol_role_query(sepol_handle_t *handle,
			    const sepol_policydb_t *p,
			    const sepol_role_key_t *key,
			    sepol_role_t **response);

/* Iterating roles */
extern int sepol_role_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_role_iter_t **iter);
extern void sepol_role_iter_destroy(sepol_role_iter_t *iter);
extern int sepol_role_iter_next(sepol_handle_t *handle, sepol_role_iter_t *iter,
				sepol_role_t **item);

#ifdef __cplusplus
}
#endif

#endif
