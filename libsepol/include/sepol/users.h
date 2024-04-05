#ifndef _SEPOL_USERS_H_
#define _SEPOL_USERS_H_

#include <sepol/policydb.h>
#include <sepol/user_record.h>
#include <sepol/handle.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_user_iter;
typedef struct sepol_user_iter sepol_user_iter_t;

/* Modify the user, or add it, if the key is not found */
extern int sepol_user_modify(sepol_handle_t * handle,
			     sepol_policydb_t * policydb,
			     const sepol_user_key_t * key,
			     const sepol_user_t * data);

/* Return the number of users */
extern int sepol_user_count(sepol_handle_t * handle,
			    const sepol_policydb_t * p, unsigned int *response);

/* Check if the specified user exists */
extern int sepol_user_exists(sepol_handle_t * handle,
			     const sepol_policydb_t * policydb,
			     const sepol_user_key_t * key, int *response);

/* Query a user - returns the user or NULL if not found */
extern int sepol_user_query(sepol_handle_t * handle,
			    const sepol_policydb_t * p,
			    const sepol_user_key_t * key,
			    sepol_user_t ** response);

/* Iterate the users
 * The handler may return:
 * -1 to signal an error condition,
 * 1 to signal successful exit
 * 0 to signal continue */
extern int sepol_user_iterate(sepol_handle_t * handle,
			      const sepol_policydb_t * policydb,
			      int (*fn) (const sepol_user_t * user,
					 void *fn_arg), void *arg);

/* Users iterator */
extern int sepol_user_iter_create(sepol_handle_t *handle,
				  const sepol_policydb_t *p,
				  sepol_user_iter_t **iter);
extern void sepol_user_iter_destroy(sepol_user_iter_t *iter);
extern int sepol_user_iter_next(sepol_handle_t *handle, sepol_user_iter_t *iter,
				sepol_user_t **item);

#ifdef __cplusplus
}
#endif

#endif
