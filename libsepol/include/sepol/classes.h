#ifndef _SEPOL_CLASSES_H_
#define _SEPOL_CLASSES_H_

#include <sepol/policydb.h>
#include <sepol/class_record.h>
#include <sepol/handle.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct sepol_class_iter;
typedef struct sepol_class_iter sepol_class_iter_t;


/* Return the number of classes */
extern int sepol_class_count(sepol_handle_t *handle, const sepol_policydb_t *p,
			     unsigned int *response);

/* Check if the specified class exists */
extern int sepol_class_exists(sepol_handle_t *handle,
			      const sepol_policydb_t *policydb,
			      const sepol_class_key_t *key, int *response);

/* Query a class - returns the class or NULL if not found */
extern int sepol_class_query(sepol_handle_t *handle, const sepol_policydb_t *p,
			     const sepol_class_key_t *key,
			     sepol_class_t **response);

/* Iterating classes */
extern int sepol_class_iter_create(sepol_handle_t *handle,
				   const sepol_policydb_t *p,
				   sepol_class_iter_t **iter);
extern void sepol_class_iter_destroy(sepol_class_iter_t *iter);
extern int sepol_class_iter_next(sepol_handle_t *handle, sepol_class_iter_t *iter,
				 sepol_class_t **item);

#ifdef __cplusplus
}
#endif

#endif
