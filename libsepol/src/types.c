#include <sepol/types.h>

#include <assert.h>
#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"
#include "sepol/policydb/ebitmap.h"
#include "sepol/policydb/hashtab.h"
#include "sepol/type_record.h"

struct sepol_type_iter {
	const sepol_policydb_t *p;
	hashtab_iter_t hashtab_iter;
};

static int type_datum_to_record(sepol_handle_t *handle, const policydb_t *p,
				const type_datum_t *type_datum, const char *name,
				sepol_type_t **type)
{
	sepol_type_t *new_type = NULL;

	if (sepol_type_create(handle, &new_type))
		goto err;

	/* Copy name */
	if (!name)
		name = p->p_type_val_to_name[type_datum->s.value - 1];
	if (sepol_type_set_name(handle, new_type, name))
		goto err;

	/* Copy flavor */
	switch (type_datum->flavor) {
	case TYPE_TYPE:
		if (!type_datum->primary)
			// this is a kernel alias TODO: should we hide it?
			sepol_type_set_flavor(new_type, SEPOL_TYPE_ALIAS);
		else
			sepol_type_set_flavor(new_type, SEPOL_TYPE_TYPE);
		break;
	case TYPE_ATTRIB:
		sepol_type_set_flavor(new_type, SEPOL_TYPE_ATTRIB);
		break;
	case TYPE_ALIAS:
		sepol_type_set_flavor(new_type, SEPOL_TYPE_ALIAS);
		break;
	default:
		ERR(handle, "unknown type flavor");
		goto err;
	}

	/* Copy types */
	const ebitmap_t *subtypes_bitmap;
	ebitmap_node_t *node;
	uint32_t bit;
	if (p->policy_type == POLICY_KERN) {
		/*
		 * In kernel policy, attribute type relations are stored in a
		 * global bitmap
		 */
		if (type_datum->flavor == TYPE_ATTRIB) {
			subtypes_bitmap = &p->attr_type_map[type_datum->s.value - 1];
		} else {
			subtypes_bitmap = &p->type_attr_map[type_datum->s.value - 1];
		}
	} else {
		subtypes_bitmap = &type_datum->types;
	}
	ebitmap_for_each_positive_bit(subtypes_bitmap, node, bit) {
		if (type_datum->s.value != bit + 1 &&
		    sepol_type_add_subtype(handle, new_type, p->p_type_val_to_name[bit]))
			goto err;
	}

	/* Copy flags */
	if ((type_datum->flags & TYPE_FLAGS_PERMISSIVE ||
	     /* Kernel policy has permissive flag stored separately as TYPE ( */
	     (p->policy_type == POLICY_KERN &&
	      ebitmap_get_bit(&p->permissive_map, type_datum->s.value))) &&
	    sepol_type_set_flag(new_type, SEPOL_TYPE_FLAGS_PERMISSIVE))
		goto err;
	if (type_datum->flags & TYPE_FLAGS_EXPAND_ATTR_TRUE &&
	    sepol_type_set_flag(new_type, SEPOL_TYPE_FLAGS_EXPAND_ATTR_TRUE))
		goto err;
	if (type_datum->flags & TYPE_FLAGS_EXPAND_ATTR_FALSE &&
	    sepol_type_set_flag(new_type, SEPOL_TYPE_FLAGS_EXPAND_ATTR_FALSE))
		goto err;

	/* Copy alias' primary name */
	if (!type_datum->primary && type_datum->flavor == TYPE_TYPE) {
		if (sepol_type_set_alias_of(handle, new_type, p->p_type_val_to_name[type_datum->s.value - 1]))
			goto err;
	} else if (type_datum->flavor == TYPE_ALIAS) {
		if (sepol_type_set_alias_of(handle, new_type, p->p_type_val_to_name[type_datum->primary - 1]))
			goto err;
	}

	/* Copy bounds name */
	if (type_datum->bounds &&
	    sepol_type_set_bounds(handle, new_type,
			   	  p->p_type_val_to_name[type_datum->bounds - 1]))
		goto err;

	*type = new_type;
	return STATUS_SUCCESS;

err:
	if (new_type)
		sepol_type_free(new_type);

	return STATUS_ERR;
}

// TODO: should we have method for adding/modifying the type in the policy

/* Return the number of types */
int sepol_type_count(sepol_handle_t *handle __attribute__ ((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	*response = p->p.p_types.table->nel;
	return STATUS_SUCCESS;
}

/* Check if the specified type exists */
int sepol_type_exists(sepol_handle_t *handle __attribute__ ((unused)),
		      const sepol_policydb_t *policydb,
		      const sepol_type_key_t *key, int *response)
{
	const char *name;
	sepol_type_key_unpack(key, &name);

	*response = hashtab_search(policydb->p.p_types.table, name) != NULL;

	return STATUS_SUCCESS;
}

/* Query a type - returns the type or NULL if not found */
int sepol_type_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_type_key_t *key, sepol_type_t **response)
{
	const char *name;
	sepol_type_key_unpack(key, &name);

	type_datum_t *type_datum = hashtab_search(p->p.p_types.table, name);
	if (!type_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return type_datum_to_record(handle, &p->p, type_datum, name, response);
}

/* Iterators */
int sepol_type_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_type_iter_t **iter)
{
	sepol_type_iter_t *new = malloc(sizeof(sepol_type_iter_t));
	if (!new) {
		ERR(handle, "cannot allocate memory for sepol_type_iter_t");
		return STATUS_ERR;
	}
	new->p = p;
	hashtab_iter_init(p->p.p_types.table, &new->hashtab_iter);

	*iter = new;

	return STATUS_SUCCESS;
}

void sepol_type_iter_destroy(sepol_type_iter_t *iter)
{
	free(iter);
}

int sepol_type_iter_next(sepol_handle_t *handle, sepol_type_iter_t *iter,
			 sepol_type_t **item)
{
	char *key;
	type_datum_t *datum;

	hashtab_iter_next(&iter->hashtab_iter, &key, (hashtab_datum_t *)&datum);
	if (!key) {
		*item = NULL;
		return STATUS_SUCCESS;
	}

	return type_datum_to_record(handle, &iter->p->p, datum, key, item);
}
