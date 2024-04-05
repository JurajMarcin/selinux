#include <sepol/roles.h>

#include <sepol/policydb/policydb.h>

#include "debug.h"

struct sepol_role_iter {
	const policydb_t *policydb;
	uint32_t idx;
};

static int role_datum_to_record(sepol_handle_t *handle,
				const policydb_t *policydb,
				role_datum_t *role_datum, sepol_role_t **record)
{
	sepol_role_t *new_role = NULL;
	if (sepol_role_create(handle, &new_role))
		goto err;

	if (sepol_role_set_name(handle, new_role,
				policydb->p_role_val_to_name[role_datum->s.value - 1]))
		goto err;

	ebitmap_node_t *enode;
	uint32_t bit;
	ebitmap_for_each_positive_bit(&role_datum->types.types, enode, bit) {
		if (sepol_role_add_type(handle, new_role,
			  		policydb->p_type_val_to_name[bit]))
			goto err;
	}

	if (role_datum->bounds &&
	    sepol_role_set_bounds(handle, new_role,
			   	  policydb->p_role_val_to_name[role_datum->bounds - 1]))
		goto err;


	switch (role_datum->flavor) {
	case ROLE_ROLE:
		if (sepol_role_set_flavor(new_role, SEPOL_ROLE_ROLE))
			goto err;
		break;
	case ROLE_ATTRIB:
		if (sepol_role_set_flavor(new_role, SEPOL_ROLE_ATTRIB))
			goto err;
		break;
	}

	ebitmap_for_each_positive_bit(&role_datum->roles, enode, bit) {
		if (sepol_role_add_subrole(handle, new_role,
					   policydb->p_role_val_to_name[bit]))
			goto err;
	}

	*record = new_role;
	return STATUS_SUCCESS;

err:
	sepol_role_free(new_role);
	return STATUS_ERR;
}

int sepol_role_count(sepol_handle_t *handle __attribute__ ((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	*response = p->p.p_roles.table->nel;
	return STATUS_SUCCESS;
}

int sepol_role_exists(sepol_handle_t *handle __attribute__ ((unused)),
		      const sepol_policydb_t *p, const sepol_role_key_t *key,
		      int *response)
{
	const char *name;
	sepol_role_key_unpack(key, &name);

	*response = (hashtab_search(p->p.p_roles.table, name) != NULL);

	return STATUS_SUCCESS;
}

int sepol_role_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		     const sepol_role_key_t *key, sepol_role_t **response)
{
	const char *name;
	sepol_role_key_unpack(key, &name);

	role_datum_t *role_datum = hashtab_search(p->p.p_roles.table, name);
	if (!role_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return role_datum_to_record(handle, &p->p, role_datum, response);
}

int sepol_role_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			   sepol_role_iter_t **iter)
{
	sepol_role_iter_t *tmp = malloc(sizeof(sepol_role_iter_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	tmp->policydb = &p->p;
	tmp->idx = 0;

	*iter = tmp;
	return STATUS_SUCCESS;
}

void sepol_role_iter_destroy(sepol_role_iter_t *iter)
{
	free(iter);
}

int sepol_role_iter_next(sepol_handle_t *handle, sepol_role_iter_t *iter,
			 sepol_role_t **item)
{
	if (iter->idx >= iter->policydb->p_roles.nprim) {
		*item = NULL;
		return STATUS_SUCCESS;
	}
	sepol_role_t *role;
	int status = role_datum_to_record(handle, iter->policydb,
					  iter->policydb->role_val_to_struct[iter->idx],
					  &role);
	if (status)
		return status;
	
	iter->idx++;
	*item = role;

	return STATUS_SUCCESS;
}
