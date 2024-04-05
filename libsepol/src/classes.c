#include <sepol/classes.h>

#include <sepol/policydb/policydb.h>
#include <stdlib.h>

#include "debug.h"
#include "sepol/handle.h"
#include "sepol/policydb/constraint.h"
#include "sepol/policydb/ebitmap.h"
#include "sepol/policydb/hashtab.h"
#include "sepol/class_record.h"

struct sepol_class_iter {
	const sepol_policydb_t *p;
	hashtab_iter_t hashtab_iter;
};

struct class_add_perm_args {
	sepol_handle_t *handle;
	sepol_class_t *class;
};

static int class_add_perm(hashtab_key_t key,
			  hashtab_datum_t datum __attribute__ ((unused)),
			  void *arg)
{
	const char *perm = key;
	struct class_add_perm_args *args = arg;

	return sepol_class_add_perm(args->handle, args->class, perm);
}

static char map_default(char from)
{
	switch (from) {
	case DEFAULT_SOURCE:
		return SEPOL_CLASS_DEFAULT_SOURCE;
	case DEFAULT_TARGET:
		return SEPOL_CLASS_DEFAULT_TARGET;
	}
	return 0;
}

static int constraint_expr_datum_to_record(sepol_handle_t *handle,
					   const policydb_t *p,
					   const constraint_expr_t *expr_datum,
					   sepol_constraint_expr_t **expr)
{
	sepol_constraint_expr_t *tmp;
	if (sepol_constraint_expr_create(handle, &tmp))
		return STATUS_ERR;
	
	/* Expr type */
	switch (expr_datum->expr_type) {
	case CEXPR_NOT:
		if (sepol_constraint_expr_set_type(handle, tmp, SEPOL_CEXPR_TYPE_NOT))
			goto err;
		break;
	case CEXPR_AND:
		if (sepol_constraint_expr_set_type(handle, tmp, SEPOL_CEXPR_TYPE_AND))
			goto err;
		break;
	case CEXPR_OR:
		if (sepol_constraint_expr_set_type(handle, tmp, SEPOL_CEXPR_TYPE_OR))
			goto err;
		break;
	case CEXPR_ATTR:
		if (sepol_constraint_expr_set_type(handle, tmp, SEPOL_CEXPR_TYPE_ATTR))
			goto err;
		break;
	case CEXPR_NAMES:
		if (sepol_constraint_expr_set_type(handle, tmp, SEPOL_CEXPR_TYPE_NAMES))
			goto err;
		break;
	}

	if (expr_datum->expr_type == CEXPR_ATTR || expr_datum->expr_type == CEXPR_NAMES) {
		/* Expr attr */
		switch (expr_datum->expr_type) {
		case CEXPR_USER:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_USER))
				goto err;
			break;
		case CEXPR_ROLE:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_ROLE))
				goto err;
			break;
		case CEXPR_TYPE:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_TYPE))
				goto err;
			break;
		case CEXPR_TARGET:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_TARGET))
				goto err;
			break;
		case CEXPR_XTARGET:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_XTARGET))
				goto err;
			break;
		case CEXPR_L1L2:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_L1L2))
				goto err;
			break;
		case CEXPR_L1H2:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_L1H2))
				goto err;
			break;
		case CEXPR_H1L2:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_H1L2))
				goto err;
			break;
		case CEXPR_H1H2:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_H1H2))
				goto err;
			break;
		case CEXPR_L1H1:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_L1H1))
				goto err;
			break;
		case CEXPR_L2H2:
			if (sepol_constraint_expr_set_attr(handle, tmp, SEPOL_CEXPR_ATTR_L2H2))
				goto err;
			break;
		}
		/* Expr op */
		switch (expr_datum->op) {
		case CEXPR_EQ:
			if (sepol_constraint_expr_set_op(handle, tmp, SEPOL_CEXPR_OP_EQ))
				goto err;
			break;
		case CEXPR_NEQ:
			if (sepol_constraint_expr_set_op(handle, tmp, SEPOL_CEXPR_OP_NEQ))
				goto err;
			break;
		case CEXPR_DOM:
			if (sepol_constraint_expr_set_op(handle, tmp, SEPOL_CEXPR_OP_DOM))
				goto err;
			break;
		case CEXPR_DOMBY:
			if (sepol_constraint_expr_set_op(handle, tmp, SEPOL_CEXPR_OP_DOMBY))
				goto err;
			break;
		case CEXPR_INCOMP:
			if (sepol_constraint_expr_set_op(handle, tmp, SEPOL_CEXPR_OP_INCOMP))
				goto err;
			break;
		}
	}

	/* Expr names */
	if (expr_datum->expr_type == CEXPR_NAMES) {
		const ebitmap_t *names = &expr_datum->names;
		char **val_to_name;
		if (expr_datum->attr & CEXPR_USER) {
			val_to_name = p->p_user_val_to_name;
		} else if (expr_datum->attr & CEXPR_ROLE) {
			val_to_name = p->p_role_val_to_name;
		} else if (expr_datum->attr & CEXPR_TYPE) {
			names = &expr_datum->type_names->types;
			val_to_name = p->p_type_val_to_name;
		}
		ebitmap_node_t *n;
		uint32_t bit;
		ebitmap_for_each_positive_bit(names, n, bit) {
			if (sepol_constraint_expr_add_name(handle, tmp,
							   val_to_name[bit]))
				goto err;
		}
	}

	
	*expr = tmp;
	return STATUS_SUCCESS;
err:
	sepol_constraint_expr_free(tmp);
	return STATUS_ERR;
}

struct add_perm_helper_args {
	sepol_handle_t *handle;
	const constraint_node_t *datum;
	sepol_constraint_t *constraint;
};

static int add_perm_helper(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	perm_datum_t *perm = datum;
	struct add_perm_helper_args *args = data;

	if (args->datum->permissions & (1 << (perm->s.value - 1)))
		return sepol_constraint_add_perm(args->handle, args->constraint,
						 key);
	return 0;
}

static int constraint_datum_to_record(sepol_handle_t *handle,
				      const policydb_t *p,
				      const class_datum_t *class_datum,
				      const constraint_node_t *constraint_datum,
				      sepol_constraint_t **constraint)
{
	sepol_constraint_t *tmp;
	sepol_constraint_expr_t *expr = NULL;
	if (sepol_constraint_create(handle, &tmp))
		return STATUS_ERR;
	
	struct add_perm_helper_args args = {
		.handle = handle,
		.datum = constraint_datum,
		.constraint = tmp,
	};
	if (hashtab_map(class_datum->permissions.table, add_perm_helper, &args))
		goto err;
	if (hashtab_map(class_datum->comdatum->permissions.table,
			add_perm_helper, &args))
		goto err;

	constraint_expr_t *expr_datum = constraint_datum->expr;
	uint32_t index = 0;
	while (expr_datum) {
		if (constraint_expr_datum_to_record(handle, p, expr_datum, &expr))
			goto err;
		if (sepol_constraint_insert_expr(handle, tmp, index, expr))
			goto err;
		expr = NULL;
		expr_datum = expr_datum->next;
	}

	*constraint = tmp;
	return STATUS_SUCCESS;
err:
	sepol_constraint_free(tmp);
	sepol_constraint_expr_free(expr);
	return STATUS_ERR;
}

static int class_datum_to_record(sepol_handle_t *handle, const policydb_t *p,
				 const class_datum_t *class_datum,
				 sepol_class_t **class)
{
	sepol_class_t *new_class = NULL;
	sepol_constraint_t *constraint = NULL;

	if (sepol_class_create(handle, &new_class))
		goto err;

	/* Copy name */
	const char *name = p->p_class_val_to_name[class_datum->s.value - 1];
	if (sepol_class_set_name(handle, new_class, name))
		goto err;

	/* Copy common */
	if (sepol_class_set_common(handle, new_class, class_datum->comkey))
		goto err;

	/* Copy perms */
	struct class_add_perm_args args = {
		.handle = handle,
		.class = new_class,
	};
	if (hashtab_map(class_datum->permissions.table, class_add_perm, &args))
		goto err;


	for (constraint_node_t *constraint_datum = class_datum->constraints;
	     constraint_datum != NULL;
	     constraint_datum = constraint_datum->next) {
		if (constraint_datum_to_record(handle, p, class_datum,
					       constraint_datum, &constraint))
			goto err;
		if (sepol_class_add_constraint(handle, new_class, constraint))
			goto err;
		constraint = NULL;
	}
	for (constraint_node_t *validatetrans_datum = class_datum->validatetrans;
	     validatetrans_datum != NULL;
	     validatetrans_datum = validatetrans_datum->next) {
		if (constraint_datum_to_record(handle, p, class_datum,
					       validatetrans_datum, &constraint))
			goto err;
		if (sepol_class_add_validatetrans(handle, new_class, constraint))
			goto err;
		constraint = NULL;
	}
	
	/* Copy default */
        if (sepol_class_set_default_user(handle, new_class,
					 map_default(class_datum->default_user)))
                goto err;
        if (sepol_class_set_default_role(handle, new_class,
					 map_default(class_datum->default_role)))
                goto err;
        if (sepol_class_set_default_type(handle, new_class,
					 map_default(class_datum->default_type)))
                goto err;
	char default_range = 0;
	switch (class_datum->default_range) {
	case DEFAULT_SOURCE_LOW:
		default_range = SEPOL_CLASS_DEFAULT_SOURCE_LOW;
		break;
	case DEFAULT_SOURCE_HIGH:
		default_range = SEPOL_CLASS_DEFAULT_SOURCE_HIGH;
		break;
	case DEFAULT_SOURCE_LOW_HIGH:
		default_range = SEPOL_CLASS_DEFAULT_SOURCE_LOW_HIGH;
		break;
	case DEFAULT_TARGET_LOW:
		default_range = SEPOL_CLASS_DEFAULT_TARGET_LOW;
		break;
	case DEFAULT_TARGET_HIGH:
		default_range = SEPOL_CLASS_DEFAULT_TARGET_HIGH;
		break;
	case DEFAULT_TARGET_LOW_HIGH:
		default_range = SEPOL_CLASS_DEFAULT_TARGET_LOW_HIGH;
		break;
	case DEFAULT_GLBLUB:
		default_range = SEPOL_CLASS_DEFAULT_GLBLUB;
		break;
	}
	if (sepol_class_set_default_range(handle, new_class, default_range))
		goto err;

	*class = new_class;
	return STATUS_SUCCESS;

err:
	if (new_class)
		sepol_class_free(new_class);
	sepol_constraint_free(constraint);

	return STATUS_ERR;
}

/* Return the number of classes */
int sepol_class_count(sepol_handle_t *handle __attribute__ ((unused)),
		     const sepol_policydb_t *p, unsigned int *response)
{
	*response = p->p.p_classes.table->nel;
	return STATUS_SUCCESS;
}

/* Check if the specified class exists */
int sepol_class_exists(sepol_handle_t *handle __attribute__ ((unused)),
		       const sepol_policydb_t *policydb,
		       const sepol_class_key_t *key, int *response)
{
	const char *name;
	sepol_class_key_unpack(key, &name);

	*response = hashtab_search(policydb->p.p_classes.table, name) != NULL;

	return STATUS_SUCCESS;
}

/* Query a class - returns the class or NULL if not found */
int sepol_class_query(sepol_handle_t *handle, const sepol_policydb_t *p,
		      const sepol_class_key_t *key, sepol_class_t **response)
{
	const char *name;
	sepol_class_key_unpack(key, &name);

	class_datum_t *class_datum = hashtab_search(p->p.p_classes.table, name);
	if (!class_datum) {
		*response = NULL;
		return STATUS_SUCCESS;
	}

	return class_datum_to_record(handle, &p->p, class_datum, response);
}

/* Iterators */
int sepol_class_iter_create(sepol_handle_t *handle, const sepol_policydb_t *p,
			    sepol_class_iter_t **iter)
{
	sepol_class_iter_t *new = malloc(sizeof(sepol_class_iter_t));
	if (!new) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	new->p = p;
	hashtab_iter_init(p->p.p_classes.table, &new->hashtab_iter);

	*iter = new;

	return STATUS_SUCCESS;
}

void sepol_class_iter_destroy(sepol_class_iter_t *iter)
{
	free(iter);
}

int sepol_class_iter_next(sepol_handle_t *handle, sepol_class_iter_t *iter,
			  sepol_class_t **item)
{
	char *key;
	class_datum_t *datum;

	hashtab_iter_next(&iter->hashtab_iter, &key, (hashtab_datum_t *)&datum);
	if (!key) {
		*item = NULL;
		return STATUS_SUCCESS;
	}

	return class_datum_to_record(handle, &iter->p->p, datum, item);
}
