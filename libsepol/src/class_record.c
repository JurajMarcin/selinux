#include <sepol/class_record.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "sepol/policydb/util.h"
#include "debug.h"

struct sepol_class {
	char *name;
	char *common;
	char **perms;
	uint32_t num_perms;
	sepol_constraint_t **constraints;
	uint32_t num_constraints;
	sepol_constraint_t **validatetrans;
	uint32_t num_validatetrans;
	char default_user;
	char default_role;
	char default_type;
	char default_range;
};

struct sepol_class_key {
	char *name;
};

struct sepol_constraint {
	char **perms;
	uint32_t num_perms;
	sepol_constraint_expr_t **exprs;
	uint32_t num_exprs;
};

struct sepol_constraint_expr {
	uint32_t expr_type;
	uint32_t attr;
	uint32_t op;
	char **names;
	uint32_t num_names;
};

static int sepol_constraint_expr_equals(sepol_handle_t *handle,
					const sepol_constraint_expr_t *expr1,
					const sepol_constraint_expr_t *expr2,
					int *result);
static int sepol_constraint_equals(sepol_handle_t *handle,
				   const sepol_constraint_t *constraint1,
				   const sepol_constraint_t *constraint2,
				   int *result);


/* Key */
int sepol_class_key_create(sepol_handle_t *handle, const char *name,
			   sepol_class_key_t **key)
{
	sepol_class_key_t *tmp_key = malloc(sizeof(sepol_class_key_t));
	if (!tmp_key)
		goto omem;
	tmp_key->name = strdup(name);
	if (!tmp_key->name)
		goto omem;
	
	*key = tmp_key;
	return STATUS_SUCCESS;

omem:
	ERR(handle, "out of memory");
	free(tmp_key);
	return STATUS_ERR;
}

void sepol_class_key_unpack(const sepol_class_key_t *key, const char **name)
{
	*name = key->name;
}

int sepol_class_key_extract(sepol_handle_t *handle, const sepol_class_t *class,
			    sepol_class_key_t **key)
{
	return sepol_class_key_create(handle, class->name, key);
}

void sepol_class_key_free(sepol_class_key_t *key)
{
	free(key->name);
	free(key);
}

int sepol_class_compare(const sepol_class_t *class, const sepol_class_key_t *key)
{
	return strcmp(class->name, key->name);
}

int sepol_class_compare2(const sepol_class_t *class, const sepol_class_t *class2)
{
	return strcmp(class->name, class2->name);
}

/* Class name */
const char *sepol_class_get_name(const sepol_class_t *class)
{
	return class->name;
}

int sepol_class_set_name(sepol_handle_t *handle, sepol_class_t *class,
			const char *name)
{
	char *tmp_name = strdup(name);
	if (!tmp_name) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	free(class->name);
	class->name = tmp_name;
	return STATUS_SUCCESS;
}

/* Common name */
const char *sepol_class_get_common(const sepol_class_t *class)
{
	return class->common;
}

int sepol_class_set_common(sepol_handle_t *handle, sepol_class_t *class,
			   const char *common)
{
	if (common) {
		char *tmp_common = strdup(common);
		if (!tmp_common) {
			ERR(handle, "out of memory");
			return STATUS_ERR;
		}
		free(class->common);
		class->common = tmp_common;
	} else {
		free(class->common);
		class->common = NULL;
	}
	return STATUS_SUCCESS;
}

/* Class-specific permissions */
int sepol_class_has_perm(const sepol_class_t *class, const char *perm)
{
	return string_list_contains(class->perms, class->num_perms, perm);
}

int sepol_class_get_perms(sepol_handle_t *handle, const sepol_class_t *class,
			  const char ***perms, uint32_t *num_perms)
{
	return string_list_scopy(handle, class->perms, class->num_perms, perms,
				 num_perms);
}

int sepol_class_add_perm(sepol_handle_t *handle, sepol_class_t *class,
			 const char *perm)
{
	return string_list_add(handle, &class->perms, &class->num_perms, perm);
}

int sepol_class_del_perm(sepol_handle_t *handle __attribute__((unused)),
			 sepol_class_t *class,
			 const char *perm)
{
	return string_list_del(class->perms, &class->num_perms, perm);
}

/* Constraints */
int sepol_class_get_constraints(sepol_handle_t *handle,
				const sepol_class_t *class,
				const sepol_constraint_t ***constraints,
				uint32_t *num_constraints)
{
	const sepol_constraint_t **tmp = calloc(class->num_constraints,
					 	sizeof(const sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < class->num_constraints; i++)
		tmp[i] = class->constraints[i];
	
	*constraints = tmp;
	*num_constraints = class->num_constraints;

	return STATUS_SUCCESS;
}

int sepol_class_add_constraint(sepol_handle_t *handle, sepol_class_t *class,
			       sepol_constraint_t *constraint)
{
	sepol_constraint_t **tmp = reallocarray(class->constraints,
						class->num_constraints + 1,
						sizeof(sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	class->constraints = tmp;
	class->constraints[class->num_constraints] = constraint;
	class->num_constraints++;

	return STATUS_SUCCESS;
}

int sepol_class_del_constraint(sepol_handle_t *handle, sepol_class_t *class,
			       const sepol_constraint_t *constraint)
{
	for (uint32_t i = class->num_constraints; i > 0; i--) {
		int result;
		if (sepol_constraint_equals(handle, constraint,
					    class->constraints[i - 1], &result))
			return STATUS_ERR;
		if (result) {
			sepol_constraint_free(class->constraints[i - 1]);
			class->num_constraints--;
			if (i - 1 < class->num_constraints)
				class->constraints[i - 1] =
					class->constraints[class->num_constraints];
		}
	}
	return STATUS_SUCCESS;
}

/* Validate transitions */
int sepol_class_get_validatetrans(sepol_handle_t *handle,
				  const sepol_class_t *class,
				  const sepol_constraint_t ***validatetrans,
				  uint32_t *num_validatetrans)
{
	const sepol_constraint_t **tmp = calloc(class->num_validatetrans,
					 	sizeof(const sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < class->num_validatetrans; i++)
		tmp[i] = class->validatetrans[i];
	
	*validatetrans = tmp;
	*num_validatetrans = class->num_validatetrans;

	return STATUS_SUCCESS;
}

int sepol_class_add_validatetrans(sepol_handle_t *handle, sepol_class_t *class,
				  sepol_constraint_t *validatetrans)
{
	sepol_constraint_t **tmp = reallocarray(class->validatetrans,
						class->num_validatetrans + 1,
						sizeof(sepol_constraint_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	class->validatetrans = tmp;
	class->validatetrans[class->num_validatetrans] = validatetrans;
	class->num_validatetrans++;

	return STATUS_SUCCESS;
}
int sepol_class_del_validatetrans(sepol_handle_t *handle, sepol_class_t *class,
				  const sepol_constraint_t *validatetrans)
{
	for (uint32_t i = class->num_validatetrans; i > 0; i--) {
		int result;
		if (sepol_constraint_equals(handle, validatetrans,
					    class->validatetrans[i - 1], &result))
			return STATUS_ERR;
		if (result) {
			sepol_constraint_free(class->validatetrans[i - 1]);
			class->num_validatetrans--;
			if (i - 1 < class->num_validatetrans)
				class->validatetrans[i - 1] =
					class->validatetrans[class->num_validatetrans];
		}
	}
	return STATUS_SUCCESS;
}

/* Defaults */
char sepol_class_get_default_user(const sepol_class_t *class)
{
	return class->default_user;
}

int sepol_class_set_default_user(sepol_handle_t *handle __attribute__ ((unused)),
				 sepol_class_t *class, char default_user)
{
	class->default_user = default_user;
	return STATUS_SUCCESS;
}

char sepol_class_get_default_role(const sepol_class_t *class)
{
	return class->default_role;
}

int sepol_class_set_default_role(sepol_handle_t *handle __attribute__ ((unused)),
				 sepol_class_t *class, char default_role)
{
	class->default_role = default_role;
	return STATUS_SUCCESS;
}

char sepol_class_get_default_type(const sepol_class_t *class)
{
	return class->default_type;
}

int sepol_class_set_default_type(sepol_handle_t *handle __attribute__ ((unused)),
				 sepol_class_t *class, char default_type)
{
	class->default_type = default_type;
	return STATUS_SUCCESS;
}

char sepol_class_get_default_range(const sepol_class_t *class)
{
	return class->default_range;
}

int sepol_class_set_default_range(sepol_handle_t *handle __attribute__ ((unused)),
				 sepol_class_t *class, char default_range)
{
	class->default_range = default_range;
	return STATUS_SUCCESS;
}

/* Create/Clone/Destroy */
int sepol_class_create(sepol_handle_t *handle, sepol_class_t **class_ptr)
{
	sepol_class_t *tmp = malloc(sizeof(sepol_class_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_class_t));
	*class_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_class_clone(sepol_handle_t *handle, const sepol_class_t *class,
		      sepol_class_t **class_ptr)
{
	sepol_class_t *tmp = NULL;
	if (sepol_class_create(handle, &tmp))
		goto err;

	if (sepol_class_set_name(handle, tmp, class->name))
		goto err;
	if (sepol_class_set_common(handle, tmp, class->common))
		goto err;
	for (size_t i = 0; i < class->num_perms; i++) {
		if (sepol_class_add_perm(handle, tmp, class->perms[i]))
			goto err;
	}
	for (size_t i = 0; i < class->num_constraints; i++) {
		if (sepol_class_add_constraint(handle, tmp, class->constraints[i]))
			goto err;
	}
	for (size_t i = 0; i < class->num_validatetrans; i++) {
		if (sepol_class_add_validatetrans(handle, tmp, class->validatetrans[i]))
			goto err;
	}
	if (sepol_class_set_default_user(handle, tmp, class->default_user))
		goto err;
	if (sepol_class_set_default_role(handle, tmp, class->default_role))
		goto err;
	if (sepol_class_set_default_type(handle, tmp, class->default_type))
		goto err;
	if (sepol_class_set_default_range(handle, tmp, class->default_range))
		goto err;

	*class_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_class_free(tmp);
	return STATUS_ERR;
}

void sepol_class_free(sepol_class_t *class)
{
	if (!class)
		return;

	free(class->name);
	free(class->common);
	for (size_t i = 0; i < class->num_perms; i++)
		free(class->perms[i]);
	for (size_t i = 0; i < class->num_constraints; i++)
		sepol_constraint_free(class->constraints[i]);
	free(class->constraints);
	for (size_t i = 0; i < class->num_validatetrans; i++)
		sepol_constraint_free(class->validatetrans[i]);
	free(class->validatetrans);
	free(class);
}

/* Constraints */

static int sepol_constraint_equals(sepol_handle_t *handle,
				   const sepol_constraint_t *constraint1,
				   const sepol_constraint_t *constraint2,
				   int *result)
{
	*result = 0;

	if (constraint1->num_exprs != constraint2->num_exprs)
		return 0;

	for (uint32_t i = 0; i < constraint1->num_exprs; i++) {
		if (sepol_constraint_expr_equals(handle, constraint1->exprs[i],
						 constraint2->exprs[i], result))
			return STATUS_ERR;
		if (!result)
			return STATUS_SUCCESS;
	}
	return STATUS_SUCCESS;
}

static int sepol_constraint_expr_equals(sepol_handle_t *handle,
					const sepol_constraint_expr_t *expr1,
					const sepol_constraint_expr_t *expr2,
					int *result)
{
	uint32_t num_names1;
	const char **names1 = NULL;
	uint32_t num_names2;
	const char **names2 = NULL;
	*result = 0;
	int status = STATUS_ERR;

	if (expr1->expr_type != expr2->expr_type)
		goto exit;

	if (expr1->expr_type != expr2->expr_type)
		goto exit;

	if (expr1->expr_type == SEPOL_CEXPR_TYPE_ATTR ||
	    expr1->expr_type == SEPOL_CEXPR_TYPE_NAMES) {
		if (expr1->op != expr2->op)
			goto exit;
		if (sepol_constraint_expr_get_names(handle, expr1, &names1,
						    &num_names1))
			goto err;
		if (sepol_constraint_expr_get_names(handle, expr2, &names2,
						    &num_names2)) {
			goto err;
		}
		if (num_names1 != num_names2)
			goto exit;
		qsort(names1, num_names1, sizeof(const char *), strcmp_qsort);
		qsort(names2, num_names2, sizeof(const char *), strcmp_qsort);
		for (uint32_t i = 0; i < num_names1; i++) {
			if (strcmp(names1[i], names2[i]))
				goto exit;
		}
	}

	*result = 1;
exit:
	status = STATUS_SUCCESS;
err:
	free(names1);
	free(names2);
	return status;
}

/* Constraints */
int sepol_constraint_create(sepol_handle_t *handle,
			    sepol_constraint_t **constraint_ptr)
{
	sepol_constraint_t *tmp = malloc(sizeof(sepol_constraint_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_constraint_t));
	*constraint_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_constraint_clone(sepol_handle_t *handle,
			   const sepol_constraint_t *constraint,
			   sepol_constraint_t **constraint_ptr)
{
	sepol_constraint_t *tmp;
	if (sepol_constraint_create(handle, &tmp))
		return STATUS_ERR;

	for (size_t i = 0; i < constraint->num_perms; i++) {
		if (sepol_constraint_add_perm(handle, tmp, constraint->perms[i]))
			goto err;
	}

	for (size_t i = 0; i < constraint->num_exprs; i++) {
		if (sepol_constraint_insert_expr(handle, tmp, i, constraint->exprs[i]))
			goto err;
	}
	*constraint_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_constraint_free(tmp);
	return STATUS_ERR;
}

int sepol_constraint_free(sepol_constraint_t *constraint)
{
	for (size_t i = 0; i < constraint->num_perms; i++)
		free(constraint->perms[i]);
	free(constraint->perms);
	for (size_t i = 0; i < constraint->num_exprs; i++)
		sepol_constraint_expr_free(constraint->exprs[i]);
	free(constraint->exprs);

	return STATUS_SUCCESS;
}

/* Constrained permissions */
int sepol_constraint_has_perm(sepol_constraint_t *constraint, const char *perm)
{
	return string_list_contains(constraint->perms, constraint->num_perms,
				    perm);
}

int sepol_constraint_get_perms(sepol_handle_t *handle,
			       const sepol_constraint_t *constraint,
			       const char ***perms, uint32_t *num_perms)
{
	return string_list_scopy(handle, constraint->perms,
				 constraint->num_perms, perms, num_perms);
}

int sepol_constraint_add_perm(sepol_handle_t *handle,
			      sepol_constraint_t *constraint, const char *perm)
{
	return string_list_add(handle, &constraint->perms,
			       &constraint->num_perms, perm);
}

int sepol_constraint_del_perm(sepol_handle_t *handle __attribute__((unused)),
			      sepol_constraint_t *constraint, const char *perm)
{
	return string_list_del(constraint->perms, &constraint->num_perms, perm);
}

/* Constraint sub expresessions */
int sepol_constraint_get_exprs(sepol_handle_t *handle,
			       const sepol_constraint_t *constraint,
			       const sepol_constraint_expr_t ***exprs,
			       uint32_t *num_exprs)
{
	const sepol_constraint_expr_t **tmp = calloc(constraint->num_exprs,
						     sizeof(const sepol_constraint_expr_t *));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}

	for (uint32_t i = 0; i < constraint->num_exprs; i++)
		tmp[i] = constraint->exprs[i];
	
	*exprs = tmp;
	*num_exprs = constraint->num_exprs;

	return STATUS_SUCCESS;
}

int sepol_constraint_insert_expr(sepol_handle_t *handle,
				 sepol_constraint_t *constraint, uint32_t index,
				 sepol_constraint_expr_t *expr)
{
	sepol_constraint_expr_t **tmp_array = reallocarray(constraint->exprs,
							   constraint->num_exprs + 1,
							   sizeof(sepol_constraint_expr_t *));
	if (!tmp_array) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	constraint->exprs = tmp_array;
	constraint->exprs[constraint->num_exprs] = NULL;

	constraint->num_exprs++;
	for (uint32_t i = 0; i < constraint->num_exprs; i++) {
		if (i >= index) {
			sepol_constraint_expr_t *tmp = constraint->exprs[i];
			constraint->exprs[i] = expr;
			expr = tmp;
		}
	}
	return STATUS_SUCCESS;
}

int sepol_constraint_remove_expr(sepol_handle_t *handle __attribute__((unused)),
				 sepol_constraint_t *constraint,
				 uint32_t index)
{
	sepol_constraint_expr_t *expr_to_push_front = NULL;
	for (uint32_t i = constraint->num_exprs - 1; i > index; i++) {
		sepol_constraint_expr_t *tmp = constraint->exprs[i];
		constraint->exprs[i] = expr_to_push_front;
		expr_to_push_front = tmp;
	}
	return STATUS_SUCCESS;
}

/* Constraint expresessions */
int sepol_constraint_expr_create(sepol_handle_t *handle,
				 sepol_constraint_expr_t **expr_ptr)
{
	sepol_constraint_expr_t *tmp = malloc(sizeof(sepol_constraint_expr_t));
	if (!tmp) {
		ERR(handle, "out of memory");
		return STATUS_ERR;
	}
	memset(tmp, 0, sizeof(sepol_constraint_expr_t));
	*expr_ptr = tmp;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_clone(sepol_handle_t *handle,
				const sepol_constraint_expr_t *expr,
				sepol_constraint_expr_t **expr_ptr)
{
	sepol_constraint_expr_t *tmp;
	if (sepol_constraint_expr_create(handle, &tmp))
		return STATUS_ERR;

	tmp->expr_type = expr->expr_type;
	tmp->attr = expr->attr;
	tmp->op = expr->op;
	for (uint32_t i = 0; i < expr->num_names; i++) {
		if (sepol_constraint_expr_add_name(handle, tmp, expr->names[i]))
			goto err;
	}
	*expr_ptr = tmp;
	return STATUS_SUCCESS;

err:
	sepol_constraint_expr_free(tmp);
	return STATUS_ERR;
}

int sepol_constraint_expr_free(sepol_constraint_expr_t *expr)
{
	for (uint32_t i = 0; i < expr->num_names; i++) {
		free(expr->names[i]);
	}
	free(expr);
	return STATUS_SUCCESS;
}

/* Constraint expr type */
uint32_t sepol_constraint_expr_get_type(sepol_constraint_expr_t *expr)
{
	return expr->expr_type;
}

int sepol_constraint_expr_set_type(sepol_handle_t *handle __attribute__((unused)),
				   sepol_constraint_expr_t *expr,
				   uint32_t type)
{
	expr->expr_type = type;
	return STATUS_SUCCESS;
}

/* Constraint expr attr */
int sepol_constraint_expr_has_attr(sepol_constraint_expr_t *expr, uint32_t attr)
{
	return expr->attr & attr;
}

int sepol_constraint_expr_set_attr(sepol_handle_t *handle __attribute__((unused)),
				   sepol_constraint_expr_t *expr,
				   uint32_t attr)
{
	expr->attr |= attr;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_unset_attr(sepol_handle_t *handle __attribute__((unused)),
				     sepol_constraint_expr_t *expr,
				     uint32_t attr)
{
	expr->attr &= ~attr;
	return STATUS_SUCCESS;
}

int sepol_constraint_expr_clear_attr(sepol_handle_t *handle __attribute__((unused)),
				     sepol_constraint_expr_t *expr)
{
	expr->attr = 0;
	return STATUS_SUCCESS;
}

/* Constraint expr attr or names operator */
uint32_t sepol_constraint_expr_get_op(sepol_constraint_expr_t *expr)
{
	return expr->op;
}

int sepol_constraint_expr_set_op(sepol_handle_t *handle __attribute__((unused)),
				 sepol_constraint_expr_t *expr, uint32_t op)
{
	expr->op = op;
	return STATUS_SUCCESS;
}

/* Constraint names */
int sepol_constraint_expr_has_name(sepol_constraint_expr_t *expr,
				   const char *name)
{
	return string_list_contains(expr->names, expr->num_names, name);
}

int sepol_constraint_expr_get_names(sepol_handle_t *handle,
				    const sepol_constraint_expr_t *expr,
				    const char ***names, uint32_t *num_names)
{
	return string_list_scopy(handle, expr->names, expr->num_names, names,
				 num_names);
}

int sepol_constraint_expr_add_name(sepol_handle_t *handle,
				   sepol_constraint_expr_t *expr,
				   const char *name)
{
	return string_list_add(handle, &expr->names, &expr->num_names, name);
}

int sepol_constraint_expr_del_name(sepol_handle_t *handle __attribute__((unused)),
				   sepol_constraint_expr_t *expr,
				   const char *name)
{
	return string_list_del(expr->names, &expr->num_names, name);
}
