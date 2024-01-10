#include <unistd.h>
#include <stdbool.h>
#include <string.h>

#include "pkcs11.h"
#include "common.h"
#include "debug.h"
#include "fork.h"

static struct {
	pthread_mutex_t mutex;
	bool registered;

	struct pkcs11_module **pkcss;
	unsigned int pkcs_num;
	unsigned int pkcs_size;

	CK_OBJECT_HANDLE_PTR *ohs;
	unsigned int oh_num;
	unsigned int oh_size;

	CK_SESSION_HANDLE_PTR *shs;
	unsigned int sh_num;
	unsigned int sh_size;
} atfork_pool = {
	.mutex = PTHREAD_MUTEX_INITIALIZER,
	.registered = false,
};

static void fork_prepare(void)
{
	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		fprintf(stderr, "pid %d: unable to lock atfork pool\n",
			getpid());
		return;
	}

	/* ----- locked ----- */
}

static void fork_parent(void)
{
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		fprintf(stderr, "pid %d: unable to unlock pool (parent)\n",
			getpid());
		return;
	}

	/* ----- unlocked ----- */
}

static void fork_child(void)
{
	struct pkcs11_module *pkcs;
	unsigned int i;

	for(i = 0; i < atfork_pool.oh_size; i++) {
		if (atfork_pool.ohs[i])
			*atfork_pool.ohs[i] = CK_INVALID_HANDLE;
	}

	for(i = 0; i < atfork_pool.sh_size; i++) {
		if (atfork_pool.shs[i])
			*atfork_pool.shs[i] = CK_INVALID_HANDLE;
	}

	for(i = 0; i < atfork_pool.pkcs_size; i++) {
		pkcs = atfork_pool.pkcss[i];
		if (pkcs)
			pkcs->state = PKCS11_UNINITIALIZED;
	}

	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		fprintf(stderr, "pid %d: unable to unlock pool (child)\n",
			getpid());
		return;
	}

	/* ----- unlocked ----- */
	return;
}

static int _pthread_atfork_once(void) {
	if (atfork_pool.registered)
		return OSSL_RV_OK;

	if (pthread_atfork(fork_prepare, fork_parent, fork_child))
		return OSSL_RV_ERR;
	atfork_pool.registered = true;

	return OSSL_RV_OK;
}

static int _gen_alloc(void **pool, unsigned int *num, unsigned int *size,
		      size_t elem_size, int elem_num)
{
	size_t bytes = elem_size * elem_num;
	void *tmp;

	/* initial allocation */
	if (!(*num)) {
		tmp = OPENSSL_zalloc(bytes);
		if (!tmp)
			return OSSL_RV_ERR;

		*pool = tmp;
		*size += elem_num;
	}

	/* grow (if required) */
	if (*num && (*num % elem_num == 0)) {
		tmp = OPENSSL_realloc(*pool, *num + (bytes));
		if (!tmp)
			return OSSL_RV_ERR;

		memset(tmp + (elem_size * *num), 0, bytes);
		*pool = tmp;
		*size += elem_num;
	}

	return OSSL_RV_OK;
}

static void _gen_free(void **pool, unsigned int *num, unsigned int *size)
{
	if (*num)
		return;

	OPENSSL_free(*pool);
	*pool = NULL;
	*size = 0;
}

#define AFP_PKCS_POOL	8
int atforkpool_register_pkcs11(struct pkcs11_module *pkcs, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!pkcs)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "pkcs: %p, lock atfork pool failed", pkcs);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	if (_gen_alloc((void **)&atfork_pool.pkcss, &atfork_pool.pkcs_num, &atfork_pool.pkcs_size,
		       sizeof(struct pkcs11 *), AFP_PKCS_POOL) != OSSL_RV_OK) {
		ps_dbg_error(dbg, "pkcs: %p, pkcs pool allocation failed", pkcs);
		goto unlock_out;
	}

	for (i = 0; i < atfork_pool.pkcs_size; i++) {
		if (atfork_pool.pkcss[i] == NULL) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "pkcs: %p, unable to register", pkcs);
		goto unlock_out;
	}

	atfork_pool.pkcss[i] = pkcs;
	atfork_pool.pkcs_num++;

	if (_pthread_atfork_once() != OSSL_RV_OK) {
		ps_dbg_warn(dbg, "unable to register fork handler");
		goto unlock_out;
	}

	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "pkcs: %p, unlock atfork pool failed", pkcs);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "pkcs: %p, registered in atfork pool", pkcs);
	return rc;
}

int atforkpool_unregister_pkcs11(struct pkcs11_module *pkcs, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!pkcs)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "pkcs: %p, lock atfork pool failed", pkcs);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	for (i = 0; i < atfork_pool.pkcs_size; i++) {
		if (atfork_pool.pkcss[i] == pkcs) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "pkcs: %p, unable to unregister", pkcs);
		goto unlock_out;
	}

	atfork_pool.pkcss[i] = NULL;
	atfork_pool.pkcs_num--;

	_gen_free((void **)&atfork_pool.pkcss, &atfork_pool.pkcs_num,
		  &atfork_pool.pkcs_size);
	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "pkcs: %p, unlock atfork pool failed", pkcs);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "pkcs: %p, unregistered in atfork pool", pkcs);
	return rc;
}

#define AFP_OH_POOL	16
int atforkpool_register_objecthandle(CK_OBJECT_HANDLE_PTR poh, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!poh)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "poh: %p, lock atfork pool failed", poh);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	if (_gen_alloc((void **)&atfork_pool.ohs,
		       &atfork_pool.oh_num, &atfork_pool.oh_size,
		       sizeof(CK_OBJECT_HANDLE_PTR), AFP_OH_POOL) != OSSL_RV_OK) {
		ps_dbg_error(dbg, "poh: %p, poh pool allocation failed", poh);
		goto unlock_out;
	}

	for (i = 0; i < atfork_pool.oh_size; i++) {
		if (atfork_pool.ohs[i] == NULL) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "poh: %p, unable to register", poh);
		goto unlock_out;
	}

	atfork_pool.ohs[i] = poh;
	atfork_pool.oh_num++;

	if (_pthread_atfork_once() != OSSL_RV_OK) {
		ps_dbg_warn(dbg, "unable to register fork handler");
		goto unlock_out;
	}

	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "poh: %p, unlock atfork pool failed", poh);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "poh: %p, registered in atfork pool", poh);
	return rc;
}

int atforkpool_unregister_objecthandle(CK_OBJECT_HANDLE_PTR poh, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!poh)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "poh: %p, lock atfork pool failed", poh);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	for (i = 0; i < atfork_pool.oh_size; i++) {
		if (atfork_pool.ohs[i] == poh) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "poh: %p, unable to unregister", poh);
		goto unlock_out;
	}

	atfork_pool.ohs[i] = NULL;
	atfork_pool.oh_num--;

	_gen_free((void **)&atfork_pool.ohs, &atfork_pool.oh_num,
		  &atfork_pool.oh_size);
	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "poh: %p, unlock atfork pool failed", poh);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "poh: %p, unregistered in atfork pool", poh);
	return rc;
}

#define AFP_SH_POOL	16
int atforkpool_register_sessionhandle(CK_SESSION_HANDLE_PTR psh, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!psh)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "psh: %p, lock atfork pool failed", psh);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	if (_gen_alloc((void **)&atfork_pool.shs, &atfork_pool.sh_num, &atfork_pool.sh_size,
		       sizeof(CK_SESSION_HANDLE_PTR), AFP_SH_POOL) != OSSL_RV_OK) {
		ps_dbg_error(dbg, "psh: %p, sh pool allocation failed", psh);
		goto unlock_out;
	}

	for (i = 0; i < atfork_pool.sh_size; i++) {
		if (atfork_pool.shs[i] == NULL) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "psh: %p, unable to register", psh);
		goto unlock_out;
	}

	atfork_pool.shs[i] = psh;
	atfork_pool.sh_num++;

	if (_pthread_atfork_once() != OSSL_RV_OK) {
		ps_dbg_warn(dbg, "unable to register fork handler");
		goto unlock_out;
	}

	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "psh: %p, unlock atfork pool failed", psh);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "psh: %p, registered in atfork pool", psh);
	return rc;
}

int atforkpool_unregister_sessionhandle(CK_SESSION_HANDLE_PTR psh, struct dbg *dbg)
{
	int rc = OSSL_RV_ERR;
	bool found = false;
	unsigned int i;

	if (!psh)
		return OSSL_RV_OK;
	if (!dbg)
		return OSSL_RV_ERR;

	if (pthread_mutex_lock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "psh: %p, lock atfork pool failed", psh);
		return OSSL_RV_ERR;
	}

	/* ----- locked ----- */
	for (i = 0; i < atfork_pool.sh_size; i++) {
		if (atfork_pool.shs[i] == psh) {
			found = true;
			break;
		}
	}

	if (!found) {
		ps_dbg_error(dbg, "psh: %p, unable to unregister", psh);
		goto unlock_out;
	}

	atfork_pool.shs[i] = NULL;
	atfork_pool.sh_num--;

	_gen_free((void **)&atfork_pool.shs, &atfork_pool.sh_num,
		  &atfork_pool.sh_size);
	rc = OSSL_RV_OK;
unlock_out:
	if (pthread_mutex_unlock(&atfork_pool.mutex)) {
		ps_dbg_error(dbg, "psh: %p, unlock atfork pool failed", psh);
		return OSSL_RV_ERR;
	}
	/* ----- unlocked ----- */
	ps_dbg_debug(dbg, "psh: %p, unregistered in atfork pool", psh);
	return rc;
}
