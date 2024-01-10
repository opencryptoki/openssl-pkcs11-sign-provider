#ifndef _FORK_H
#define _FORK_H

int atforkpool_register_pkcs11(struct pkcs11_module *pkcs, struct dbg *dbg);
int atforkpool_unregister_pkcs11(struct pkcs11_module *pkcs, struct dbg *dbg);

int atforkpool_register_objecthandle(CK_OBJECT_HANDLE_PTR poh, struct dbg *dbg);
int atforkpool_unregister_objecthandle(CK_OBJECT_HANDLE_PTR poh, struct dbg *dbg);

int atforkpool_register_sessionhandle(CK_SESSION_HANDLE_PTR psh, struct dbg *dbg);
int atforkpool_unregister_sessionhandle(CK_SESSION_HANDLE_PTR psh, struct dbg *dbg);

#endif /* _FORK_H */
