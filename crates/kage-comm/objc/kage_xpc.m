#import <Foundation/Foundation.h>

@protocol KageDaemonXPCProtocol
- (void)pingWithReply:(void (^)(NSString * _Nonnull))reply;
- (void)resolveIdentityWithOrg:(NSString * _Nonnull)org env:(NSString * _Nonnull)env withReply:(void (^)(NSString * _Nullable, NSError * _Nullable))reply;
- (void)wrapKeyWithKidBech32:(NSString * _Nonnull)kidBech32 fileKey:(NSData * _Nonnull)fileKey withReply:(void (^)(NSString * _Nullable, NSString * _Nullable, NSString * _Nullable, NSError * _Nullable))reply;
- (void)unwrapKeyWithKidBech32:(NSString * _Nonnull)kidBech32 nonceB64:(NSString * _Nonnull)nonceB64 payloadB64:(NSString * _Nonnull)payloadB64 withReply:(void (^)(NSData * _Nullable, NSError * _Nullable))reply;
- (void)unlockWithKidBech32:(NSString * _Nonnull)kidBech32 durationSeconds:(uint32_t)durationSeconds withReply:(void (^)(BOOL, NSError * _Nullable))reply;
@end

static void kage_write_cstr(char *out, size_t out_len, NSString *s) {
    if (!out || out_len == 0) return;
    if (!s) { out[0] = 0; return; }
    const char *utf8 = [s UTF8String];
    if (!utf8) { out[0] = 0; return; }
    size_t n = strnlen(utf8, out_len - 1);
    memcpy(out, utf8, n);
    out[n] = 0;
}

static int kage_return_error(NSError *err, char *err_out, size_t err_out_len) {
    if (!err) {
        kage_write_cstr(err_out, err_out_len, @"unknown error");
        return -32005;
    }
    kage_write_cstr(err_out, err_out_len, err.localizedDescription ?: @"unknown error");
    return (int)err.code;
}

static NSXPCConnection *kage_connect(void) {
    NSXPCConnection *c = [[NSXPCConnection alloc] initWithMachServiceName:@"com.kage.daemon" options:0];
    c.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(KageDaemonXPCProtocol)];
    [c resume];
    return c;
}

int kage_xpc_ping(char *out, size_t out_len, char *err_out, size_t err_out_len) {
    @autoreleasepool {
        __block int rc = -32005;
        __block NSString *result = nil;
        __block NSError *callErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSXPCConnection *c = kage_connect();
        id<KageDaemonXPCProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull err) {
            callErr = err;
            dispatch_semaphore_signal(sem);
        }];

        [proxy pingWithReply:^(NSString * _Nonnull s) {
            result = s;
            rc = 0;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [c invalidate];

        if (rc == 0) {
            kage_write_cstr(out, out_len, result ?: @"");
            return 0;
        }
        return kage_return_error(callErr, err_out, err_out_len);
    }
}

int kage_xpc_resolve_identity(const char *org, const char *env, char *out, size_t out_len, char *err_out, size_t err_out_len) {
    @autoreleasepool {
        __block int rc = -32005;
        __block NSString *result = nil;
        __block NSError *callErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSString *orgStr = org ? [NSString stringWithUTF8String:org] : nil;
        NSString *envStr = env ? [NSString stringWithUTF8String:env] : nil;
        if (!orgStr || !envStr) {
            kage_write_cstr(err_out, err_out_len, @"invalid utf8");
            return -32005;
        }

        NSXPCConnection *c = kage_connect();
        id<KageDaemonXPCProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull err) {
            callErr = err;
            dispatch_semaphore_signal(sem);
        }];

        [proxy resolveIdentityWithOrg:orgStr env:envStr withReply:^(NSString * _Nullable kidBech32, NSError * _Nullable err) {
            if (err) {
                callErr = err;
                dispatch_semaphore_signal(sem);
                return;
            }
            result = kidBech32;
            rc = 0;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [c invalidate];

        if (rc == 0) {
            kage_write_cstr(out, out_len, result ?: @"");
            return 0;
        }
        return kage_return_error(callErr, err_out, err_out_len);
    }
}

int kage_xpc_unlock(const char *kid_bech32, uint32_t duration_seconds, char *err_out, size_t err_out_len) {
    @autoreleasepool {
        __block int rc = -32005;
        __block NSError *callErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSString *kid = kid_bech32 ? [NSString stringWithUTF8String:kid_bech32] : nil;
        if (!kid) {
            kage_write_cstr(err_out, err_out_len, @"invalid utf8");
            return -32005;
        }

        NSXPCConnection *c = kage_connect();
        id<KageDaemonXPCProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull err) {
            callErr = err;
            dispatch_semaphore_signal(sem);
        }];

        [proxy unlockWithKidBech32:kid durationSeconds:duration_seconds withReply:^(BOOL ok, NSError * _Nullable err) {
            if (err) {
                callErr = err;
                dispatch_semaphore_signal(sem);
                return;
            }
            rc = ok ? 0 : -32005;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [c invalidate];

        if (rc == 0) return 0;
        return kage_return_error(callErr, err_out, err_out_len);
    }
}

int kage_xpc_wrap_key(
    const char *kid_bech32,
    const unsigned char *file_key,
    size_t file_key_len,
    char *nonce_b64_out,
    size_t nonce_b64_out_len,
    char *payload_b64_out,
    size_t payload_b64_out_len,
    char *err_out,
    size_t err_out_len
) {
    @autoreleasepool {
        __block int rc = -32005;
        __block NSString *nonceB64 = nil;
        __block NSString *payloadB64 = nil;
        __block NSError *callErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSString *kid = kid_bech32 ? [NSString stringWithUTF8String:kid_bech32] : nil;
        if (!kid || !file_key || file_key_len != 16) {
            kage_write_cstr(err_out, err_out_len, @"invalid input");
            return -32005;
        }

        NSData *fk = [NSData dataWithBytes:file_key length:file_key_len];

        NSXPCConnection *c = kage_connect();
        id<KageDaemonXPCProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull err) {
            callErr = err;
            dispatch_semaphore_signal(sem);
        }];

        [proxy wrapKeyWithKidBech32:kid fileKey:fk withReply:^(NSString * _Nullable kidIgnored, NSString * _Nullable n, NSString * _Nullable p, NSError * _Nullable err) {
            (void)kidIgnored;
            if (err) {
                callErr = err;
                dispatch_semaphore_signal(sem);
                return;
            }
            nonceB64 = n;
            payloadB64 = p;
            rc = 0;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [c invalidate];

        if (rc == 0) {
            kage_write_cstr(nonce_b64_out, nonce_b64_out_len, nonceB64 ?: @"");
            kage_write_cstr(payload_b64_out, payload_b64_out_len, payloadB64 ?: @"");
            return 0;
        }
        return kage_return_error(callErr, err_out, err_out_len);
    }
}

int kage_xpc_unwrap_key(
    const char *kid_bech32,
    const char *nonce_b64,
    const char *payload_b64,
    unsigned char *file_key_out,
    size_t file_key_out_len,
    char *err_out,
    size_t err_out_len
) {
    @autoreleasepool {
        __block int rc = -32005;
        __block NSData *fileKey = nil;
        __block NSError *callErr = nil;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        NSString *kid = kid_bech32 ? [NSString stringWithUTF8String:kid_bech32] : nil;
        NSString *nonce = nonce_b64 ? [NSString stringWithUTF8String:nonce_b64] : nil;
        NSString *payload = payload_b64 ? [NSString stringWithUTF8String:payload_b64] : nil;
        if (!kid || !nonce || !payload || !file_key_out || file_key_out_len != 16) {
            kage_write_cstr(err_out, err_out_len, @"invalid input");
            return -32005;
        }

        NSXPCConnection *c = kage_connect();
        id<KageDaemonXPCProtocol> proxy = [c remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull err) {
            callErr = err;
            dispatch_semaphore_signal(sem);
        }];

        [proxy unwrapKeyWithKidBech32:kid nonceB64:nonce payloadB64:payload withReply:^(NSData * _Nullable fk, NSError * _Nullable err) {
            if (err) {
                callErr = err;
                dispatch_semaphore_signal(sem);
                return;
            }
            fileKey = fk;
            rc = 0;
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        [c invalidate];

        if (rc == 0) {
            if (!fileKey || fileKey.length != 16) {
                kage_write_cstr(err_out, err_out_len, @"invalid file key returned");
                return -32005;
            }
            memcpy(file_key_out, fileKey.bytes, 16);
            return 0;
        }
        return kage_return_error(callErr, err_out, err_out_len);
    }
}
