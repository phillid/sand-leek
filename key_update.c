#include <openssl/bn.h>
#include <openssl/rsa.h>

#if OPENSSL_VERSION_NUMBER >= 0x10100000L

int
key_update_d(RSA *rsa_key) {
	const BIGNUM *p = NULL;
	const BIGNUM *q = NULL;
	const BIGNUM *d = NULL;
	const BIGNUM *e = NULL;
	BIGNUM *gcd = BN_secure_new();
	BIGNUM *p1 = BN_secure_new();
	BIGNUM *q1 = BN_secure_new();
	BIGNUM *p1q1 = BN_secure_new();
	BIGNUM *lambda_n = BN_secure_new();
	BIGNUM *true_d = BN_secure_new();
	BIGNUM *true_dmp1 = BN_secure_new();
	BIGNUM *true_dmq1 = BN_secure_new();
	BIGNUM *true_iqmp = BN_secure_new();
	BN_CTX *bn_ctx = BN_CTX_secure_new();

	if (!(bn_ctx && gcd && p1 && q1 && p1q1 && lambda_n && true_d &&
	    true_dmp1 && true_dmq1 && true_iqmp)) {
		perror("bignum or bignum context allocation");
		return 1;
	}

	RSA_get0_key(rsa_key, NULL, &e, &d);
	RSA_get0_factors(rsa_key, &p, &q);

	/* calculate p-1 and q-1 and their product */
	BN_sub(p1, p, BN_value_one());
	BN_sub(q1, q, BN_value_one());
	BN_mul(p1q1, p1, q1, bn_ctx);

	/* calculate LCM of p1,q1 with p1*q1/gcd(p1,q1) */
	BN_gcd(gcd, p1, q1, bn_ctx);
	BN_div(lambda_n, NULL, p1q1, gcd, bn_ctx);

	BN_mod_inverse(true_d, e, lambda_n, bn_ctx);
	BN_mod_inverse(true_iqmp, q, p, bn_ctx);
	BN_mod(true_dmp1, true_d, p1, bn_ctx);
	BN_mod(true_dmq1, true_d, q1, bn_ctx);

	/* cleanup BN structs not managed by RSA internal functions */
	BN_clear_free(gcd);
	BN_clear_free(p1);
	BN_clear_free(q1);
	BN_clear_free(p1q1);
	BN_clear_free(lambda_n);
	BN_CTX_free(bn_ctx);

	if (!RSA_set0_key(rsa_key, NULL, NULL, true_d)) {
		fprintf(stderr, "setting d failed\n");
		return 1;
	}
	if (!RSA_set0_crt_params(rsa_key, true_dmp1, true_dmq1, true_iqmp)) {
		fprintf(stderr, "setting crt params failed\n");
		return 1;
	}
	return 0;
}

#else

int
key_update_d(RSA *rsa_key) {
	BIGNUM *gcd = BN_new();
	BIGNUM *p1 = BN_new();
	BIGNUM *q1 = BN_new();
	BIGNUM *p1q1 = BN_new();
	BIGNUM *lambda_n = BN_new();
	BIGNUM *true_d = BN_new();
	BIGNUM *true_dmp1 = BN_new();
	BIGNUM *true_dmq1 = BN_new();
	BIGNUM *true_iqmp = BN_new();
	BN_CTX *bn_ctx = BN_CTX_new();

	if (!(bn_ctx && gcd && p1 && q1 && p1q1 && lambda_n && true_d &&
	    true_dmp1 && true_dmq1 && true_iqmp)) {
		perror("bignum or bignum context allocation");
		return 1;
	}

	/* calculate p-1 and q-1 and their product */
	BN_sub(p1, rsa_key->p, BN_value_one());
	BN_sub(q1, rsa_key->q, BN_value_one());
	BN_mul(p1q1, p1, q1, bn_ctx);

	/* calculate LCM of p1,q1 with p1*q1/gcd(p1,q1) */
	BN_gcd(gcd, p1, q1, bn_ctx);
	BN_div(lambda_n, NULL, p1q1, gcd, bn_ctx);

	BN_mod_inverse(rsa_key->d, rsa_key->e, lambda_n, bn_ctx);
	BN_mod_inverse(true_iqmp, rsa_key->q, rsa_key->p, bn_ctx);
	BN_mod(rsa_key->dmp1, rsa_key->d, p1, bn_ctx);
	BN_mod(rsa_key->dmq1, rsa_key->d, q1, bn_ctx);

	/* cleanup BN structs not managed by RSA internal functions */
	BN_clear_free(gcd);
	BN_clear_free(p1);
	BN_clear_free(q1);
	BN_clear_free(p1q1);
	BN_clear_free(lambda_n);
	BN_CTX_free(bn_ctx);

	return 0;
}
#endif
